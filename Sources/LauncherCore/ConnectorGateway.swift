import Foundation
import Network
import Darwin

private final class ConnectorOutput {
    private let queue = DispatchQueue(label: "connector.gateway.output")
    private let slots = DispatchSemaphore(value: 32)
    func send(_ bytes: Data) {
        guard bytes.count < 131072, slots.wait(timeout: .now()) == .success else { exit(74) }
        queue.async {
            defer { self.slots.signal() }
            let deadline = connectorTime() + 2
            bytes.withUnsafeBytes { ptr in
                var sent = 0
                while sent < ptr.count {
                    guard connectorTime() < deadline else { exit(74) }
                    let count = write(STDOUT_FILENO, ptr.baseAddress!.advanced(by: sent), ptr.count - sent)
                    if count > 0 { sent += count; continue }
                    guard count < 0, [EAGAIN, EWOULDBLOCK, EINTR].contains(errno), connectorTime() < deadline else { exit(74) }
                    Thread.sleep(forTimeInterval: 0.005)
                }
            }
        }
    }
}

/// One loopback listener. Its private command pipe belongs only to the supervisor.
public final class ConnectorGateway: @unchecked Sendable {
    private let config: ConnectorConfiguration
    private let queue = DispatchQueue(label: "connector.gateway.state")
    private var listener: NWListener?
    private var timer: DispatchSourceTimer?
    private var grant = ConnectorGrant()
    private var snapshot = ConnectorSnapshot()
    private var active: [UUID: Tunnel] = [:]
    private var metadata: [UUID: ConnectorConnection] = [:]
    private var lastEmit: Double = 0
    private let output = ConnectorOutput()
    private struct Drain {
        let id: UUID
        let action: String
        let binding: ConnectorTransactionBinding?
        var hold: ConnectorHoldBinding? = nil
        var remaining: Set<UUID>
        let deadline: Double
    }
    private var drain: Drain?
    private var cleanupDeadline: Double?
    private var fence: ConnectorFence?
    private var hold: ConnectorHold?
    private let lifetimeDirectory: URL
    private var lifetime: ConnectorGatewayLifetime?
    private var coordinated: Bool { hold?.fenced == true || fence?.fenced == true }
    private struct PFRead {
        let id: UUID
        let binding: ConnectorTransactionBinding
        let epoch: UInt64
        var reply: UUID?
        var valid = true
    }
    private var pfRead: PFRead?
    public init(config: ConnectorConfiguration, lifetimeDirectory: URL) {
        self.config = config; self.lifetimeDirectory = lifetimeDirectory
    }
    public func run() throws {
        try config.validate()
        lifetime = try ConnectorGatewayLifetime(directory: lifetimeDirectory)
        snapshot.gatewayLifetime = lifetime?.identity; snapshot.holdProtocol = 1
        // A stopped reader must never stall the watchdog while tunnels keep forwarding.
        let flags = fcntl(STDOUT_FILENO, F_GETFL)
        guard flags >= 0, fcntl(STDOUT_FILENO, F_SETFL, flags | O_NONBLOCK) == 0 else { throw LauncherError.message("无法建立有界控制输出。") }
        signal(SIGPIPE, SIG_IGN)
        snapshot.transactionProtocol = 2
        snapshot.configDigest = config.digest; snapshot.upstream = config.upstreamLabel
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: UInt16(config.listenPort))!)
        let listener = try NWListener(using: parameters)
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                guard let port = listener.port?.rawValue, port != self.config.upstreamPort else { self.stop("port_conflict"); exit(70) }
                self.snapshot.port = port; self.stop("awaiting_manual_check"); self.emit()
            case .failed: self.stop("port_conflict"); self.emit(); exit(70)
            default: break
            }
        }
        listener.newConnectionHandler = { connection in
            guard self.drain == nil, self.cleanupDeadline == nil, self.active.count < 128 else { connection.cancel(); return }
            let id = UUID(), epoch = self.grant.epoch, tunnel = Tunnel(connection)
            self.active[id] = tunnel
            Task { await self.serve(id: id, tunnel: tunnel, epoch: epoch) }
        }
        self.listener = listener; listener.start(queue: queue)
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: .milliseconds(100))
        timer.setEventHandler {
            let now = connectorTime()
            if let deadline = self.cleanupDeadline, now >= deadline, !self.active.isEmpty {
                self.stop("transaction_drain_timeout"); self.emit(); exit(74)
            }
            if let drain = self.drain, now >= drain.deadline {
                self.stop("transaction_drain_timeout"); self.emit(); exit(74)
            }
            if self.hold?.fenced == true, !self.grant.heartbeatCurrent(now), self.hold?.terminal == false {
                self.stop("heartbeat_expired")
            }
            if self.fence?.expired(at: now) == true {
                self.stop("transaction_expired", expired: true)
            }
            if self.grant.expired(now), self.grant.allowed || self.grant.capability != nil || !self.active.isEmpty {
                self.stop(self.grant.heartbeatCurrent(now) ? "probe_or_evidence_expired" : "heartbeat_expired")
            }
            if now - self.lastEmit >= 1 { self.lastEmit = now; self.emit() }
        }; self.timer = timer; timer.resume()
        DispatchQueue.global(qos: .utility).async {
            // Bound each command frame before decoding; tokens never appear in replies.
            var pending = Data()
            while true {
                let part = FileHandle.standardInput.availableData
                if part.isEmpty { self.queue.async { self.stop("supervisor_closed"); exit(0) }; return }
                pending.append(part)
                while let end = pending.firstIndex(of: 10) {
                    let line = Data(pending[..<end]); pending.removeSubrange(...end)
                    guard line.count <= 8192, let command = try? JSONDecoder().decode(ConnectorGatewayCommand.self, from: line) else {
                        self.queue.async { self.stop("invalid_internal_command"); exit(65) }; return
                    }
                    self.queue.async { self.handle(command) }
                }
                if pending.count > 8192 { self.queue.async { self.stop("invalid_internal_command"); exit(65) }; return }
            }
        }
    }
    private func stop(_ reason: String, expired: Bool = false) {
        grant.block()
        fence?.stop(reason, expired: expired)
        hold?.interrupt()
        let rejectedRead = pfRead?.valid == true ? pfRead?.reply : nil
        if let read = pfRead, read.valid {
            pfRead?.valid = false; pfRead?.reply = nil
        }
        for tunnel in active.values { tunnel.cancel() }
        if !active.isEmpty { cleanupDeadline = min(cleanupDeadline ?? .infinity, drain?.deadline ?? connectorTime() + 2.5) }
        if snapshot.reason != reason { snapshot.events.insert(.init(code: reason), at: 0); snapshot.events = Array(snapshot.events.prefix(40)) }
        snapshot.state = "blocked"; snapshot.reason = reason
        if let rejectedRead { emit(rejectedRead, accepted: false) }
        if let pending = drain { drain = nil; emit(pending.id, accepted: false) }
    }
    private func handle(_ command: ConnectorGatewayCommand) {
        let now = connectorTime()
        if grant.expired(now), grant.allowed || grant.capability != nil { stop(grant.heartbeatCurrent(now) ? "probe_or_evidence_expired" : "heartbeat_expired") }
        var accepted = false
        switch command.operation {
        case .heartbeat:
            grant.heartbeat(now); accepted = true
            if let fence, fence.phase == "committed", pfRead == nil { verifyPF(fence.binding, reply: nil) }
        case .block:
            let allowed = Set(["manual_block", "network_changed", "configuration_changed", "probe_failed", "exit_mismatch", "supervisor_stopped"])
            stop(allowed.contains(command.reason ?? "") ? command.reason! : "manual_block"); accepted = true
        case .beginProbe:
            if !coordinated, drain == nil, cleanupDeadline == nil, command.epoch == grant.epoch, let id = command.checkID, let token = command.authorization {
                if command.manual {
                    for item in active.values { item.cancel() }
                }
                accepted = grant.begin(id: id, token: token, manual: command.manual, now: now)
                if accepted { snapshot.state = command.manual ? "checking" : "allowed"; snapshot.reason = "checking" }
            }
        case .revokeProbe:
            if !coordinated, drain == nil, cleanupDeadline == nil, command.epoch == grant.epoch, let id = command.checkID {
                accepted = grant.revoke(id: id, now: now)
                if accepted {
                    let ids = Set(metadata.keys.filter { metadata[$0]?.probe == true })
                    if !ids.isEmpty {
                        drain = .init(id: command.id, action: "legacy", binding: nil, remaining: ids, deadline: now + 2.5)
                        for key in ids { active[key]?.cancel() }
                        return // ACK follows the final relay task's exit, never just cancel().
                    }
                }
            }
        case .allow, .renew:
            if !coordinated, drain == nil, cleanupDeadline == nil, command.epoch == grant.epoch, let id = command.checkID {
                accepted = grant.commit(id: id, manual: command.operation == .allow, now: now)
                if accepted { snapshot.state = "allowed"; snapshot.reason = command.operation == .allow ? "manual_check_passed" : "periodic_check_passed" }
            }
        case .hold, .attachTransaction, .cancelHold, .leaveHold:
            handleHold(command); return
        default:
            transaction(command); return
        }
        emit(command.id, accepted: accepted)
    }

    private func handleHold(_ command: ConnectorGatewayCommand) {
        guard let identity = command.hold, identity.valid,
              identity.gatewayInstance == snapshot.instanceID, identity.configurationDigest == config.digest else {
            emit(command.id, accepted: false); return
        }
        let now = connectorTime()
        if command.operation == .hold {
            if let hold, hold.binding.id == identity.id {
                emit(command.id, accepted: hold.binding == identity && hold.phase == "held" && drain == nil && cleanupDeadline == nil)
                return
            }
            guard !coordinated, drain == nil, cleanupDeadline == nil, pfRead == nil,
                  identity.initialEpoch == grant.epoch, grant.epoch < UInt64.max, grant.heartbeatCurrent(now) else {
                emit(command.id, accepted: false); return
            }
            stop("hold_establishing")
            hold = .init(binding: identity, effectiveEpoch: grant.epoch)
            startHoldDrain(command.id, action: "hold", identity: identity); return
        }
        guard hold?.binding == identity else { emit(command.id, accepted: false); return }
        if command.operation == .attachTransaction {
            guard let binding = command.transaction, binding.valid, identity.matches(binding) else {
                emit(command.id, accepted: false); return
            }
            if let attachment = hold?.attachment {
                emit(command.id, accepted: attachment == binding && hold?.phase == "attached" && fence?.terminal == false)
                return // Never recreate the preparation budget on replay.
            }
            guard hold?.phase == "held", drain == nil, cleanupDeadline == nil, pfRead == nil,
                  active.isEmpty, grant.heartbeatCurrent(now), hold?.effectiveEpoch == grant.epoch,
                  hold?.attach(binding) == true else { emit(command.id, accepted: false); return }
            fence = .init(binding: binding, effectiveEpoch: grant.epoch, now: now)
            fence?.reserved(); emit(command.id); return
        }
        if command.operation == .cancelHold {
            guard hold?.fenced == true else { emit(command.id, accepted: false); return }
            if hold?.phase == "cancelled", drain == nil, cleanupDeadline == nil { emit(command.id); return }
            stop("transaction_cancelled"); hold?.cancel()
            startHoldDrain(command.id, action: "cancelHold", identity: identity); return
        }
        if command.operation == .leaveHold {
            if hold?.phase == "released" { emit(command.id); return }
            guard drain == nil, cleanupDeadline == nil, pfRead == nil, hold?.terminal == true,
                  active.isEmpty, hold?.leave() == true else { emit(command.id, accepted: false); return }
            if fence?.binding == hold?.attachment { _ = fence?.leaving() }
            grant.block(); startHoldDrain(command.id, action: "leaveHold", identity: identity); return
        }
        emit(command.id, accepted: false)
    }
    private func startHoldDrain(_ id: UUID, action: String, identity: ConnectorHoldBinding) {
        if let previous = drain { emit(previous.id, accepted: false) }
        drain = .init(id: id, action: action, binding: nil, hold: identity, remaining: Set(active.keys),
                      deadline: min(cleanupDeadline ?? .infinity, connectorTime() + 2.5))
        for tunnel in active.values { tunnel.cancel() }
        finishDrainIfReady()
    }

    private func transaction(_ command: ConnectorGatewayCommand) {
        if let hold, hold.fenced {
            guard command.hold == hold.binding, hold.attachment != nil, command.transaction == hold.attachment,
                  ![.reserveTransaction, .leaveCoordinatedMode].contains(command.operation) else {
                emit(command.id, accepted: false); return
            }
        }

        guard let binding = command.transaction, binding.valid,
              binding.gatewayInstance == snapshot.instanceID, binding.configurationDigest == config.digest else {
            emit(command.id, accepted: false); return
        }
        let now = connectorTime()
        if command.operation == .reserveTransaction {
            if let fence, fence.binding == binding {
                emit(command.id, accepted: !["reserving", "leaving"].contains(fence.phase)); return
            }
            guard fence?.binding.id != binding.id, fence?.fenced != true, drain == nil, pfRead == nil,
                  binding.initialEpoch == grant.epoch, grant.epoch < UInt64.max,
                  grant.heartbeatCurrent(now) else { emit(command.id, accepted: false); return }
            stop("transaction_reserving")
            fence = ConnectorFence(binding: binding, effectiveEpoch: grant.epoch, now: now)
            startDrain(command.id, action: "reserve", binding: binding); return
        }
        guard fence?.binding == binding else { emit(command.id, accepted: false); return }
        if command.operation == .cancelTransaction {
            if drain?.action == "cancel" { emit(command.id, accepted: false); return }
            guard fence?.fenced == true else { emit(command.id, accepted: false); return }
            if fence?.terminal != true { stop("transaction_cancelled") }
            fence?.cancelling()
            startDrain(command.id, action: "cancel", binding: binding); return
        }
        if command.operation == .leaveCoordinatedMode {
            if fence?.phase == "released" { emit(command.id); return }
            guard drain == nil, fence?.leaving() == true else { emit(command.id, accepted: false); return }
            grant.block()
            startDrain(command.id, action: "leave", binding: binding); return
        }
        guard let current = fence, current.fenced, !current.terminal, drain == nil,
              grant.epoch == current.effectiveEpoch, grant.heartbeatCurrent(now), !current.expired(at: now) else {
            emit(command.id, accepted: false); return
        }
        var accepted = false
        switch command.operation {
        case .beginTransactionProbe:
            if current.phase == "probing", current.probeID == command.checkID { emit(command.id); return }
            if let id = command.checkID, let token = command.authorization, current.phase == "reserved",
               grant.transactionProbe(id: id, token: token, now: now, deadline: current.deadline) {
                accepted = fence?.begin(id: id, now: now) == true
                if !accepted { stop("transaction_interrupted") }
            }
        case .prepareTransaction:
            if ["prepared", "committed"].contains(current.phase), current.probeID == command.checkID { emit(command.id); return }
            guard let samples = command.samples, Set(samples.keys) == Set(ConnectorConfiguration.hosts),
                  let services = command.services, ConnectorServiceResponse.complete(services),
                  samples.values.allSatisfy(config.matches), let id = command.checkID,
                  current.phase == "probing", current.probeID == id,
                  grant.revokeCompletedTransaction(id: id, now: now), fence?.revoking(id: id, now: now) == true else {
                stop("probe_failed"); emit(command.id, accepted: false); return
            }
            startDrain(command.id, action: "prepare", binding: binding); return
        case .commitTransaction:
            if current.phase == "committed" { emit(command.id); return }
            guard current.phase == "prepared", pfRead == nil else { emit(command.id, accepted: false); return }
            verifyPF(binding, reply: command.id); return
        default: break
        }
        emit(command.id, accepted: accepted)
    }

    private func startDrain(_ id: UUID, action: String, binding: ConnectorTransactionBinding) {
        if let previous = drain { emit(previous.id, accepted: false) }
        let ids = Set(active.keys)
        drain = .init(id: id, action: action, binding: binding, remaining: ids,
                      deadline: min(cleanupDeadline ?? .infinity, connectorTime() + 2.5))
        for tunnel in active.values { tunnel.cancel() }
        finishDrainIfReady()
    }
    private func finishDrainIfReady() {
        guard let pending = drain, pending.remaining.isEmpty else { return }
        guard connectorTime() < pending.deadline else {
            stop("transaction_drain_timeout"); emit(); exit(74)
        }
        drain = nil
        guard pending.binding == nil || fence?.binding == pending.binding else { emit(pending.id, accepted: false); return }
        if ["reserve", "prepare"].contains(pending.action), fence?.expired(at: connectorTime()) == true {
            stop("transaction_expired", expired: true); emit(pending.id, accepted: false); return
        }
        if let identity = pending.hold {
            guard hold?.binding == identity else { emit(pending.id, accepted: false); return }
            switch pending.action {
            case "hold": hold?.drained()
            case "cancelHold": hold?.cancelled()
            case "leaveHold": hold?.released(); fence?.released()
            default: emit(pending.id, accepted: false); return
            }
        }
        switch pending.action {
        case "reserve": fence?.reserved()
        case "prepare": fence?.prepared()
        case "cancel": fence?.cancelled()
        case "leave": fence?.released()
        default: break
        }
        emit(pending.id)
    }

    private func verifyPF(_ binding: ConnectorTransactionBinding, reply: UUID?) {
        let id = UUID(), epoch = grant.epoch
        pfRead = .init(id: id, binding: binding, epoch: epoch, reply: reply)
        // Trusted file reads run off the watchdog queue; a stuck read cannot stop expiry.
        DispatchQueue.global(qos: .utility).async {
            let deadline = ConnectorPFVerifier.deadline(for: binding.pf)
            self.queue.async {
                guard let ticket = self.pfRead, ticket.id == id else { return }
                self.pfRead = nil
                guard ticket.valid, self.fence?.binding == binding, self.grant.epoch == epoch,
                      self.fence?.effectiveEpoch == epoch else { return }
                let now = connectorTime()
                guard let deadline, now < deadline, self.grant.heartbeatCurrent(now),
                      self.fence?.expired(at: now) == false else {
                    self.stop("pf_evidence_unavailable")
                    if let reply = ticket.reply { self.emit(reply, accepted: false) }; return
                }
                if let reply = ticket.reply {
                    guard self.fence?.phase == "prepared", self.drain == nil, let check = self.fence?.probeID,
                          self.grant.commit(id: check, manual: true, now: now),
                          self.fence?.commit(now: now, pfDeadline: deadline, grantDeadline: self.grant.evidenceDeadline) == true else {
                        self.stop("transaction_commit_failed"); self.emit(reply, accepted: false); return
                    }
                    self.grant.shortenDeadline(to: self.fence!.deadline)
                    self.snapshot.state = "allowed"; self.snapshot.reason = "transaction_committed"
                    self.emit(reply)
                } else if self.fence?.phase == "committed" {
                    self.fence?.shorten(to: deadline); self.grant.shortenDeadline(to: deadline)
                }
            }
        }
        queue.asyncAfter(deadline: .now() + 1) {
            guard self.pfRead?.id == id, self.pfRead?.valid == true else { return }
            // Retain the read slot until the worker exits; repeated requests cannot create more stuck readers.
            self.stop("pf_read_timeout"); self.emit()
        }
    }
    private func emit(_ command: UUID? = nil, accepted: Bool = true) {
        snapshot.sampledAt = Date(); snapshot.epoch = grant.epoch
        snapshot.hold = hold?.status
        snapshot.hold?.drainPending = drain != nil || cleanupDeadline != nil
        snapshot.transaction = fence?.status
        snapshot.transaction?.drainPending = drain != nil || cleanupDeadline != nil
        snapshot.heartbeatAge = grant.lastHeartbeat.map { max(0, connectorTime() - $0) } ?? 999
        snapshot.connections = Array(metadata.values.sorted { $0.startedAt > $1.startedAt }.prefix(40)); snapshot.connectionCount = metadata.count
        guard let bytes = try? JSONEncoder().encode(ConnectorGatewayReply(commandID: command, accepted: accepted, snapshot: snapshot)) + Data([10]) else { exit(74) }
        output.send(bytes)
    }
    private func authorize(_ id: UUID, epoch: UInt64, request: ProxyRequest, bytes: Data) -> Bool? {
        queue.sync {
            guard active[id] != nil, grant.epoch == epoch else { return nil }
            let headers = String(decoding: bytes, as: UTF8.self).components(separatedBy: "\r\n")
            let values = headers.dropFirst().compactMap { line -> String? in
                guard let colon = line.firstIndex(of: ":"), line[..<colon].lowercased() == "proxy-authorization" else { return nil }
                return String(line[line.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            }
            guard values.count <= 1, let probe = grant.authorize(target: request.target, connect: request.connect, auth: values.first, now: connectorTime()) else { return nil }
            metadata[id] = .init(id: id, host: request.target.host, port: request.target.port, startedAt: Date(), probe: probe)
            return probe
        }
    }
    private func transferred(_ id: UUID, upload: Bool, count: Int) {
        queue.async {
            guard var item = self.metadata[id] else { return }
            if upload { item.uploaded &+= UInt64(count); self.snapshot.uploaded &+= UInt64(count) }
            else { item.downloaded &+= UInt64(count); self.snapshot.downloaded &+= UInt64(count) }
            self.metadata[id] = item
        }
    }
    private func handshakeCurrent(_ id: UUID, epoch: UInt64) -> Bool {
        queue.sync {
            let now = connectorTime()
            guard active[id] != nil, grant.epoch == epoch, grant.heartbeatCurrent(now),
                  cleanupDeadline == nil, drain?.remaining.contains(id) != true,
                  fence?.expired(at: now) != true, let connection = metadata[id] else { return false }
            if connection.probe {
                return grant.capability.map { $0.epoch == epoch && now < $0.deadline } == true
            }
            return grant.allowed && now < grant.evidenceDeadline
        }
    }
    private func serve(id: UUID, tunnel: Tunnel, epoch: UInt64) async {
        let timeout = DispatchWorkItem { tunnel.cancel() }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10, execute: timeout)
        defer {
            timeout.cancel(); tunnel.cancel()
            queue.async {
                self.active.removeValue(forKey: id); self.metadata.removeValue(forKey: id)
                if self.active.isEmpty { self.cleanupDeadline = nil }
                if self.drain != nil {
                    self.drain?.remaining.remove(id)
                    self.finishDrainIfReady()
                }
            }
        }
        do {
            try await tunnel.client.start()
            let bytes = try await tunnel.client.headers(), request = try ProxyRequest.parse(bytes)
            guard authorize(id, epoch: epoch, request: request, bytes: bytes) != nil else {
                try? await tunnel.client.send(Data("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)); return
            }
            guard handshakeCurrent(id, epoch: epoch) else { return }
            let upstream = Channel(NWConnection(host: NWEndpoint.Host(config.upstreamHost), port: NWEndpoint.Port(rawValue: UInt16(config.upstreamPort))!, using: .tcp))
            tunnel.attach(upstream)
            do {
                try await upstream.start(failOnWaiting: true)
                guard handshakeCurrent(id, epoch: epoch) else { return }
                try await connect(upstream, target: request.target)
            }
            catch { queue.async { if self.active[id] != nil && self.grant.epoch == epoch { self.stop("upstream_failed") } }; throw error }
            guard handshakeCurrent(id, epoch: epoch) else { return }
            if request.connect { try await tunnel.client.send(Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) }
            else { try await upstream.send(request.forwarded); transferred(id, upload: true, count: request.forwarded.count) }
            timeout.cancel()
            await withTaskGroup(of: Void.self) { group in
                group.addTask { do { try await tunnel.client.pump(to: upstream) { self.transferred(id, upload: true, count: $0) } } catch { tunnel.cancel() } }
                group.addTask { do { try await upstream.pump(to: tunnel.client) { self.transferred(id, upload: false, count: $0) } } catch { tunnel.cancel() } }
                await group.waitForAll()
            }
        } catch { /* Fixed state codes only; no request bytes or credentials. */ }
    }
    private func connect(_ channel: Channel, target: Target) async throws {
        if config.upstreamProtocol == "http" {
            try await channel.send(Data("CONNECT \(target.authority) HTTP/1.1\r\nHost: \(target.authority)\r\n\r\n".utf8))
            let response = String(decoding: try await channel.headers(), as: UTF8.self).components(separatedBy: "\r\n")[0].split(separator: " ")
            guard response.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(response[0]), let code = Int(response[1]), (200...299).contains(code) else { throw LauncherError.message("upstream_failed") }
        } else {
            try await channel.send(Data([5, 1, 0]))
            guard try await channel.exact(2) == Data([5, 0]) else { throw LauncherError.message("upstream_failed") }
            let host = Array(target.host.utf8)
            guard !host.isEmpty, host.count <= 255 else { throw LauncherError.message("upstream_failed") }
            try await channel.send(Data([5, 1, 0, 3, UInt8(host.count)] + host + [UInt8(target.port >> 8), UInt8(target.port & 255)]))
            let reply = [UInt8](try await channel.exact(4))
            guard reply[0] == 5, reply[1] == 0, reply[2] == 0 else { throw LauncherError.message("upstream_failed") }
            switch reply[3] {
            case 1: _ = try await channel.exact(6)
            case 4: _ = try await channel.exact(18)
            case 3: let n = try await channel.exact(1).first!; _ = try await channel.exact(Int(n) + 2)
            default: throw LauncherError.message("upstream_failed")
            }
        }
    }
}
