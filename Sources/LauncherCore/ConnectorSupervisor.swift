import Foundation
import AppKit
import Network
import Security
import Darwin

protocol ConnectorCommandTransport: AnyObject, Sendable {
    var isRunning: Bool { get }
    func send(_ command: ConnectorGatewayCommand) -> Bool
    func request(_ command: ConnectorGatewayCommand) -> ConnectorGatewayReply?
    func terminate()
}

private final class ConnectorPipe: ConnectorCommandTransport, @unchecked Sendable {
    private let condition = NSCondition()
    private let writeLock = NSLock()
    private var replies: [UUID: ConnectorGatewayReply] = [:]
    private var waiting = Set<UUID>()
    private var closed = false
    private let input: FileHandle
    private let readerQueue = DispatchQueue(label: "connector.supervisor.reader")
    private var buffer = Data()
    let process: Process
    var isRunning: Bool { process.isRunning }
    var receive: ((ConnectorSnapshot) -> Void)?
    var exited: (() -> Void)?
    init(tool: URL, configURL: URL) throws {
        let process = Process(), stdin = Pipe(), stdout = Pipe()
        process.executableURL = tool; process.arguments = ["connector-gateway", configURL.path]
        process.standardInput = stdin; process.standardOutput = stdout; process.standardError = FileHandle.nullDevice
        self.process = process; input = stdin.fileHandleForWriting
        let fd = input.fileDescriptor, flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw LauncherError.message("无法建立连接器控制管道。") }
        stdout.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { handle.readabilityHandler = nil; return }
            if data.isEmpty { handle.readabilityHandler = nil; self.finish(); return }
            self.readerQueue.sync { self.consume(data) }
        }
        process.terminationHandler = { [weak self] _ in self?.finish() }
    }
    func start() throws { try process.run() }
    private func finish() {
        condition.lock(); let first = !closed; closed = true; condition.broadcast(); condition.unlock()
        if first { exited?() }
    }
    private func consume(_ data: Data) {
        condition.lock(); let ended = closed; condition.unlock()
        guard !ended else { return }
        buffer.append(data)
        while let end = buffer.firstIndex(of: 10) {
            let line = Data(buffer[..<end]); buffer.removeSubrange(...end)
            guard line.count <= 131072, let reply = try? JSONDecoder().decode(ConnectorGatewayReply.self, from: line) else { terminate(); return }
            condition.lock()
            if let id = reply.commandID, waiting.contains(id) { replies[id] = reply; condition.broadcast() }
            condition.unlock()
            receive?(reply.snapshot)
        }
        if buffer.count > 131072 { terminate() }
    }
    func send(_ command: ConnectorGatewayCommand) -> Bool {
        guard let data = try? JSONEncoder().encode(command) + Data([10]), data.count <= 4096 else { return false }
        writeLock.lock(); defer { writeLock.unlock() }
        let count = data.withUnsafeBytes { write(input.fileDescriptor, $0.baseAddress!, $0.count) }
        if count != data.count { terminate(); return false }; return true
    }
    func request(_ command: ConnectorGatewayCommand) -> ConnectorGatewayReply? {
        condition.lock(); guard !closed else { condition.unlock(); return nil }
        waiting.insert(command.id); condition.unlock()
        defer { condition.lock(); waiting.remove(command.id); replies.removeValue(forKey: command.id); condition.unlock() }
        guard send(command) else { return nil }
        let deadline = connectorTime() + 2.5
        condition.lock(); defer { condition.unlock() }
        while !closed && replies[command.id] == nil && connectorTime() < deadline {
            _ = condition.wait(until: Date().addingTimeInterval(0.1))
        }
        return replies[command.id]
    }
    func terminate() { if process.isRunning { kill(process.processIdentifier, SIGKILL) }; finish() }
    func close() { try? input.close() }
}

public final class ConnectorSupervisor: @unchecked Sendable {
    private let queue = DispatchQueue(label: "connector.supervisor.state")
    private let tool: URL
    private var pipe: (any ConnectorCommandTransport)?
    private var config = ConnectorConfiguration()
    private var state = ConnectorSnapshot()
    private var generation = 0
    private var checking = false
    private var timer: DispatchSourceTimer?
    private let network = NWPathMonitor()
    private var lastPath: String?
    private var observers: [NSObjectProtocol] = []
    private var signals: [DispatchSourceSignal] = []
    private var lockFD: Int32 = -1
    private var lastCheck: Double = 0
    private var localFault: String? = "awaiting_manual_check"
    private var childID: UUID?
    private var childEnded = false
    private var heartbeatPending = false
    private var legacyWorker: UUID?
    private var workers = Set<UUID>()
    private struct Coordination {
        let binding: ConnectorTransactionBinding
        var worker: UUID?
        var workerAction: ConnectorControlAction? = .prepare
        var operation = "queued"
        var terminalSeen = false
        var failure: String?
    }
    private var coordination: Coordination?
    private let holdIO = DispatchQueue(label: "connector.supervisor.hold-io")
    private var holdStore: ConnectorHoldStore?
    private var durableHold: ConnectorHoldIntent?
    private var holdIdentity: ConnectorHoldBinding?
    private var holdOperation = "none"
    private var holdWorker: UUID?
    private var holdFailure: String?
    private var holdHistory: [UUID: ConnectorHoldRequest] = [:]
    private var holdCommandOrder: [UUID] = []
    private var holdJournalUnknown = false
    private var holdOrphan = false
    private var holdTerminalSeen = false
    private var orphanProof: ConnectorGatewayLifetime?
    private var holdDirectory = Paths.root
    private var holdFenced: Bool {
        holdJournalUnknown || holdOrphan || (holdIdentity != nil && holdOperation != "released") ||
            durableHold.map { !$0.released } == true
    }
    private var commandHistory: [UUID: ConnectorControlRequest] = [:]
    private var commandOrder: [UUID] = []
    private let configuration: @Sendable () -> ConnectorConfiguration?
    private let probe: @Sendable (UInt16, String, ConnectorProbeProfile) async -> ConnectorProbeResult
    public init(tool: URL) {
        self.tool = tool; configuration = { try? ConnectorConfiguration.read() }
        probe = { port, token, profile in await ConnectorProbe.sample(port: port, token: token, profile: profile) }
    }
    // Deterministic transport/probe tests; no production flag, path or environment override.
    init(config: ConnectorConfiguration, transport: any ConnectorCommandTransport, snapshot: ConnectorSnapshot,
         configuration: @escaping @Sendable () -> ConnectorConfiguration?,
         probe: @escaping @Sendable (UInt16, String, ConnectorProbeProfile) async -> ConnectorProbeResult,
         holdDirectory: URL? = nil) {
        tool = URL(fileURLWithPath: "/unused-in-fixture"); self.config = config; pipe = transport
        state = snapshot; childID = snapshot.instanceID; localFault = nil
        self.configuration = configuration; self.probe = probe
        if let holdDirectory { self.holdDirectory = holdDirectory; self.holdStore = try? ConnectorHoldStore(directory: holdDirectory) }
    }
    private func loadHoldBarrier() throws -> Bool {
        holdStore = try ConnectorHoldStore(directory: holdDirectory)
        durableHold = try holdStore!.load()
        if let record = durableHold, !record.released {
            holdOrphan = true; holdIdentity = record.hold; holdOperation = "interrupted"
            pipe = nil; childEnded = true
            state.state = "stopped"; state.reason = "orphan_hold"
            state.hold = .init(id: record.hold.id, phase: "interrupted", drainPending: true)
            return true
        }
        return false
    }
    // Fixture recovery uses the same production loader; never spawns a child.
    func restoreHoldBarrierForTesting() throws { _ = try queue.sync { try loadHoldBarrier() } }
    private func serveControl() throws {
        try ConnectorIPC.serve(legacy: { self.handle($0) }, coordinated: { self.handle($0) }, held: { self.handle($0) })
    }
    public func run() throws {
        signal(SIGPIPE, SIG_IGN)
        try ConnectorIPC.privateDirectory(create: true)
        lockFD = open(Paths.root.appendingPathComponent("connector.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        var info = stat()
        guard lockFD >= 0, fstat(lockFD, &info) == 0, info.st_uid == geteuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_mode & 0o077 == 0, flock(lockFD, LOCK_EX | LOCK_NB) == 0 else {
            throw LauncherError.message("连接器守卫已运行或生命周期锁不可用。")
        }
        if try loadHoldBarrier() { try serveControl(); return }
        config = try ConnectorConfiguration.read()
        state.configDigest = config.digest; state.upstream = config.upstreamLabel
        let pipe = try ConnectorPipe(tool: tool, configURL: ConnectorConfiguration.url)
        pipe.receive = { value in self.queue.async { self.receive(value) } }
        pipe.exited = { self.queue.async {
            self.childEnded = true; self.generation += 1; self.checking = false
            self.localFault = "gateway_exited"; self.state.state = "stopped"; self.state.reason = "gateway_exited"
            self.coordination?.operation = "interrupted"; self.coordination?.terminalSeen = true
            if self.holdFenced { self.holdOperation = "interrupted"; self.holdTerminalSeen = true }
        } }
        self.pipe = pipe; try pipe.start()
        try serveControl()
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: 1)
        timer.setEventHandler {
            if !self.heartbeatPending && !self.childEnded {
                self.heartbeatPending = true
                DispatchQueue.global().async {
                    let reply = pipe.request(.init(operation: .heartbeat))
                    if reply?.accepted != true { pipe.terminate() }
                    self.queue.async { self.heartbeatPending = false }
                }
            }
            if self.configuration()?.digest != self.config.digest { self.invalidate("configuration_changed") }
            if self.state.trafficEnabled, !self.checking, connectorTime() - self.lastCheck >= 15 { self.beginCheck(manual: false) }
        }; self.timer = timer; timer.resume()
        network.pathUpdateHandler = { path in self.queue.async {
            let signature = "\(path.status)|\(path.supportsIPv4)|\(path.supportsIPv6)|\(path.availableInterfaces.map(\.name).sorted())"
            if let last = self.lastPath, last != signature { self.invalidate("network_changed") }
            self.lastPath = signature
        } }; network.start(queue: DispatchQueue(label: "connector.supervisor.network"))
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: name, object: nil, queue: nil) { _ in self.queue.async { self.invalidate("network_changed") } })
        }
        for sig in [SIGTERM, SIGINT] {
            signal(sig, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: sig, queue: queue)
            source.setEventHandler {
                self.invalidate("supervisor_stopped"); pipe.close()
                DispatchQueue.global().asyncAfter(deadline: .now() + 0.4) { pipe.terminate(); exit(0) }
            }; source.resume(); signals.append(source)
        }
    }
    private func receive(_ value: ConnectorSnapshot) {
        guard !childEnded else { return }
        guard value.configDigest == config.digest, childID == nil || childID == value.instanceID else {
            pipe?.terminate(); return
        }
        if childID == nil { childID = value.instanceID }
        guard value.epoch >= state.epoch,
              value.epoch != state.epoch || value.sampledAt >= state.sampledAt else { return }
        let checkedAt = state.checkedAt, ip = state.observedIP
        if holdFenced, let identity = holdIdentity {
            if let held = value.hold, held.id == identity.id, ["cancelled", "interrupted"].contains(held.phase), !holdTerminalSeen {
                generation += 1; checking = false; holdTerminalSeen = true; holdOperation = held.phase
            }
            if coordination == nil || coordination?.operation == "released" {
                state = value
                return
            }
        }
        if let attempt = coordination, attempt.operation != "released" {
            state = value
            if let transaction = value.transaction, transaction.id == attempt.binding.id {
                if ["cancelled", "expired", "interrupted"].contains(transaction.phase), !attempt.terminalSeen {
                    generation += 1; checking = false; coordination?.terminalSeen = true
                    coordination?.operation = transaction.phase
                } else if attempt.worker == nil, !attempt.terminalSeen,
                          ["prepared", "committed"].contains(transaction.phase) {
                    coordination?.operation = transaction.phase
                    if coordination?.failure == "private_result_unconfirmed" { coordination?.failure = nil }
                }
                if ["prepared", "committed"].contains(transaction.phase) {
                    state.checkedAt = checkedAt; state.observedIP = ip
                }
            }
            // Expected blocked/reserving/probing/prepared states are not legacy failures.
            return
        }
        // A gateway-originated failure cancels an in-flight renewal as well.
        if value.state == "blocked", value.reason != "awaiting_manual_check",
           localFault == nil || (checking && value.epoch > state.epoch) {
            generation += 1; checking = false; localFault = value.reason
        }
        state = value; state.checkedAt = checkedAt; state.observedIP = ip
        if let fault = localFault {
            state.state = checking ? "checking" : "blocked"; state.reason = checking ? "checking" : fault
            if !checking { state.checkedAt = nil; state.observedIP = nil }
        }
    }
    private func invalidate(_ reason: String) {
        let coordinated = fenced
        generation += 1; checking = false; localFault = reason; state.checkedAt = nil; state.observedIP = nil
        if coordinated { coordination?.operation = "interrupted"; coordination?.terminalSeen = true }
        if holdFenced { holdOperation = "interrupted"; holdTerminalSeen = true }
        _ = pipe?.send(.init(operation: .block, reason: reason))
        if coordinated { return } // Keep the actual observation until the gateway confirms the block.
        state.state = "blocked"; state.reason = reason
    }
    private var fenced: Bool {
        holdFenced || (coordination != nil && coordination?.operation != "released") ||
            (state.transaction != nil && state.transaction?.phase != "released")
    }
    private var publicSnapshot: ConnectorSnapshot {
        var value = state; value.controlProtocol = 2; value.coordinatedOperation = holdFenced ? holdOperation : coordination?.operation
        return value
    }
    func observe(_ snapshot: ConnectorSnapshot) { queue.sync { receive(snapshot) } }
    func handle(_ command: String) -> ConnectorSnapshot {
        if command == "block" {
            let pipe = queue.sync { invalidate("manual_block"); return self.pipe }
            if let reply = pipe?.request(.init(operation: .block, reason: "manual_block")), reply.accepted {
                return queue.sync { receive(reply.snapshot); return publicSnapshot }
            }
            pipe?.terminate()
        }
        return queue.sync {
            if command == "check", !checking { beginCheck(manual: true) }
            return publicSnapshot
        }
    }

    func handle(_ request: ConnectorHoldRequest) -> ConnectorHoldReply {
        queue.sync {
            func reply(_ accepted: Bool, _ reason: String) -> ConnectorHoldReply {
                let operation = coordination?.binding.id == request.hold.id && holdOperation == "attached" ?
                    coordination!.operation : holdOperation
                return .init(version: 2, commandID: request.commandID, holdID: request.hold.id, accepted: accepted,
                             reason: holdFailure ?? reason, operation: operation,
                             localWorkPending: !workers.isEmpty || legacyWorker != nil, snapshot: publicSnapshot)
            }
            guard request.valid else { return reply(false, "invalid_request") }
            if let previous = holdHistory[request.commandID], previous.action != request.action ||
                previous.hold != request.hold || previous.binding != request.binding { return reply(false, "command_identity_changed") }
            if request.action != .status, holdHistory[request.commandID] == nil {
                holdHistory[request.commandID] = request; holdCommandOrder.append(request.commandID)
                if holdCommandOrder.count > 64 { holdHistory.removeValue(forKey: holdCommandOrder.removeFirst()) }
            }
            let identity = request.hold, matches = holdIdentity == request.hold
            if request.action == .status { return reply(matches, matches ? "hold_observed" : "hold_unknown") }
            guard !holdJournalUnknown else { return reply(false, "hold_journal_unknown") }
            if request.action == .hold {
                if matches { return reply(true, "existing_hold") }
                guard !fenced, workers.isEmpty, holdStore != nil, let pipe, pipe.isRunning, !childEnded,
                      state.isCurrent(), state.holdProtocol == 1, state.transactionProtocol == 2, let lifetime = state.gatewayLifetime,
                      state.instanceID == identity.gatewayInstance, state.configDigest == identity.configurationDigest,
                      state.epoch == identity.initialEpoch, configuration()?.digest == config.digest,
                      durableHold?.hold.id != identity.id else { return reply(false, "hold_not_available") }
                generation += 1; checking = false; holdIdentity = identity; holdOperation = "holding"
                holdTerminalSeen = false; holdFailure = nil
                let intent = ConnectorHoldIntent(hold: identity, lifetime: lifetime), previous = durableHold
                enqueueHoldWork { worker, ticket in
                    guard self.persistHold(intent, replacing: previous) else { return }
                    guard self.holdCurrent(identity, ticket: ticket, worker: worker) else { return }
                    let response = self.exchange(.init(operation: .hold, hold: identity), pipe: pipe)
                    self.completeHoldResponse(response, identity: identity, ticket: ticket, expected: "held")
                }
                return reply(true, "hold_queued")
            }
            guard matches else { return reply(false, "hold_unknown") }
            if holdOrphan {
                guard request.action == .leave, holdWorker == nil, workers.isEmpty, legacyWorker == nil,
                      let record = durableHold, !record.released else { return reply(false, "orphan_requires_explicit_leave") }
                enqueueOrphanLeave(record, identity: identity)
                return reply(true, "orphan_leave_queued")
            }
            if request.action == .leave, holdOperation == "released" { return reply(true, "existing_hold") }
            if request.action == .leave, (childEnded || !pipeIsRunning ||
                state.hold?.id != identity.id && ["unknown", "interrupted"].contains(holdOperation)),
               workers.isEmpty, legacyWorker == nil,
               let record = durableHold, !record.released {
                // Original command may never have reached the Gateway. Do not forge a new epoch;
                // stop only this owned child, then require its lifetime lock as the exit proof.
                pipe?.terminate(); pipe = nil; childEnded = true; holdOrphan = true
                state.state = "stopped"; state.reason = "orphan_hold"
                state.hold = .init(id: identity.id, phase: "interrupted", drainPending: true)
                enqueueOrphanLeave(record, identity: identity)
                return reply(true, "orphan_leave_queued")
            }
            guard let pipe, pipe.isRunning, !childEnded else { return reply(false, "hold_gateway_stopped") }
            if request.action == .cancel {
                if holdOperation == "cancelling" || (state.hold?.id == identity.id && state.hold?.phase == "cancelled" &&
                    state.hold?.drainPending == false && workers.isEmpty) { return reply(true, "existing_hold") }
                guard holdOperation != "released" else { return reply(false, "hold_released") }
                generation += 1; checking = false; holdOperation = "cancelling"; holdTerminalSeen = true
                enqueueHoldWork { _, ticket in
                    guard self.queue.sync(execute: { self.durableHold?.hold == identity && !self.holdJournalUnknown }) else { return }
                    // Also establish the fence when cancellation won the race with the first hold send.
                    _ = self.exchange(.init(operation: .hold, hold: identity), pipe: pipe)
                    let response = self.exchange(.init(operation: .cancelHold, hold: identity), pipe: pipe)
                    self.completeHoldResponse(response, identity: identity, ticket: ticket, expected: "cancelled")
                }
                return reply(true, "cancel_queued")
            }
            guard holdWorker == nil, workers.isEmpty, legacyWorker == nil, state.isCurrent(),
                  state.hold?.id == identity.id, state.hold?.drainPending == false else {
                return reply(false, "settlement_pending_or_stale")
            }
            if request.action == .leave {
                guard ["cancelled", "interrupted", "released"].contains(state.hold?.phase ?? ""),
                      let record = durableHold, !record.released else { return reply(false, "leave_requires_terminal") }
                holdOperation = "leaving"
                enqueueHoldWork { _, ticket in
                    let response = self.exchange(.init(operation: .leaveHold, hold: identity), pipe: pipe)
                    guard response?.accepted == true, response?.snapshot.hold?.phase == "released",
                          response?.snapshot.hold?.drainPending == false else {
                        self.completeHoldResponse(response, identity: identity, ticket: ticket, expected: "released"); return
                    }
                    var released = record; released.released = true
                    guard self.persistHold(released, replacing: record) else { return }
                    self.queue.sync {
                        self.holdOperation = "released"; self.holdFailure = nil
                        self.coordination?.operation = "released"
                    }
                }
                return reply(true, "leave_queued")
            }
            guard let binding = request.binding, !holdTerminalSeen,
                  configuration()?.digest == config.digest else { return reply(false, "prepare_not_available") }
            if request.action == .prepare {
                guard state.transactionProtocol == 2 else { return reply(false, "transaction_protocol_unsupported") }
                if durableHold?.attachment == binding, coordination?.binding == binding { return reply(true, "existing_transaction") }
                guard state.hold?.phase == "held", var record = durableHold, !record.released,
                      record.attachment == nil || record.attachment == binding else { return reply(false, "attachment_not_available") }
                let previous = record; record.attachment = binding; holdOperation = "attaching"
                enqueueHoldWork { worker, ticket in
                    guard self.persistHold(record, replacing: previous), self.holdCurrent(identity, ticket: ticket, worker: worker) else { return }
                    self.queue.sync {
                        self.workers.remove(worker); self.holdWorker = nil
                        self.holdOperation = "attached"
                        let result = self.handleTransaction(.init(action: .prepare, binding: binding), held: identity)
                        if !result.accepted { self.holdOperation = "unknown"; self.holdFailure = result.reason }
                    }
                }
                return reply(true, "prepare_queued")
            }
            guard request.action == .commit, durableHold?.attachment == binding, state.hold?.phase == "attached" else {
                return reply(false, "commit_not_available")
            }
            let result = handleTransaction(.init(action: .commit, binding: binding), held: identity)
            return reply(result.accepted, result.reason)
        }
    }

    private var pipeIsRunning: Bool { pipe?.isRunning == true }

    private func enqueueOrphanLeave(_ record: ConnectorHoldIntent, identity: ConnectorHoldBinding) {
        holdOperation = "leaving"; holdFailure = nil
        enqueueHoldWork { _, _ in
            do {
                let proof = try ConnectorGatewayLifetime(directory: self.holdDirectory, expected: record.lifetime)
                self.queue.sync { self.orphanProof = proof }
                var released = record; released.released = true
                guard self.persistHold(released, replacing: record) else { return }
                self.queue.sync {
                    self.holdOrphan = false; self.holdOperation = "released"; self.holdFailure = "orphan_released_restart_required"
                    self.state.hold = .init(id: identity.id, phase: "released")
                }
            } catch {
                self.queue.sync { self.holdOperation = "interrupted"; self.holdFailure = "old_gateway_exit_unconfirmed" }
            }
        }
    }

    /// Queue mutations off the state queue; the local fence is installed before returning to IPC.
    private func enqueueHoldWork(_ body: @escaping (UUID, Int) -> Void) {
        let worker = UUID(), ticket = generation
        holdWorker = worker; workers.insert(worker)
        holdIO.async {
            body(worker, ticket)
            self.queue.sync {
                self.workers.remove(worker)
                if self.holdWorker == worker { self.holdWorker = nil }
            }
        }
    }
    private func persistHold(_ next: ConnectorHoldIntent, replacing previous: ConnectorHoldIntent?) -> Bool {
        do {
            guard let store = holdStore else { throw LauncherError.message("hold_store_unavailable") }
            try store.save(next, replacing: previous)
            queue.sync { self.durableHold = next }
            return true
        } catch {
            queue.sync {
                self.holdJournalUnknown = true; self.holdFailure = "hold_journal_unknown"
                self.invalidate("manual_block")
            }
            return false
        }
    }
    private func holdCurrent(_ identity: ConnectorHoldBinding, ticket: Int, worker: UUID) -> Bool {
        queue.sync { holdIdentity == identity && generation == ticket && holdWorker == worker && !holdJournalUnknown && !childEnded }
    }
    private func completeHoldResponse(_ response: ConnectorGatewayReply?, identity: ConnectorHoldBinding, ticket: Int, expected: String) {
        queue.sync {
            guard holdIdentity == identity, generation == ticket, !holdJournalUnknown else { return }
            if response?.accepted == true, state.hold?.id == identity.id, state.hold?.phase == expected,
               state.hold?.drainPending == false {
                holdOperation = expected; holdFailure = nil
            } else { holdOperation = "unknown"; holdFailure = "private_result_unconfirmed" }
        }
    }

    func handle(_ request: ConnectorControlRequest) -> ConnectorControlReply {
        queue.sync { handleTransaction(request, held: nil) }
    }
    private func handleTransaction(_ request: ConnectorControlRequest, held: ConnectorHoldBinding?) -> ConnectorControlReply {
            func reply(_ accepted: Bool, _ reason: String) -> ConnectorControlReply {
                .init(version: 1, commandID: request.commandID, transactionID: request.binding.id,
                      accepted: accepted, reason: reason, operation: coordination?.operation ?? "none",
                      localWorkPending: !workers.isEmpty || legacyWorker != nil,
                      snapshot: publicSnapshot)
            }
            let binding = request.binding
            if holdFenced, held == nil { return reply(false, "coordinated_hold_active") }
            guard request.version == 1, binding.valid else { return reply(false, "invalid_request") }
            if let previous = commandHistory[request.commandID],
               previous.action != request.action || previous.binding != binding { return reply(false, "command_identity_changed") }
            // This bounded ledger catches recent exchange-ID reuse. Binding, not commandID, is the durable operation identity.
            if request.action != .status, commandHistory[request.commandID] == nil {
                commandHistory[request.commandID] = request; commandOrder.append(request.commandID)
                if commandOrder.count > 64 { commandHistory.removeValue(forKey: commandOrder.removeFirst()) }
            }
            let matching = coordination?.binding == binding
            if request.action == .status {
                return reply(matching, matching ? (coordination?.failure ?? "transaction_observed") : "transaction_unknown")
            }
            if request.action == .prepare {
                if matching { return reply(true, "existing_transaction") }
                guard coordination?.binding.id != binding.id, (!fenced || held == holdIdentity && held != nil), workers.isEmpty,
                      let pipe, pipe.isRunning, !childEnded, state.isCurrent(), state.transactionProtocol == 2,
                      state.instanceID == binding.gatewayInstance, state.configDigest == binding.configurationDigest,
                      (held != nil || state.epoch == binding.initialEpoch), configuration()?.digest == config.digest else {
                    return reply(false, "prepare_not_available")
                }
                generation += 1; checking = false; localFault = nil
                let ticket = generation, worker = UUID(), expected = config
                coordination = .init(binding: binding, worker: worker)
                workers.insert(worker)
                Task.detached { await self.prepare(binding, ticket: ticket, worker: worker, pipe: pipe, config: expected, held: held) }
                return reply(true, "prepare_queued")
            }
            guard matching, let pipe, pipe.isRunning, !childEnded else { return reply(false, "transaction_unknown_or_stopped") }
            let phase = state.transaction?.id == binding.id ? state.transaction?.phase : nil
            if request.action == .cancel {
                if (coordination?.worker != nil && coordination?.workerAction == .cancel) ||
                    phase == "released" || (phase == "cancelled" && state.transaction?.drainPending == false) {
                    return reply(true, "existing_transaction")
                }
                scheduleCancel(binding, pipe: pipe)
                return reply(true, "cancel_queued")
            }
            if request.action == .commit, phase == "committed", coordination?.terminalSeen == false,
               state.isCurrent() { return reply(true, "existing_transaction") }
            if request.action == .leave, phase == "released", workers.isEmpty, legacyWorker == nil, state.isCurrent() {
                coordination?.operation = "released"
                return reply(true, "existing_transaction")
            }
            if coordination?.worker != nil { return reply(false, "operation_pending") }
            guard workers.isEmpty, legacyWorker == nil, state.isCurrent(), state.transaction?.drainPending == false else {
                return reply(false, "settlement_pending_or_stale")
            }
            let action: ConnectorOperation
            switch request.action {
            case .commit:
                guard phase == "prepared", coordination?.terminalSeen == false,
                      configuration()?.digest == config.digest else { return reply(false, "commit_not_available") }
                action = .commitTransaction
            case .leave:
                guard ["cancelled", "expired", "interrupted"].contains(phase ?? "") else { return reply(false, "leave_requires_terminal") }
                action = .leaveCoordinatedMode
            default: return reply(false, "unsupported_action")
            }
            let worker = UUID(), ticket = generation
            coordination?.worker = worker; coordination?.operation = action == .commitTransaction ? "committing" : "leaving"
            coordination?.workerAction = request.action
            workers.insert(worker)
            DispatchQueue.global(qos: .utility).async {
                let response = self.current(binding, ticket: ticket, worker: worker) ?
                    self.exchange(.init(operation: action, transaction: binding, hold: held), pipe: pipe) : nil
                self.finish(worker, binding: binding, ticket: ticket, accepted: response?.accepted == true)
            }
            return reply(true, action == .commitTransaction ? "commit_queued" : "leave_queued")
    }

    private func current(_ binding: ConnectorTransactionBinding, ticket: Int, worker: UUID) -> Bool {
        queue.sync { !childEnded && generation == ticket && coordination?.binding == binding && coordination?.worker == worker }
    }
    private func exchange(_ command: ConnectorGatewayCommand, pipe: any ConnectorCommandTransport) -> ConnectorGatewayReply? {
        guard let reply = pipe.request(command), reply.commandID == command.id else { return nil }
        let valid = queue.sync {
            guard !childEnded, reply.snapshot.instanceID == childID, reply.snapshot.configDigest == config.digest,
                  !reply.accepted || command.transaction == nil || reply.snapshot.transaction?.id == command.transaction?.id,
                  !reply.accepted || command.hold == nil || reply.snapshot.hold?.id == command.hold?.id else { return false }
            receive(reply.snapshot); return true
        }
        return valid ? reply : nil
    }
    private func finish(_ worker: UUID, binding: ConnectorTransactionBinding, ticket: Int, accepted: Bool) {
        queue.async {
            self.workers.remove(worker)
            guard self.coordination?.binding == binding, self.coordination?.worker == worker else { return }
            self.coordination?.worker = nil
            self.coordination?.workerAction = nil
            if self.childEnded { self.coordination?.operation = "interrupted"; return }
            if self.generation != ticket {
                let phase = self.state.transaction?.id == binding.id ? self.state.transaction?.phase : nil
                self.coordination?.operation = ["cancelled", "expired", "interrupted"].contains(phase ?? "") ? phase! : "interrupted"
                return
            }
            if !self.childEnded, let transaction = self.state.transaction, transaction.id == binding.id,
               ["prepared", "committed", "cancelled", "expired", "interrupted", "released"].contains(transaction.phase) {
                self.coordination?.operation = transaction.phase
            } else {
                self.coordination?.operation = self.generation == ticket ? "unknown" : "interrupted"
            }
            if !accepted && self.coordination?.operation == "unknown" && self.coordination?.failure == nil {
                self.coordination?.failure = "private_result_unconfirmed"
            }
        }
    }
    private func scheduleCancel(_ binding: ConnectorTransactionBinding, pipe: any ConnectorCommandTransport) {
        generation += 1; checking = false
        let ticket = generation, worker = UUID()
        coordination?.worker = worker; coordination?.operation = "cancelling"; workers.insert(worker)
        coordination?.workerAction = .cancel
        DispatchQueue.global(qos: .utility).async {
            // A cancel arriving before the original reserve must also fence its late arrival.
            let held = self.queue.sync { self.holdIdentity.flatMap { $0.matches(binding) ? $0 : nil } }
            let reserved = self.exchange(.init(operation: held == nil ? .reserveTransaction : .hold, transaction: binding, hold: held), pipe: pipe)
            if reserved?.snapshot.transaction?.id == binding.id, reserved?.snapshot.transaction?.phase == "released" {
                self.finish(worker, binding: binding, ticket: ticket, accepted: true); return
            }
            // Do not require the reserve ACK: an existing reserving fence can still be cancelled safely.
            let cancelled = self.exchange(.init(operation: held == nil ? .cancelTransaction : .cancelHold, transaction: binding, hold: held), pipe: pipe)
            self.finish(worker, binding: binding, ticket: ticket, accepted: cancelled?.accepted == true)
        }
    }
    private func abortPreparation(_ binding: ConnectorTransactionBinding, ticket: Int, worker: UUID,
                                  pipe: any ConnectorCommandTransport, reason: String) {
        queue.async {
            guard self.generation == ticket, self.coordination?.binding == binding, self.coordination?.worker == worker else { return }
            self.coordination?.failure = reason
            self.scheduleCancel(binding, pipe: pipe)
        }
    }
    private func prepare(_ binding: ConnectorTransactionBinding, ticket: Int, worker: UUID,
                         pipe: any ConnectorCommandTransport, config: ConnectorConfiguration, held: ConnectorHoldBinding?) async {
        var accepted = false
        defer { finish(worker, binding: binding, ticket: ticket, accepted: accepted) }
        func abort(_ reason: String) { abortPreparation(binding, ticket: ticket, worker: worker, pipe: pipe, reason: reason) }
        guard current(binding, ticket: ticket, worker: worker) else { return }
        guard let reserved = exchange(.init(operation: held == nil ? .reserveTransaction : .attachTransaction, transaction: binding, hold: held), pipe: pipe),
              reserved.accepted, reserved.snapshot.transaction?.phase == "reserved",
              reserved.snapshot.transaction?.drainPending == false else { abort("reserve_unconfirmed"); return }
        guard current(binding, ticket: ticket, worker: worker), configuration()?.digest == config.digest,
              let token = ConnectorProbe.token() else { abort("preparation_interrupted"); return }
        let check = UUID()
        guard let started = exchange(.init(operation: .beginTransactionProbe, checkID: check, authorization: token,
                                          transaction: binding, hold: held), pipe: pipe), started.accepted else { abort("probe_not_started"); return }
        guard current(binding, ticket: ticket, worker: worker) else { return }
        let sampleTime = Date(), result = await probe(started.snapshot.port, token, .coordinatedRecovery)
        guard result.settled else { unsettledProbe(pipe); return }
        guard current(binding, ticket: ticket, worker: worker) else { return }
        guard Set(result.samples.keys) == Set(ConnectorConfiguration.hosts) else { abort("probe_failed"); return }
        guard result.samples.values.allSatisfy(config.matches) else { abort("exit_mismatch"); return }
        guard ConnectorServiceResponse.complete(result.services) else { abort("service_failed"); return }
        guard configuration()?.digest == config.digest else { abort("configuration_changed"); return }
        guard let prepared = exchange(.init(operation: .prepareTransaction, checkID: check, transaction: binding,
                                           samples: result.samples, services: result.services, hold: held), pipe: pipe), prepared.accepted,
              prepared.snapshot.transaction?.phase == "prepared", prepared.snapshot.transaction?.drainPending == false else {
            abort("prepare_unconfirmed"); return
        }
        accepted = true
        queue.async {
            guard self.generation == ticket, self.coordination?.binding == binding, self.coordination?.worker == worker else { return }
            self.state.checkedAt = sampleTime; self.state.observedIP = result.samples.values.sorted().first
        }
    }
    private func unsettledProbe(_ pipe: any ConnectorCommandTransport) {
        pipe.terminate()
        queue.async {
            self.childEnded = true; self.generation += 1; self.checking = false
            self.coordination?.operation = "interrupted"; self.coordination?.terminalSeen = true
            self.localFault = "probe_cleanup_failed"; self.state.state = "stopped"; self.state.reason = "probe_cleanup_failed"
        }
    }
    private func beginCheck(manual: Bool) {
        guard !fenced, workers.isEmpty, legacyWorker == nil,
              let pipe, pipe.isRunning, !checking, !childEnded, state.port > 0,
              configuration()?.digest == config.digest else { return }
        checking = true
        let worker = UUID(); legacyWorker = worker
        let started = connectorTime()
        let ticket = generation, expected = config
        if manual { state.state = "checking"; state.reason = "checking" }
        Task.detached {
            await self.check(pipe: pipe, config: expected, ticket: ticket, manual: manual, started: started)
            self.queue.async { if self.legacyWorker == worker { self.legacyWorker = nil } }
        }
    }
    private func current(_ ticket: Int) -> Bool { queue.sync { generation == ticket && checking && !fenced } }
    private func fail(_ reason: String, ticket: Int) {
        queue.async { if self.generation == ticket { self.invalidate(reason) } }
    }
    private func check(pipe: any ConnectorCommandTransport, config: ConnectorConfiguration, ticket: Int, manual: Bool, started: Double) async {
        guard let token = ConnectorProbe.token() else { fail("probe_failed", ticket: ticket); return }
        let checkID = UUID()
        let epoch = queue.sync { state.epoch }
        guard current(ticket), let start = pipe.request(.init(operation: .beginProbe, epoch: epoch, checkID: checkID, authorization: token, manual: manual)), start.accepted else {
            fail("probe_failed", ticket: ticket); return
        }
        let sampleTime = Date()
        let result = await probe(start.snapshot.port, token, .traceOnly)
        guard result.settled else { unsettledProbe(pipe); return }
        guard current(ticket), let revoked = pipe.request(.init(operation: .revokeProbe, epoch: start.snapshot.epoch, checkID: checkID)), revoked.accepted else {
            fail("probe_failed", ticket: ticket); return
        }
        guard Set(result.samples.keys) == Set(ConnectorConfiguration.hosts) else { fail("probe_failed", ticket: ticket); return }
        guard result.samples.values.allSatisfy(config.matches) else { fail("exit_mismatch", ticket: ticket); return }
        guard current(ticket), configuration()?.digest == config.digest,
              let allowed = pipe.request(.init(operation: manual ? .allow : .renew, epoch: start.snapshot.epoch, checkID: checkID)), allowed.accepted else {
            fail("probe_failed", ticket: ticket); return
        }
        queue.async {
            guard self.generation == ticket, !self.childEnded,
                  allowed.snapshot.epoch >= self.state.epoch,
                  allowed.snapshot.configDigest == self.config.digest else { return }
            self.localFault = nil; self.checking = false; self.lastCheck = started
            self.state = allowed.snapshot; self.state.checkedAt = sampleTime
            self.state.observedIP = Array(Set(result.samples.values)).sorted().joined(separator: " / ")
        }
    }
}
