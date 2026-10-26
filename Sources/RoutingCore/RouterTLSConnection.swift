import Foundation
import Darwin
import Network
import Security

/// Owns one TLS transport. Kernel samples observe that transport without owning its private FD.
/// No caller is wired into production collection yet; successful TLS is not route acceptance.
// Immutable configuration is shared; mutable state and private perform callbacks stay on queue.
// Only StopRequest crosses that queue, under its lock. A callback's strong self prevents deinit
// from racing it; NWConnection cancellation in deinit uses the framework's thread-safe API.
final class RouterTLSConnection: @unchecked Sendable {
    typealias Endpoint = RouterOwnedTCPProbe.Endpoint
    typealias Observer = RouterSystemOutboundSocket

    enum Trust { case system, fixtureAnchor }
    enum Failure: Error, Equatable {
        case unavailable, invalidTarget, busy, closed, cancelled, timedOut
        case connectionFailed, tlsFailed, pathUnknown, pathChanged, identityChanged
        case socketUnknown(Observer.Unknown), unsupportedTLS, eof
    }
    struct Sample {
        let source: Observer.Source
        let trust: Trust
        let serverName: String
        let protocolVersion: UInt16
        let connectStartedAt: RouterSystemClock
        let socket: Observer.Evidence
        let collectorAuthenticated = false
        let canPromoteAccepted = false
    }
    struct Exchange {
        let reply: RouterTCPEchoWire.Reply
        let before: Sample
        let after: Sample
        let interval: RouterTrafficInterval
        let egressVerified = false
        let canPromoteAccepted = false
    }

    /// Cancellation is visible even while a synchronous kernel read occupies the owner queue.
    private final class StopRequest {
        private let lock = NSLock()
        private var reason: Failure?
        func record(_ value: Failure) {
            lock.lock(); defer { lock.unlock() }
            if reason == nil { reason = value }
        }
        func read() -> Failure? {
            lock.lock(); defer { lock.unlock() }
            return reason
        }
    }

    private let queue = DispatchQueue(label: "claude-router.tls-owner")
    private let connection: NWConnection
    private let source: Observer.Source
    private let trust: Trust
    private let target: Endpoint
    private let serverName: String
    private let initialProcess: RouterSystemKernelObservation.ProcessSnapshot
    private let began: RouterSystemClock
    private let expires: TimeInterval
    private let stopRequest = StopRequest()

    // Only the dedicated queue accesses the remaining mutable state and operation callbacks.
    private var previous: RouterSystemClock
    private var startedAt: RouterSystemClock?
    private var baseline: Sample?
    private var originalPath: NWPath?
    private var terminal: Error?
    private var busy = false
    private var pendingFailure: ((Error) -> Void)?
    private var onReady: (() throws -> Void)?
    private var timer: DispatchSourceTimer?

    static func installed(target: Endpoint, serverName: String,
                          until deadline: TimeInterval) async throws -> RouterTLSConnection {
        guard getuid() == 0, geteuid() == 0 else { throw Failure.unavailable }
        let began = try RouterSystemKernelObservation.clock()
        // The fixed helper identity is checked before any connection can start.
        let process = try RouterSystemKernelObservation.host()
        let owner = try Self(target: target, serverName: serverName, deadline: deadline,
                             source: .installedHelper, began: began, process: process, anchorDER: nil)
        try await owner.open()
        return owner
    }

    static func loopbackFixture(target: Endpoint, serverName: String, anchorDER: Data? = nil,
                                until deadline: TimeInterval) async throws -> RouterTLSConnection {
        guard getuid() != 0, geteuid() == getuid(), target.isLoopback else { throw Failure.unavailable }
        let began = try RouterSystemKernelObservation.clock()
        let process = try RouterSystemKernelObservation.Reader.live.process(getpid())
        let owner = try Self(target: target, serverName: serverName, deadline: deadline,
                             source: .fixture, began: began, process: process, anchorDER: anchorDER)
        try await owner.open()
        return owner
    }

    private init(target: Endpoint, serverName: String, deadline: TimeInterval, source: Observer.Source,
                 began: RouterSystemClock, process: RouterSystemKernelObservation.ProcessSnapshot,
                 anchorDER: Data?) throws {
        guard deadline.isFinite, !target.address.contains("%"), RouterValidation.validDomain(serverName),
              process.work.pid == getpid(), process.work.bootID == began.bootID,
              process.uid == getuid(), process.realUID == getuid() else { throw Failure.invalidTarget }
        // Revalidate as a destination, including when a caller supplied an observed local endpoint.
        let destination = try Endpoint(address: target.address, port: target.port)
        let name = serverName.lowercased()
        let expires = min(deadline, began.uptime + 5)
        try Self.requireFresh(began, try RouterSystemKernelObservation.clock(), expires)
        let options = NWProtocolTLS.Options()
        sec_protocol_options_set_min_tls_protocol_version(options.securityProtocolOptions, .TLSv12)
        sec_protocol_options_set_tls_tickets_enabled(options.securityProtocolOptions, false)
        sec_protocol_options_set_tls_resumption_enabled(options.securityProtocolOptions, false)
        name.withCString { sec_protocol_options_set_tls_server_name(options.securityProtocolOptions, $0) }

        if let anchorDER {
            guard source == .fixture, getuid() != 0, geteuid() == getuid(), destination.isLoopback,
                  !anchorDER.isEmpty, anchorDER.count <= 65_536,
                  let anchor = SecCertificateCreateWithData(nil, anchorDER as CFData) else {
                throw Failure.invalidTarget
            }
            let verificationQueue = DispatchQueue(label: "claude-router.fixture-trust")
            sec_protocol_options_set_verify_block(options.securityProtocolOptions, { _, supplied, complete in
                guard getuid() != 0, geteuid() == getuid(),
                      ProcessInfo.processInfo.systemUptime < expires else {
                    complete(false); return
                }
                let trust = sec_trust_copy_ref(supplied).takeRetainedValue()
                let configured =
                    SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, name as CFString)) == errSecSuccess &&
                    SecTrustSetAnchorCertificates(trust, [anchor] as CFArray) == errSecSuccess &&
                    SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess &&
                    SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess
                var error: CFError?
                let accepted = configured && SecTrustEvaluateWithError(trust, &error)
                // Evaluation itself is not hard-cancellable. A late result cannot open the owner.
                complete(accepted && ProcessInfo.processInfo.systemUptime < expires)
            }, verificationQueue)
        }
        // The installed factory cannot set anchors or a verification callback.
        let parameters = NWParameters(tls: options, tcp: NWProtocolTCP.Options())
        guard let port = NWEndpoint.Port(rawValue: destination.port) else { throw Failure.invalidTarget }
        connection = NWConnection(host: .init(destination.address), port: port, using: parameters)
        self.target = destination
        self.serverName = name
        self.source = source
        self.trust = anchorDER == nil ? .system : .fixtureAnchor
        self.began = began
        self.previous = began
        self.expires = expires
        self.initialProcess = process

        connection.stateUpdateHandler = { [weak self] in self?.stateChanged($0) }
        connection.pathUpdateHandler = { [weak self] path in
            guard let self, self.terminal == nil, let original = self.originalPath else { return }
            if original != path { self.finishWithFailure(Failure.pathChanged) }
        }
        connection.viabilityUpdateHandler = { [weak self] viable in
            guard let self, self.baseline != nil else { return }
            if !viable { self.finishWithFailure(Failure.pathChanged) }
        }
    }

    deinit { timer?.cancel(); connection.cancel() }

    /// Marks the owner unusable immediately; transport cancellation is serialized with callbacks.
    func close() { stop(.closed) }

    private func stop(_ reason: Failure) {
        stopRequest.record(reason)
        queue.async { self.finishWithFailure(reason) }
    }

    private func open() async throws {
        try await perform { done in
            guard self.startedAt == nil else { throw Failure.unavailable }
            self.onReady = {
                self.baseline = try self.capture()
                done(.success(()))
            }
            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + max(0, self.expires - ProcessInfo.processInfo.systemUptime))
            timer.setEventHandler { [weak self] in self?.finishWithFailure(Failure.timedOut) }
            self.timer = timer
            timer.resume()
            self.startedAt = try self.checkpoint()
            self.connection.start(queue: self.queue)
        }
    }

    func sample() async throws -> Sample {
        try await perform { done in
            guard self.baseline != nil else { throw Failure.unavailable }
            done(.success(try self.capture()))
        }
    }

    func exchange(nonce: UUID) async throws -> Exchange {
        try await perform { done in
            guard self.baseline != nil else { throw Failure.unavailable }
            let began = try self.checkpoint()
            let before = try self.capture()
            let request = try RouterTCPEchoWire.request(nonce)
            self.connection.send(content: request, completion: .contentProcessed { [weak self] error in
                guard let self, self.terminal == nil else { return }
                do {
                    _ = try self.checkpoint()
                    if let error { throw Self.failure(error) }
                    self.readExactly(4) { prefix in
                        do {
                            let count = try RouterTCPEchoWire.bodyLength(try prefix.get())
                            self.readExactly(count) { body in
                                do {
                                    let reply = try RouterTCPEchoWire.parseResponse(try body.get(), expected: nonce)
                                    let after = try self.capture()
                                    let interval = RouterTrafficInterval(start: began, end: try self.checkpoint())
                                    try interval.validate(boot: began.bootID, maximumDuration: 5)
                                    done(.success(.init(reply: reply, before: before, after: after, interval: interval)))
                                } catch { done(.failure(error)) }
                            }
                        } catch { done(.failure(error)) }
                    }
                } catch { done(.failure(error)) }
            })
        }
    }

    private func readExactly(_ count: Int, accumulated: Data = Data(),
                             completion: @escaping (Result<Data, Error>) -> Void) {
        do {
            _ = try checkpoint()
            guard count > 0, count <= RouterTCPEchoWire.maximumBody, accumulated.count < count else {
                throw RouterTCPEchoError.malformed
            }
        } catch { completion(.failure(error)); return }
        connection.receive(minimumIncompleteLength: 1, maximumLength: count - accumulated.count) {
            [weak self] data, _, eof, error in
            guard let self, self.terminal == nil else { return }
            do {
                _ = try self.checkpoint()
                if let error { throw Self.failure(error) }
                guard !eof, let data, !data.isEmpty, data.count <= count - accumulated.count else {
                    throw Failure.eof
                }
                let bytes = accumulated + data
                if bytes.count == count { completion(.success(bytes)) }
                else { self.readExactly(count, accumulated: bytes, completion: completion) }
            } catch { completion(.failure(error)) }
        }
    }

    private func stateChanged(_ state: NWConnection.State) {
        guard terminal == nil else { return }
        do {
            _ = try checkpoint()
            switch state {
            case .ready:
                let action = onReady
                onReady = nil
                try action?()
            case .waiting(let error), .failed(let error): throw Self.failure(error)
            case .cancelled: throw Failure.closed
            case .preparing where baseline != nil: throw Failure.pathChanged
            default: break
            }
        } catch { finishWithFailure(error) }
    }

    private func capture() throws -> Sample {
        _ = try checkpoint()
        guard connection.state == .ready, let path = connection.currentPath,
              path.status == .satisfied, let startedAt else { throw Failure.pathUnknown }
        if let originalPath, originalPath != path { throw Failure.pathChanged }
        let tuple = try Observer.Tuple(local: Self.endpoint(path.localEndpoint, local: true),
                                       peer: Self.endpoint(path.remoteEndpoint, local: false))
        guard tuple.peer == target, tuple.local.family == target.family else { throw Failure.pathChanged }
        guard let metadata = connection.metadata(definition: NWProtocolTLS.definition) as? NWProtocolTLS.Metadata else {
            throw Failure.unsupportedTLS
        }
        let version = sec_protocol_metadata_get_negotiated_tls_protocol_version(metadata.securityProtocolMetadata)
        guard version == .TLSv12 || version == .TLSv13 else { throw Failure.unsupportedTLS }
        let observation = source == .installedHelper
            ? Observer.installedSelf(tuple: tuple, until: expires)
            : Observer.fixtureSelf(tuple: tuple, until: expires)
        let observed: Observer.Evidence
        switch observation {
        case .observed(let evidence): observed = evidence
        case .unknown(let reason): throw Failure.socketUnknown(reason)
        }
        _ = try checkpoint()
        try Self.requireContinuity(observed, initialProcess: initialProcess, baseline: baseline,
            source: source, protocolVersion: UInt16(version.rawValue),
            pathUnchanged: connection.state == .ready && connection.currentPath == path)
        originalPath = path
        return .init(source: source, trust: trust, serverName: serverName,
                     protocolVersion: UInt16(version.rawValue), connectStartedAt: startedAt, socket: observed)
    }

    /// Use the shared sockaddr decoder, including its different local/destination address policies.
    static func endpoint(_ endpoint: NWEndpoint?, local: Bool) throws -> Endpoint {
        guard case .hostPort(let host, let port) = endpoint else { throw Failure.pathUnknown }
        let text: String
        let family: Int32
        switch host {
        case .ipv4(let address): text = address.debugDescription; family = AF_INET
        case .ipv6(let address): text = address.debugDescription; family = AF_INET6
        default: throw Failure.pathUnknown
        }
        guard !text.contains("%"), port.rawValue > 0 else { throw Failure.pathUnknown }
        var storage = sockaddr_storage()
        let length: socklen_t
        if family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = port.rawValue.bigEndian
            guard inet_pton(AF_INET, text, &address.sin_addr) == 1 else { throw Failure.pathUnknown }
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeMutableBytes(of: &storage) { target in
                withUnsafeBytes(of: address) { target.copyBytes(from: $0) }
            }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = port.rawValue.bigEndian
            guard inet_pton(AF_INET6, text, &address.sin6_addr) == 1 else { throw Failure.pathUnknown }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeMutableBytes(of: &storage) { target in
                withUnsafeBytes(of: address) { target.copyBytes(from: $0) }
            }
        }
        return try RouterOwnedTCPProbe.decodeAddress(storage, length: length, local: local)
    }

    @discardableResult private func checkpoint() throws -> RouterSystemClock {
        if let terminal { throw terminal }
        if let requested = stopRequest.read() { throw requested }
        let now = try RouterSystemKernelObservation.clock()
        try Self.requireFresh(began, now, expires)
        try Self.requireFresh(previous, now, expires)
        previous = now
        return now
    }

    static func requireFresh(_ start: RouterSystemClock, _ now: RouterSystemClock,
                             _ deadline: TimeInterval) throws {
        do {
            try RouterOwnedTCPProbe.requireFresh(start: start, now: now, deadline: deadline)
            try RouterTrafficInterval(start: start, end: now).validate(boot: start.bootID, maximumDuration: 5)
        } catch RouterOwnedProbeError.cancelled { throw Failure.cancelled }
        catch { throw Failure.timedOut }
    }

    /// Used by capture, whose live NW state supplies pathUnchanged. It is not a caller proof.
    static func requireContinuity(_ observed: Observer.Evidence,
                                  initialProcess: RouterSystemKernelObservation.ProcessSnapshot,
                                  baseline: Sample?, source: Observer.Source,
                                  protocolVersion: UInt16, pathUnchanged: Bool) throws {
        guard pathUnchanged else { throw Failure.pathChanged }
        guard protocolVersion == 0x0303 || protocolVersion == 0x0304 else { throw Failure.unsupportedTLS }
        guard observed.source == source, observed.process.identity == initialProcess else {
            throw Failure.identityChanged
        }
        if let baseline {
            guard baseline.source == source, baseline.socket.process == observed.process,
                  baseline.socket.socket == observed.socket, baseline.protocolVersion == protocolVersion else {
                throw Failure.identityChanged
            }
        }
    }

    private static func failure(_ error: NWError) -> Failure {
        if case .tls = error { return .tlsFailed }
        return .connectionFailed
    }

    private func finishWithFailure(_ error: Error) {
        guard terminal == nil else { return }
        terminal = error
        timer?.cancel(); timer = nil
        onReady = nil
        connection.cancel()
        let failure = pendingFailure
        pendingFailure = nil
        busy = false
        failure?(error)
    }

    /// Every continuation finishes once on queue. Any failure permanently invalidates this owner.
    private func perform<T>(_ body: @escaping (@escaping (Result<T, Error>) -> Void) throws -> Void) async throws -> T {
        try await withTaskCancellationHandler(operation: {
            try await withCheckedThrowingContinuation { continuation in
                self.queue.async {
                    do { _ = try self.checkpoint() }
                    catch { self.finishWithFailure(error); continuation.resume(throwing: error); return }
                    guard !self.busy else { continuation.resume(throwing: Failure.busy); return }
                    self.busy = true
                    var finished = false
                    self.pendingFailure = { error in
                        guard !finished else { return }
                        finished = true
                        continuation.resume(throwing: error)
                    }
                    let done: (Result<T, Error>) -> Void = { result in
                        guard !finished else { return }
                        do {
                            let value = try result.get()
                            _ = try self.checkpoint()
                            finished = true
                            self.pendingFailure = nil
                            self.busy = false
                            continuation.resume(returning: value)
                        } catch { self.finishWithFailure(error) }
                    }
                    do { try body(done) } catch { self.finishWithFailure(error) }
                }
            }
        }, onCancel: { self.stop(.cancelled) })
    }
}
