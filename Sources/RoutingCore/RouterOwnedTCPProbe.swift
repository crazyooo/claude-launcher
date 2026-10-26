import Foundation
import Darwin

enum RouterOwnedProbeError: String, Error {
    case invalidTarget, unavailable, refused, timedOut, identityChanged, closed, cancelled
}

/// One owned TCP descriptor, retained through all observations. Production sends no payload.
/// Connecting does not establish TLS, application health, egress or route acceptance.
final class RouterOwnedTCPProbe {
    struct Endpoint: Equatable {
        let address: String
        let bytes: Data
        let port: UInt16
        var family: Int32 { bytes.count == 4 ? AF_INET : AF_INET6 }

        init(address: String, port: UInt16) throws {
            try self.init(address: address, port: port, local: false)
        }
        private init(address: String, port: UInt16, local: Bool) throws {
            guard port > 0, let bytes = RouterTrafficAddress.bytes(address),
                  local || !RouterTrafficAddress.isFake(address) else { throw RouterOwnedProbeError.invalidTarget }
            let octets = Array(bytes)
            if octets.count == 4 {
                guard octets[0] != 0, octets[0] < 224,
                      local || !(octets[0] == 169 && octets[1] == 254) else { throw RouterOwnedProbeError.invalidTarget }
            } else {
                let unspecified = octets.allSatisfy { $0 == 0 }
                let mapped = octets.prefix(10).allSatisfy { $0 == 0 } && octets[10] == 255 && octets[11] == 255
                let compatible = octets.prefix(12).allSatisfy { $0 == 0 } && octets.suffix(4) != [0, 0, 0, 1]
                guard !unspecified, !mapped, !compatible, octets[0] != 255,
                      !(octets[0] == 254 && octets[1] & 0xc0 == 0x80) else {
                    throw RouterOwnedProbeError.invalidTarget
                }
            }
            self.address = address; self.bytes = bytes; self.port = port
        }
        fileprivate static func observedLocal(address: String, port: UInt16) throws -> Self {
            try .init(address: address, port: port, local: true)
        }

        static func == (lhs: Self, rhs: Self) -> Bool { lhs.bytes == rhs.bytes && lhs.port == rhs.port }
        var isLoopback: Bool {
            bytes.count == 4 ? bytes.first == 127 : Array(bytes) == Array(repeating: 0, count: 15) + [1]
        }
    }
    struct Process: Equatable {
        let identity: RouterSystemKernelObservation.ProcessSnapshot
        let path: String
    }
    struct Tuple: Equatable {
        let local: Endpoint
        let peer: Endpoint
    }
    struct Sample: Equatable {
        let process: Process
        let tuple: Tuple
    }
    /// Injection is for fixture runs only; it cannot select installed provenance.
    struct Effects {
        var clock: () throws -> RouterSystemClock
        var process: () throws -> Process
        var create: (Int32) throws -> Int32
        var configure: (Int32, Int32) throws -> Void
        var connect: (Int32, Endpoint, TimeInterval) throws -> Void
        var tuple: (Int32) throws -> Tuple
        var close: (Int32) -> Void
        var io: RouterOwnedTCPIO.Effects? = nil
    }
    private var descriptor: Int32?
    private let effects: Effects
    private let original: Sample
    /// Lower bound for a new tracker; ready may occur after the tracker was created.
    let connectStartedAt: RouterSystemClock
    let openedAt: RouterSystemClock
    let fixture: Bool

    private init(descriptor: Int32, effects: Effects, sample: Sample,
                 connectStartedAt: RouterSystemClock, openedAt: RouterSystemClock, fixture: Bool) {
        self.descriptor = descriptor; self.effects = effects; original = sample
        self.connectStartedAt = connectStartedAt
        self.openedAt = openedAt; self.fixture = fixture
    }
    deinit { close() }
    func close() {
        guard let fd = descriptor else { return }
        descriptor = nil
        effects.close(fd)
    }
    func sample(until deadline: TimeInterval) throws -> Sample {
        guard let fd = descriptor else { throw RouterOwnedProbeError.closed }
        try Self.requireFresh(start: openedAt, now: effects.clock(), deadline: deadline)
        let before = try effects.process(), tuple = try effects.tuple(fd), after = try effects.process()
        guard before == after, before == original.process, tuple == original.tuple else {
            throw RouterOwnedProbeError.identityChanged
        }
        try Self.requireFresh(start: openedAt, now: effects.clock(), deadline: deadline)
        return .init(process: after, tuple: tuple)
    }
    /// Plaintext exchange is available only to an unprivileged loopback fixture.
    func exchangeLoopbackFixture(nonce: UUID, until deadline: TimeInterval) throws -> RouterOwnedTCPIO.Observation {
        guard fixture, getuid() != 0, geteuid() == getuid(),
              original.tuple.peer.isLoopback, !original.tuple.peer.address.contains("%"),
              let descriptor, let io = effects.io else { throw RouterOwnedProbeError.unavailable }
        let before = try sample(until: deadline)
        let exchange = try RouterOwnedTCPIO.exchange(fd: descriptor, nonce: nonce, until: deadline,
                                                     clock: effects.clock, io: io)
        guard try sample(until: deadline) == before else { throw RouterOwnedProbeError.identityChanged }
        return exchange
    }
    static func installed(address: String, port: UInt16, until deadline: TimeInterval) throws -> RouterOwnedTCPProbe {
        guard getuid() == 0, geteuid() == 0 else { throw RouterOwnedProbeError.unavailable }
        return try open(endpoint: .init(address: address, port: port), until: deadline, fixture: false,
                        effects: native(requireInstalledHelper: true))
    }
    static func fixture(endpoint: Endpoint, until deadline: TimeInterval, effects: Effects) throws -> RouterOwnedTCPProbe {
        guard getuid() != 0, geteuid() != 0 else { throw RouterOwnedProbeError.unavailable }
        return try open(endpoint: endpoint, until: deadline, fixture: true, effects: effects)
    }
    /// Real syscall coverage limited to the unprivileged test process and loopback.
    static func loopbackFixture(endpoint: Endpoint, until deadline: TimeInterval) throws -> RouterOwnedTCPProbe {
        guard getuid() != 0, geteuid() == getuid(), endpoint.isLoopback,
              !endpoint.address.contains("%") else { throw RouterOwnedProbeError.invalidTarget }
        return try open(endpoint: endpoint, until: deadline, fixture: true, effects: native(requireInstalledHelper: false))
    }
    private static func open(endpoint: Endpoint, until deadline: TimeInterval,
                             fixture: Bool, effects: Effects) throws -> RouterOwnedTCPProbe {
        let began = try effects.clock()
        let connectDeadline = min(deadline, began.uptime + 3)
        try requireFresh(start: began, now: began, deadline: connectDeadline)
        let identity = try effects.process()
        guard identity.identity.work.bootID == began.bootID else { throw RouterOwnedProbeError.identityChanged }
        let fd = try effects.create(endpoint.family)
        guard fd >= 0 else { throw RouterOwnedProbeError.unavailable }
        var transferred = false
        defer { if !transferred { effects.close(fd) } }
        try effects.configure(fd, endpoint.family)
        let connecting = try effects.clock()
        try requireFresh(start: began, now: connecting, deadline: connectDeadline)
        try effects.connect(fd, endpoint, connectDeadline)
        let tuple = try effects.tuple(fd)
        guard tuple.peer == endpoint, tuple.local.family == endpoint.family,
              try effects.process() == identity else { throw RouterOwnedProbeError.identityChanged }
        let ready = try effects.clock()
        try requireFresh(start: began, now: ready, deadline: connectDeadline)
        try requireFresh(start: connecting, now: ready, deadline: connectDeadline)
        let result = RouterOwnedTCPProbe(descriptor: fd, effects: effects,
            sample: .init(process: identity, tuple: tuple),
            connectStartedAt: connecting, openedAt: ready, fixture: fixture)
        transferred = true
        return result
    }
    static func requireFresh(start: RouterSystemClock, now: RouterSystemClock, deadline: TimeInterval) throws {
        guard !Task.isCancelled else { throw RouterOwnedProbeError.cancelled }
        guard deadline.isFinite, now.uptime < deadline else { throw RouterOwnedProbeError.timedOut }
        do {
            try RouterTrafficInterval(start: start, end: now).validate(boot: start.bootID, maximumDuration: 60)
        } catch { throw RouterOwnedProbeError.timedOut }
    }
    private static func native(requireInstalledHelper: Bool) -> Effects {
        .init(clock: RouterSystemKernelObservation.clock, process: {
            let first = try RouterSystemKernelObservation.Reader.live.process(getpid())
            var buffer = [CChar](repeating: 0, count: 4096)
            let count = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
            guard count > 0, Int(count) < buffer.count,
                  let nul = buffer.firstIndex(of: 0), nul == Int(count),
                  let path = String(bytes: buffer.prefix(nul).map { UInt8(bitPattern: $0) }, encoding: .utf8),
                  RouterValidation.validProcessPath(path), first.uid == getuid(), first.realUID == getuid(),
                  geteuid() == getuid(),
                  !requireInstalledHelper || (getuid() == 0 && path == RouterSystemLayout.helper),
                  try RouterSystemKernelObservation.Reader.live.process(getpid()) == first else {
                throw RouterOwnedProbeError.identityChanged
            }
            return .init(identity: first, path: path)
        }, create: { family in
            let fd = Darwin.socket(family, SOCK_STREAM, IPPROTO_TCP)
            guard fd >= 0 else { throw RouterOwnedProbeError.unavailable }
            return fd
        }, configure: { fd, family in
            guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { throw RouterOwnedProbeError.unavailable }
            var noSignal: Int32 = 1
            guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                throw RouterOwnedProbeError.unavailable
            }
            if family == AF_INET6 {
                var only: Int32 = 1
                guard setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &only, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                    throw RouterOwnedProbeError.unavailable
                }
            }
        }, connect: connect, tuple: socketTuple, close: { _ = Darwin.close($0) }, io: .native)
    }
    private static func connect(_ fd: Int32, _ endpoint: Endpoint, _ deadline: TimeInterval) throws {
        let result: Int32
        if endpoint.family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
            address.sin_port = endpoint.port.bigEndian
            _ = withUnsafeMutableBytes(of: &address.sin_addr) { endpoint.bytes.copyBytes(to: $0) }
            result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        } else {
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); address.sin6_family = sa_family_t(AF_INET6)
            address.sin6_port = endpoint.port.bigEndian
            _ = withUnsafeMutableBytes(of: &address.sin6_addr) { endpoint.bytes.copyBytes(to: $0) }
            result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
            }
        }
        let error = result == 0 ? 0 : errno
        if result != 0 && error != EINPROGRESS { throw connectionError(error) }
        if result != 0 {
            try waitForConnect(deadline: deadline, uptime: { ProcessInfo.processInfo.systemUptime }, poll: { timeout in
                var item = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                let result = Darwin.poll(&item, 1, timeout)
                return (result, result < 0 ? errno : 0, item.revents)
            }, socketError: {
                var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0,
                      length == MemoryLayout<Int32>.size else { throw RouterOwnedProbeError.unavailable }
                return error
            })
        }
        guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterOwnedProbeError.timedOut }
    }
    /// Same loop for production poll/SO_ERROR and deterministic deadline/EINTR tests.
    static func waitForConnect(deadline: TimeInterval, uptime: () -> TimeInterval,
                               poll: (Int32) -> (Int32, Int32, Int16),
                               socketError: () throws -> Int32) throws {
        while true {
            guard !Task.isCancelled else { throw RouterOwnedProbeError.cancelled }
            let remaining = deadline - uptime()
            guard deadline.isFinite, remaining.isFinite, remaining > 0 else { throw RouterOwnedProbeError.timedOut }
            let milliseconds = Int32(min(ceil(remaining * 1000), 3000))
            let (count, error, events) = poll(milliseconds)
            guard !Task.isCancelled else { throw RouterOwnedProbeError.cancelled }
            guard uptime() < deadline else { throw RouterOwnedProbeError.timedOut }
            if count < 0 && error == EINTR { continue }
            guard count >= 0 else { throw RouterOwnedProbeError.unavailable }
            if count == 0 { throw RouterOwnedProbeError.timedOut }
            guard events & Int16(POLLNVAL) == 0,
                  events & Int16(POLLOUT | POLLERR | POLLHUP) != 0 else { throw RouterOwnedProbeError.unavailable }
            let errorCode = try socketError()
            guard errorCode == 0 else { throw connectionError(errorCode) }
            return
        }
    }
    private static func connectionError(_ code: Int32) -> RouterOwnedProbeError {
        code == ECONNREFUSED ? .refused : (code == ETIMEDOUT ? .timedOut : .unavailable)
    }
    private static func socketTuple(_ fd: Int32) throws -> Tuple {
        var type: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &size) == 0,
              size == MemoryLayout<Int32>.size, type == SOCK_STREAM else { throw RouterOwnedProbeError.identityChanged }
        func endpoint(peer: Bool) throws -> Endpoint {
            var storage = sockaddr_storage(), length = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let result = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    peer ? getpeername(fd, $0, &length) : getsockname(fd, $0, &length)
                }
            }
            guard result == 0 else { throw RouterOwnedProbeError.unavailable }
            return try decodeAddress(storage, length: length, local: !peer)
        }
        return try .init(local: endpoint(peer: false), peer: endpoint(peer: true))
    }
    static func decodeAddress(_ storage: sockaddr_storage, length: socklen_t, local: Bool = false) throws -> Endpoint {
        var storage = storage
        var text = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let port: UInt16
        if storage.ss_family == AF_INET {
            guard length == MemoryLayout<sockaddr_in>.size, storage.ss_len == length else {
                throw RouterOwnedProbeError.identityChanged
            }
            var address = withUnsafePointer(to: &storage) { $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee } }
            port = UInt16(bigEndian: address.sin_port)
            guard inet_ntop(AF_INET, &address.sin_addr, &text, socklen_t(text.count)) != nil else {
                throw RouterOwnedProbeError.identityChanged
            }
        } else if storage.ss_family == AF_INET6 {
            guard length == MemoryLayout<sockaddr_in6>.size, storage.ss_len == length else {
                throw RouterOwnedProbeError.identityChanged
            }
            var address = withUnsafePointer(to: &storage) { $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee } }
            guard address.sin6_scope_id == 0 else { throw RouterOwnedProbeError.invalidTarget }
            port = UInt16(bigEndian: address.sin6_port)
            guard inet_ntop(AF_INET6, &address.sin6_addr, &text, socklen_t(text.count)) != nil else {
                throw RouterOwnedProbeError.identityChanged
            }
        } else { throw RouterOwnedProbeError.identityChanged }
        return try local ? Endpoint.observedLocal(address: String(cString: text), port: port) :
            Endpoint(address: String(cString: text), port: port)
    }
}
