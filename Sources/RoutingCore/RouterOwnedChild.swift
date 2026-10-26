import Foundation
import Darwin

/// This object is the exclusive reaper of its direct child. Never reconstruct it from a journal PID.
/// Callers retain it even if persisting identity or releasing the gate fails.
final class RouterOwnedChild {
    enum Observation: Equatable { case running, exited(Int32), ownershipUnknown }
    let instance: UUID
    let pid: pid_t
    private let lock = NSLock()
    private var gate: Int32?
    private var terminal: Observation?

    private init(instance: UUID, pid: pid_t, gate: Int32) {
        self.instance = instance; self.pid = pid; self.gate = gate
    }

    /// Only the installed provider chooses the verified executable and fixed argv; IPC cannot supply them.
    static func spawn(instance: UUID, executable: String, arguments: [String]) throws -> RouterOwnedChild {
        try requireExclusiveReaping()
        guard executable.hasPrefix("/"), !executable.utf8.contains(0),
              !arguments.contains(where: { $0.utf8.contains(0) }) else { throw RouterSystemError.invalidRequest }
        var pipeFDs = [Int32](repeating: -1, count: 2)
        guard pipe(&pipeFDs) == 0 else { throw RouterSystemError.operationUnsettled }
        var parentOwnsWrite = true
        defer {
            close(pipeFDs[0])
            if parentOwnsWrite { close(pipeFDs[1]) }
        }
        guard fcntl(pipeFDs[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(pipeFDs[1], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(pipeFDs[1], F_SETNOSIGPIPE, 1) == 0,
              fcntl(pipeFDs[1], F_SETFL, O_NONBLOCK) == 0 else { throw RouterSystemError.operationUnsettled }
        var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw RouterSystemError.operationUnsettled }
        defer { posix_spawn_file_actions_destroy(&actions) }
        guard posix_spawnattr_init(&attributes) == 0 else { throw RouterSystemError.operationUnsettled }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_adddup2(&actions, pipeFDs[0], STDIN_FILENO) == 0,
              posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0 else {
            throw RouterSystemError.operationUnsettled
        }
        func duplicate(_ value: String) -> UnsafeMutablePointer<CChar>? { value.withCString { strdup($0) } }
        let argv = ([executable] + arguments).map(duplicate)
        let env = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"].map(duplicate)
        defer { argv.forEach { free($0) }; env.forEach { free($0) } }
        guard argv.allSatisfy({ $0 != nil }), env.allSatisfy({ $0 != nil }) else { throw RouterSystemError.operationUnsettled }
        var argvTerminated = argv + [nil], envTerminated = env + [nil], pid: pid_t = 0
        let error = posix_spawn(&pid, executable, &actions, &attributes, &argvTerminated, &envTerminated)
        guard error == 0 else { throw RouterSystemError.operationUnsettled }
        parentOwnsWrite = false
        return .init(instance: instance, pid: pid, gate: pipeFDs[1])
    }

    func observe() -> Observation {
        lock.lock(); defer { lock.unlock() }
        return observeLocked()
    }
    private func observeLocked() -> Observation {
        if let terminal { return terminal }
        var status: Int32 = 0
        var result: pid_t
        repeat { result = waitpid(pid, &status, WNOHANG) } while result < 0 && errno == EINTR
        if result == 0 { return .running }
        terminal = result == pid ? .exited(status) : .ownershipUnknown
        closeGateLocked()
        return terminal!
    }
    func closeGate() {
        lock.lock(); defer { lock.unlock() }
        closeGateLocked()
    }
    private func closeGateLocked() {
        if let fd = gate { gate = nil; close(fd) }
    }
    func releaseGate() throws {
        lock.lock(); defer { lock.unlock() }
        guard observeLocked() == .running, let fd = gate else { throw RouterSystemError.operationUnsettled }
        defer { closeGateLocked() }
        let data = RouterSystemGate.permit(instance)
        // One small nonblocking write is atomic (below PIPE_BUF). Never retry partial/unknown writes.
        let written = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, $0.count) }
        guard written == data.count else { throw RouterSystemError.operationUnsettled }
    }
    func signal(_ number: Int32) throws {
        lock.lock(); defer { lock.unlock() }
        try Self.requireExclusiveReaping()
        switch observeLocked() {
        case .exited: return
        case .ownershipUnknown: throw RouterSystemError.ownershipUnknown
        case .running:
            // A direct, unreaped child cannot have its PID reused between this check and kill.
            guard kill(pid, number) == 0 || errno == ESRCH else { throw RouterSystemError.operationUnsettled }
        }
    }
    func waitUntil(_ deadline: TimeInterval) -> Observation {
        guard deadline.isFinite else { return observe() }
        while true {
            let result = observe()
            guard result == .running, ProcessInfo.processInfo.systemUptime < deadline else { return result }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }
    /// The installed single-purpose host must keep this disposition unchanged for its whole lifetime,
    /// use no global waitpid(-1), and never register an automatic reaper. Reject rather than modify it here.
    static func requireExclusiveReaping() throws {
        var action = sigaction()
        guard sigaction(SIGCHLD, nil, &action) == 0 else { throw RouterSystemError.ownershipUnknown }
        try validateReaping(action)
    }
    static func validateReaping(_ action: sigaction) throws {
        guard action.sa_flags & SA_NOCLDWAIT == 0, action.__sigaction_u.__sa_handler == nil else {
            throw RouterSystemError.ownershipUnknown
        }
    }
    deinit { closeGate() } // Never signal from deinit. The host retains this object until terminal.
}

enum RouterSystemGate {
    static func permit(_ id: UUID) -> Data { Data(("START " + id.uuidString.lowercased() + "\n").utf8) }

    /// Requires exact bytes AND EOF within one absolute deadline; malformed/partial messages never authorize exec.
    static func receive(fd: Int32, instance: UUID, deadline: TimeInterval) throws {
        let expected = permit(instance)
        var received = Data()
        guard deadline.isFinite else { throw RouterSystemError.stalePreview }
        while true {
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            guard remaining > 0 else { throw RouterSystemError.stalePreview }
            var event = pollfd(fd: fd, events: Int16(POLLIN | POLLHUP), revents: 0)
            let result = poll(&event, 1, Int32(min(remaining * 1000 + 1, Double(Int32.max))))
            if result < 0 && errno == EINTR { continue }
            guard result > 0, event.revents & Int16(POLLNVAL | POLLERR) == 0 else { throw RouterSystemError.operationUnsettled }
            var bytes = [UInt8](repeating: 0, count: expected.count + 1)
            let count = Darwin.read(fd, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterSystemError.operationUnsettled }
            guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.stalePreview }
            if count == 0 {
                guard received == expected else { throw RouterSystemError.invalidRequest }
                return
            }
            received.append(contentsOf: bytes.prefix(count))
            guard received.count <= expected.count, expected.starts(with: received) else { throw RouterSystemError.invalidRequest }
        }
    }
}
