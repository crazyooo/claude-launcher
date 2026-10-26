import Foundation
import Darwin

/// The installed host retains one runner throughout its lifetime, including failed requests.
/// No Foundation.Process or global waitpid(-1) may reap its children.
final class RouterSystemCommand {
    enum Command {
        case routesIPv4, routesIPv6, selectedRouteIPv4, selectedRouteIPv6, dnsState, vpnServices, userCoreJob, validateCore(UUID)
        case systemJob, bootstrapSystemJob, bootoutSystemJob
    }
    private let ownerUID: UInt32
    private let lock = NSLock()
    private var pending: Child?

    init(ownerUID: UInt32) throws {
        guard ownerUID >= 501, ownerUID < UInt32.max else { throw RouterSystemError.ownershipUnknown }
        self.ownerUID = ownerUID
    }

    func run(_ command: Command) throws -> (RouterProcessResult, Data) {
        let path: String, arguments: [String], timeout: TimeInterval
        switch command {
        case .routesIPv4: path = "/usr/sbin/netstat"; arguments = ["-rn", "-f", "inet"]; timeout = 3
        case .routesIPv6: path = "/usr/sbin/netstat"; arguments = ["-rn", "-f", "inet6"]; timeout = 3
        case .selectedRouteIPv4: path = "/sbin/route"; arguments = ["-n", "get", "-inet", "1.1.1.1"]; timeout = 3
        case .selectedRouteIPv6: path = "/sbin/route"; arguments = ["-n", "get", "-inet6", "2606:4700:4700::1111"]; timeout = 3
        case .dnsState: path = "/usr/sbin/scutil"; arguments = ["--dns"]; timeout = 3
        case .vpnServices: path = "/usr/sbin/scutil"; arguments = ["--nc", "list"]; timeout = 3
        case .userCoreJob:
            path = "/bin/launchctl"; arguments = ["print", "gui/\(ownerUID)/" + RouterCoreRelease.label]; timeout = 3
        case .systemJob, .bootstrapSystemJob, .bootoutSystemJob:
            guard getuid() == 0, geteuid() == 0 else { throw RouterSystemError.ownershipUnknown }
            path = "/bin/launchctl"; timeout = 3
            switch command {
            case .systemJob: arguments = ["print", "system/" + RouterSystemLayout.label]
            case .bootstrapSystemJob:
                arguments = ["bootstrap", "system", RouterSystemLayout.launchDaemons + "/" + RouterSystemInstallFile.launchd.leaf]
            default: arguments = ["bootout", "system/" + RouterSystemLayout.label]
            }
        case .validateCore(let id):
            let directory = RouterSystemLayout.state + "/stage-" + id.uuidString.lowercased()
            path = "/usr/bin/sandbox-exec"
            arguments = ["-p", "(version 1)(allow default)(deny network*)", RouterSystemLayout.core,
                         "-t", "-d", directory, "-f", directory + "/config.json"]
            timeout = 15
        }
        return try capture(path, arguments, timeout: timeout)
    }

    /// Matches only the existing read-only observer's exact calls and this installation's user.
    func captureObservation(_ path: String, _ args: [String], _ timeout: TimeInterval) throws -> (RouterProcessResult, Data) {
        guard timeout == 3 else { throw RouterSystemError.invalidRequest }
        switch (path, args) {
        case ("/usr/sbin/netstat", ["-rn", "-f", "inet"]): return try run(.routesIPv4)
        case ("/usr/sbin/netstat", ["-rn", "-f", "inet6"]): return try run(.routesIPv6)
        case ("/usr/sbin/scutil", ["--nc", "list"]): return try run(.vpnServices)
        case ("/bin/launchctl", ["print", "gui/\(ownerUID)/" + RouterCoreRelease.label]): return try run(.userCoreJob)
        default: throw RouterSystemError.invalidRequest
        }
    }

    /// No root or IPC caller can use the test-only arbitrary executable entry point.
    func fixtureCapture(_ path: String, _ args: [String], timeout: TimeInterval) throws -> (RouterProcessResult, Data) {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        return try capture(path, args, timeout: timeout)
    }

    private func capture(_ path: String, _ args: [String], timeout: TimeInterval) throws -> (RouterProcessResult, Data) {
        guard timeout.isFinite, timeout > 0, timeout <= 15, path.hasPrefix("/"),
              !([path] + args).contains(where: { $0.utf8.contains(0) }) else { throw RouterSystemError.invalidRequest }
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try RouterOwnedChild.requireExclusiveReaping()
        if let old = pending {
            old.closeReader()
            try old.terminate()
            pending = nil // terminate returns only after this precise child was reaped.
        }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let child = try Child.spawn(path, args)
        pending = child
        var stopAttempted = false
        do {
            while true {
                try child.drain(until: deadline)
                try child.sample()
                // A late exit/EOF cannot turn an expired operation into a success.
                if ProcessInfo.processInfo.systemUptime >= deadline {
                    child.closeReader()
                    stopAttempted = true
                    try child.terminate()
                    pending = nil
                    return (.init(exitCode: child.exitCode, timedOut: true, settled: true), Data())
                }
                if child.exited && child.eof {
                    pending = nil
                    return (.init(exitCode: child.exitCode, timedOut: false, settled: true), child.output)
                }
                child.pause(until: deadline)
            }
        } catch {
            child.closeReader()
            // Failure to reap keeps the owner occupied. A later request drains it before spawning.
            if !stopAttempted, (try? child.terminate()) != nil { pending = nil }
            throw RouterSystemError.operationUnsettled
        }
    }

    private final class Child {
        let pid: pid_t
        private var reader: Int32?
        private var status: Int32?
        private var unknown = false
        private(set) var output = Data()
        var exited: Bool { status != nil }
        var eof: Bool { reader == nil }
        var exitCode: Int32 {
            guard let status else { return -1 }
            return status & 0x7f == 0 ? (status >> 8) & 0xff : 128 + (status & 0x7f)
        }
        init(pid: pid_t, reader: Int32) { self.pid = pid; self.reader = reader }
        deinit { closeReader() }
        func closeReader() { if let fd = reader { reader = nil; close(fd) } }
        func sample() throws {
            guard !unknown else { throw RouterSystemError.ownershipUnknown }
            if exited { return }
            var result: pid_t, value: Int32 = 0
            repeat { result = waitpid(pid, &value, WNOHANG) } while result < 0 && errno == EINTR
            if result == pid { status = value }
            else if result != 0 { unknown = true; throw RouterSystemError.ownershipUnknown }
        }
        func terminate() throws {
            try RouterOwnedChild.requireExclusiveReaping()
            for (signal, grace): (Int32, TimeInterval) in [(SIGTERM, 0.5), (SIGKILL, 1)] {
                try sample()
                if exited { return }
                // This PID belongs to our direct unreaped child and cannot yet be reused.
                guard kill(pid, signal) == 0 || errno == ESRCH else { throw RouterSystemError.operationUnsettled }
                let deadline = ProcessInfo.processInfo.systemUptime + grace
                repeat {
                    try sample()
                    if exited { return }
                    _ = poll(nil, 0, 10)
                } while ProcessInfo.processInfo.systemUptime < deadline
            }
            throw RouterSystemError.operationUnsettled
        }
        func drain(until deadline: TimeInterval) throws {
            guard let fd = reader else { return }
            var buffer = [UInt8](repeating: 0, count: 4096)
            for _ in 0..<8 {
                if ProcessInfo.processInfo.systemUptime >= deadline { return }
                let count = Darwin.read(fd, &buffer, buffer.count)
                if count > 0 {
                    guard output.count + count <= 65_536 else { throw RouterSystemError.operationUnsettled }
                    output.append(contentsOf: buffer.prefix(count))
                } else if count == 0 { closeReader(); return }
                else if errno == EAGAIN { return }
                else if errno != EINTR { throw RouterSystemError.operationUnsettled }
            }
        }
        func pause(until deadline: TimeInterval) {
            var item = pollfd(fd: reader ?? -1, events: Int16(POLLIN), revents: 0)
            _ = poll(&item, 1, Int32(max(0, min(10, (deadline - ProcessInfo.processInfo.systemUptime) * 1000))))
        }

        static func spawn(_ path: String, _ args: [String]) throws -> Child {
            var descriptors = [Int32](repeating: -1, count: 2)
            guard pipe(&descriptors) == 0 else { throw RouterSystemError.operationUnsettled }
            var transferred = false
            defer { close(descriptors[1]); if !transferred { close(descriptors[0]) } }
            for fd in descriptors {
                guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw RouterSystemError.operationUnsettled }
            }
            guard fcntl(descriptors[0], F_SETFL, O_NONBLOCK) == 0 else { throw RouterSystemError.operationUnsettled }
            var actions: posix_spawn_file_actions_t?, attributes: posix_spawnattr_t?
            guard posix_spawn_file_actions_init(&actions) == 0 else { throw RouterSystemError.operationUnsettled }
            defer { posix_spawn_file_actions_destroy(&actions) }
            guard posix_spawnattr_init(&attributes) == 0 else { throw RouterSystemError.operationUnsettled }
            defer { posix_spawnattr_destroy(&attributes) }
            var mask = sigset_t(), defaults = sigset_t()
            sigemptyset(&mask); sigemptyset(&defaults)
            for signal in [SIGPIPE, SIGTERM, SIGINT, SIGCHLD] { sigaddset(&defaults, signal) }
            guard posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0) == 0,
                  posix_spawn_file_actions_adddup2(&actions, descriptors[1], STDOUT_FILENO) == 0,
                  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0) == 0,
                  posix_spawnattr_setsigmask(&attributes, &mask) == 0,
                  posix_spawnattr_setsigdefault(&attributes, &defaults) == 0,
                  posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF)) == 0 else {
                throw RouterSystemError.operationUnsettled
            }
            func duplicate(_ value: String) -> UnsafeMutablePointer<CChar>? { value.withCString { strdup($0) } }
            let argv = ([path] + args).map(duplicate)
            let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"].map(duplicate)
            defer { argv.forEach { free($0) }; environment.forEach { free($0) } }
            guard argv.allSatisfy({ $0 != nil }), environment.allSatisfy({ $0 != nil }) else { throw RouterSystemError.operationUnsettled }
            var arguments = argv + [nil], variables = environment + [nil], pid: pid_t = 0
            guard posix_spawn(&pid, path, &actions, &attributes, &arguments, &variables) == 0 else { throw RouterSystemError.operationUnsettled }
            transferred = true
            return Child(pid: pid, reader: descriptors[0])
        }
    }
}
