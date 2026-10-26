import Foundation
import Darwin

/// Worker-only transport. Production uses a fixed bundled helper; injectable executable is internal for fixtures.
enum GatedAuthorizationProcess {
    static func capture(executable: String, arguments: [String], intent: PFAuthorizationIntent,
                        timeout: TimeInterval = 120,
                        permit: PFAuthorizationStartPermit = .init(),
                        persistBeforeStart: (PFAuthorizationIntent) throws -> Void) -> BoundedProcess.Capture {
        let empty = BoundedProcess.Capture(data: Data(), complete: false, settled: true)
        guard !intent.startMayHaveBeenSent, intent.identity == nil else { return .init(data: Data(), complete: false, settled: false) }
        guard timeout.isFinite, timeout > 0 else { return empty }
        let process = Process(), input = Pipe(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = input; process.standardOutput = output; process.standardError = FileHandle.nullDevice
        let handles = [input.fileHandleForReading, input.fileHandleForWriting, output.fileHandleForReading, output.fileHandleForWriting]
        var closed = Set<Int>()
        func closeOnce(_ index: Int) -> Bool {
            guard closed.insert(index).inserted else { return true }
            do { try handles[index].close(); return true } catch { return false }
        }
        defer { for index in handles.indices { _ = closeOnce(index) } }
        for handle in handles {
            guard fcntl(handle.fileDescriptor, F_SETFD, FD_CLOEXEC) == 0 else { return empty }
        }
        let writer = handles[1].fileDescriptor, reader = handles[2].fileDescriptor
        for fd in [writer, reader] {
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return empty }
        }
        guard fcntl(writer, F_SETNOSIGPIPE, 1) == 0 else { return empty }
        let deadline = connectorTime() + timeout
        do { try process.run() } catch { return empty }
        var failed = false
        if !closeOnce(0) { failed = true }
        if !closeOnce(3) { failed = true }
        let ready = PFAuthorizationGate.ready(intent.executionID)
        var buffer = [UInt8](repeating: 0, count: 4096), captured = Data()
        var started = false, eof = false
        while !failed && !started {
            guard connectorTime() < deadline else { failed = true; break }
            let count = Darwin.read(reader, &buffer, buffer.count)
            if count > 0 {
                captured.append(contentsOf: buffer.prefix(count))
                guard captured.count <= ready.count, ready.starts(with: captured) else { failed = true; break }
                if captured == ready {
                    do {
                        let identity = try PFAuthorizationProcessIdentity.capture(pid: process.processIdentifier, executionID: intent.executionID)
                        let frame = try JSONEncoder().encode(PFAuthorizationStart(execution: identity, request: intent.request))
                        // Round-trip validates even in-memory request values before any START intent is saved.
                        _ = try JSONDecoder().decode(PFAuthorizationStart.self, from: frame)
                        guard frame.count <= PFAuthorizationGate.maximumInput, connectorTime() < deadline,
                              identity.observe() == .sameProcessAlive else { throw PFAuthorizationGate.failure }
                        try persistBeforeStart(intent.armed(with: identity))
                        // A blocked/failed fsync must never be followed by a late START.
                        guard connectorTime() < deadline, identity.observe() == .sameProcessAlive else { throw PFAuthorizationGate.failure }
                        try permit.send {
                            guard connectorTime() < deadline else { throw PFAuthorizationGate.failure }
                            let written = frame.withUnsafeBytes { Darwin.write(writer, $0.baseAddress, $0.count) }
                            // Never resend a partial/unknown write. EOF alone cannot validate a truncated frame.
                            guard written == frame.count else { throw PFAuthorizationGate.failure }
                        }
                        started = true
                    } catch { failed = true }
                    if !closeOnce(1) { failed = true }
                    captured = Data()
                }
            } else if count == 0 { failed = true }
            else if errno != EAGAIN && errno != EINTR { failed = true }
            if !started && !failed { Thread.sleep(forTimeInterval: 0.005) }
        }
        // Include READY in the total output budget.
        let maximumResult = 16_384 - ready.count
        while !failed && started {
            guard connectorTime() < deadline else { failed = true; break }
            if !eof {
                let count = Darwin.read(reader, &buffer, buffer.count)
                if count > 0 {
                    guard captured.count + count <= maximumResult else { failed = true; break }
                    captured.append(contentsOf: buffer.prefix(count))
                } else if count == 0 { eof = true }
                else if errno != EAGAIN && errno != EINTR { failed = true; break }
            }
            if eof && !process.isRunning { break }
            Thread.sleep(forTimeInterval: 0.005)
        }
        if !closeOnce(1) { failed = true }
        // Only the owned local process is signalled, never root descendants.
        if process.isRunning {
            process.terminate()
            let termDeadline = connectorTime() + 0.5
            while process.isRunning && connectorTime() < termDeadline { Thread.sleep(forTimeInterval: 0.01) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            let killDeadline = connectorTime() + 0.5
            while process.isRunning && connectorTime() < killDeadline { Thread.sleep(forTimeInterval: 0.01) }
        }
        let settled = !process.isRunning
        for index in handles.indices { if !closeOnce(index) { failed = true } }
        let complete = !failed && started && eof && settled && process.terminationStatus == 0
        return .init(data: complete ? captured : Data(), complete: complete, settled: settled)
    }
}
