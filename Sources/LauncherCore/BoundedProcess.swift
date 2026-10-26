import Foundation
import Darwin

/// Bounded helper execution for authorization and small proxy probes.
enum BoundedProcess {
    struct Capture {
        let data: Data
        let complete, settled: Bool
    }

    struct Diagnostic {
        let data: Data
        let exitCode: Int32?
        let complete, settled, cancelled, timedOut: Bool
    }

    /// Preserve the original capture contract, including discarding nonzero-exit output.
    static func capture(executable: String, arguments: [String], timeout: TimeInterval, input: Data? = nil) -> Capture {
        let value = run(executable: executable, arguments: arguments, timeout: timeout, input: input,
                        maximumInput: 4096, cancelled: { false })
        let success = value.complete && value.exitCode == 0
        return .init(data: success ? value.data : Data(), complete: success, settled: value.settled)
    }

    static func diagnostic(arguments: [String], timeout: TimeInterval, input: Data,
                           cancelled: () -> Bool) -> Diagnostic {
        run(executable: "/usr/bin/curl", arguments: arguments, timeout: timeout,
            input: input, maximumInput: 16_384, cancelled: cancelled)
    }

    /// Worker-only, shared bounded engine. No stderr or inherited proxy/credential environment.
    static func run(executable: String, arguments: [String], timeout: TimeInterval,
                    input: Data?, maximumInput: Int, cancelled: () -> Bool) -> Diagnostic {
        var wasCancelled = false, timedOut = false
        func unavailable() -> Diagnostic {
            .init(data: Data(), exitCode: nil, complete: false, settled: true,
                  cancelled: cancelled(), timedOut: false)
        }

        let process = Process(), pipe = Pipe()
        let stdin = input == nil ? nil : Pipe()
        process.executableURL = URL(fileURLWithPath: executable); process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = stdin?.fileHandleForReading ?? FileHandle.nullDevice
        process.standardOutput = pipe; process.standardError = FileHandle.nullDevice
        let reader = pipe.fileHandleForReading, writer = pipe.fileHandleForWriting
        var writerClosed = false, stdinClosed = false, stdinReaderClosed = false
        func closeOnce(_ handle: FileHandle, attempted: inout Bool) -> Bool {
            guard !attempted else { return true }
            // A failed close has uncertain descriptor ownership; never retry a reused fd.
            attempted = true
            do { try handle.close(); return true } catch { return false }
        }
        func closeHandles() -> Bool {
            var success = closeOnce(writer, attempted: &writerClosed)
            do { try reader.close() } catch { success = false }
            if let stdin {
                if !closeOnce(stdin.fileHandleForWriting, attempted: &stdinClosed) { success = false }
                if !closeOnce(stdin.fileHandleForReading, attempted: &stdinReaderClosed) { success = false }
            }
            return success
        }
        let fd = reader.fileDescriptor
        let flags = fcntl(fd, F_GETFL)
        guard input == nil || input!.count <= maximumInput, timeout.isFinite, timeout > 0, flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else {
            _ = closeHandles(); return unavailable()
        }
        if let stdin {
            let fd = stdin.fileHandleForWriting.fileDescriptor
            let flags = fcntl(fd, F_GETFL)
            guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
                  fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else {
                _ = closeHandles(); return unavailable()
            }
        }
        guard !cancelled() else { _ = closeHandles(); return unavailable() }
        let deadline = connectorTime() + timeout
        do { try process.run() } catch {
            _ = closeHandles(); return unavailable()
        }
        var failed = !closeOnce(writer, attempted: &writerClosed)
        // A delayed spawn must not submit credentials after cancellation or expiry.
        if cancelled() { wasCancelled = true; failed = true }
        if connectorTime() >= deadline { timedOut = true; failed = true }
        if let stdin, let input {
            if !closeOnce(stdin.fileHandleForReading, attempted: &stdinReaderClosed) { failed = true }
            let descriptor = stdin.fileHandleForWriting.fileDescriptor
            if !failed {
                // Small credential envelopes only, never argv/environment. Partial writes fail closed.
                let count = input.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
                if count != input.count { failed = true }
            }
            if !closeOnce(stdin.fileHandleForWriting, attempted: &stdinClosed) { failed = true }
        }
        var output = Data(), eof = false
        var buffer = [UInt8](repeating: 0, count: 4096)
        while !failed {
            if cancelled() { wasCancelled = true; failed = true; break }
            if connectorTime() >= deadline { timedOut = true; failed = true; break }
            if !eof {
                let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
                if count > 0 {
                    if output.count + count > 16_384 { failed = true; break }
                    output.append(contentsOf: buffer.prefix(count))
                } else if count == 0 { eof = true }
                else if errno != EAGAIN && errno != EINTR { failed = true; break }
            }
            if !process.isRunning && eof { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        if process.isRunning {
            process.terminate()
            let grace = connectorTime() + 0.5
            while process.isRunning && connectorTime() < grace { Thread.sleep(forTimeInterval: 0.01) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            let killGrace = connectorTime() + 0.5
            while process.isRunning && connectorTime() < killGrace { Thread.sleep(forTimeInterval: 0.01) }
        }
        let settled = !process.isRunning
        let exitCode = settled && process.terminationReason == .exit ? process.terminationStatus : nil
        wasCancelled = wasCancelled || cancelled()
        let complete = !failed && eof && settled && !wasCancelled
        let closed = closeHandles()
        return .init(data: complete && closed ? output : Data(), exitCode: exitCode,
                     complete: complete && closed, settled: settled, cancelled: wasCancelled, timedOut: timedOut)
    }
}
