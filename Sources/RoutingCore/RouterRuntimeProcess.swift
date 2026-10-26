import Foundation
import Darwin

struct RouterProcessResult { let exitCode: Int32; let timedOut: Bool; let settled: Bool }

/// Raw tool output is discarded: it can contain configuration and credentials.
enum RouterRuntimeProcess {
    static func capture(_ executable: String, _ arguments: [String], timeout: TimeInterval) throws -> (RouterProcessResult, Data) {
        guard timeout > 0, timeout <= 60 else { throw RouterRuntimeError.operationFailed }
        let child = Process(), pipe = Pipe()
        child.executableURL = URL(fileURLWithPath: executable); child.arguments = arguments
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        child.standardInput = FileHandle.nullDevice; child.standardOutput = pipe; child.standardError = FileHandle.nullDevice
        let reader = pipe.fileHandleForReading, writer = pipe.fileHandleForWriting
        defer { try? reader.close() }
        let fd = reader.fileDescriptor
        guard fcntl(fd, F_SETFL, O_NONBLOCK) == 0 else { try? writer.close(); throw RouterRuntimeError.operationFailed }
        do { try child.run() } catch { try? writer.close(); throw RouterRuntimeError.operationFailed }
        try? writer.close()
        var data = Data(), buffer = [UInt8](repeating: 0, count: 4096), eof = false, overflow = false
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while ProcessInfo.processInfo.systemUptime < deadline {
            let n = Darwin.read(fd, &buffer, buffer.count)
            if n > 0 {
                if data.count + n > 65_536 { overflow = true; break }
                data.append(contentsOf: buffer.prefix(n))
            } else if n == 0 { eof = true }
            else if errno != EAGAIN && errno != EINTR { overflow = true; break }
            if eof && !child.isRunning { break }
            Thread.sleep(forTimeInterval: 0.01)
        }
        let expired = child.isRunning || !eof
        if child.isRunning {
            child.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 0.5
            while child.isRunning && ProcessInfo.processInfo.systemUptime < grace { Thread.sleep(forTimeInterval: 0.01) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            let end = ProcessInfo.processInfo.systemUptime + 0.5
            while child.isRunning && ProcessInfo.processInfo.systemUptime < end { Thread.sleep(forTimeInterval: 0.01) }
        }
        let settled = !child.isRunning
        return (.init(exitCode: settled ? child.terminationStatus : -1, timedOut: expired || overflow, settled: settled),
                expired || overflow ? Data() : data)
    }
    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) throws -> RouterProcessResult {
        guard timeout > 0, timeout <= 60 else { throw RouterRuntimeError.operationFailed }
        let child = Process()
        child.executableURL = URL(fileURLWithPath: executable); child.arguments = arguments
        child.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
        do { try child.run() } catch { throw RouterRuntimeError.operationFailed }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        while child.isRunning && ProcessInfo.processInfo.systemUptime < deadline { Thread.sleep(forTimeInterval: 0.01) }
        let expired = child.isRunning
        if expired {
            child.terminate()
            let grace = ProcessInfo.processInfo.systemUptime + 0.5
            while child.isRunning && ProcessInfo.processInfo.systemUptime < grace { Thread.sleep(forTimeInterval: 0.01) }
            if child.isRunning { kill(child.processIdentifier, SIGKILL) }
            let killGrace = ProcessInfo.processInfo.systemUptime + 0.5
            while child.isRunning && ProcessInfo.processInfo.systemUptime < killGrace { Thread.sleep(forTimeInterval: 0.01) }
        }
        let settled = !child.isRunning
        return .init(exitCode: settled ? child.terminationStatus : -1, timedOut: expired, settled: settled)
    }
}
