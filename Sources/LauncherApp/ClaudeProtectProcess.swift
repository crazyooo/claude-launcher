import Foundation
import Darwin

struct ProtectCommand {
    let executable: String
    let arguments: [String]
    let timeout: TimeInterval
}

struct ProtectCommandResult {
    var exitCode: Int32 = 0
    var output = ""
    var error = ""
    var timedOut = false
    var succeeded: Bool { !timedOut && exitCode == 0 }
    var json: [String: Any]? {
        guard !timedOut, let data = output.data(using: .utf8) else { return nil }
        return (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
    }
}

enum ProtectProcess {
    static func run(_ command: ProtectCommand) async -> ProtectCommandResult {
        await Task.detached { execute(command) }.value
    }

    /// Drain both pipes while the child runs. Neither process exit nor a pipe's
    /// EOF is allowed to hold the UI forever (descendants can inherit the pipe).
    private static func execute(_ command: ProtectCommand) -> ProtectCommandResult {
        let process = Process(), stdout = Pipe(), stderr = Pipe()
        process.executableURL = URL(fileURLWithPath: command.executable)
        process.arguments = command.arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": NSHomeDirectory()]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = stdout
        process.standardError = stderr
        let outFD = stdout.fileHandleForReading.fileDescriptor
        let errFD = stderr.fileHandleForReading.fileDescriptor
        guard fcntl(outFD, F_SETFL, O_NONBLOCK) != -1,
              fcntl(errFD, F_SETFL, O_NONBLOCK) != -1 else {
            return .init(exitCode: -1, error: "无法创建有界命令输出。")
        }
        do { try process.run() }
        catch { return .init(exitCode: -1, error: error.localizedDescription) }
        var out = Data(), err = Data(), oversized = false
        let limit = 262_144
        func drain(_ fd: Int32, into data: inout Data) {
            var buffer = [UInt8](repeating: 0, count: 8192)
            // Bound each drain pass too, so a noisy child cannot starve the deadline.
            for _ in 0..<32 {
                let count = Darwin.read(fd, &buffer, buffer.count)
                if count <= 0 { return }
                let remaining = max(0, limit - data.count)
                data.append(contentsOf: buffer.prefix(min(count, remaining)))
                if count > remaining { oversized = true; return }
            }
        }
        let start = ProcessInfo.processInfo.systemUptime
        var timedOut = false
        while true {
            drain(outFD, into: &out); drain(errFD, into: &err)
            if !process.isRunning { break }
            timedOut = ProcessInfo.processInfo.systemUptime - start >= command.timeout
            if timedOut || oversized {
                process.terminate()
                let grace = ProcessInfo.processInfo.systemUptime + 0.3
                while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {
                    Thread.sleep(forTimeInterval: 0.01)
                }
                if process.isRunning { _ = Darwin.kill(process.processIdentifier, SIGKILL) }
                break
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
        drain(outFD, into: &out); drain(errFD, into: &err)
        return .init(exitCode: process.isRunning || oversized ? -1 : process.terminationStatus,
                     output: String(decoding: out, as: UTF8.self),
                     error: oversized ? "命令输出超出限制。" : String(decoding: err, as: UTF8.self),
                     timedOut: timedOut)
    }
}

struct ClaudeProtectEffects {
    var run: (ProtectCommand) async -> ProtectCommandResult = { await ProtectProcess.run($0) }
}
