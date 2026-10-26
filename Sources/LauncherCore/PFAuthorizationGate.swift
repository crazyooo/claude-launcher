import Foundation
import Darwin

struct PFAuthorizationStart: Codable {
    let version: Int
    let execution: PFAuthorizationExecutionIdentity
    let request: PFRecoveryRequest
    init(execution: PFAuthorizationExecutionIdentity, request: PFRecoveryRequest) {
        version = 1; self.execution = execution; self.request = request
    }
    private enum CodingKeys: String, CodingKey { case version, execution, request }
    init(from decoder: Decoder) throws {
        try ConnectorSchema.keys(decoder, ["version", "execution", "request"])
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        version = try fields.decode(Int.self, forKey: .version)
        execution = try fields.decode(PFAuthorizationExecutionIdentity.self, forKey: .execution)
        request = try fields.decode(PFRecoveryRequest.self, forKey: .request)
        guard version == 1 else { throw ConnectorSchema.invalid(decoder) }
    }
}

/// The only production gate target is the existing fixed administrator script.
public enum PFAuthorizationGate {
    static let maximumInput = 4096
    static let failure = LauncherError.message("授权启动帧无效或超时；未发起系统授权。")
    static func ready(_ id: UUID) -> Data { Data("PF_AUTH_READY_V1 \(id.uuidString)\n".utf8) }

    public static func run(executionID: UUID) throws -> Never {
        let own = try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: executionID)
        let deadline = connectorTime() + 120
        guard fcntl(STDOUT_FILENO, F_SETNOSIGPIPE, 1) == 0 else { throw failure }
        let frame = ready(executionID)
        guard frame.withUnsafeBytes({ Darwin.write(STDOUT_FILENO, $0.baseAddress, $0.count) }) == frame.count else { throw failure }
        let start = try readStart(fd: STDIN_FILENO, expected: own, deadline: deadline)
        guard try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: executionID) == own,
              connectorTime() < deadline else { throw failure }
        let null = open("/dev/null", O_RDONLY | O_CLOEXEC)
        guard null >= 0 else { throw failure }
        let replaced = dup2(null, STDIN_FILENO); if null != STDIN_FILENO { close(null) }
        guard replaced == STDIN_FILENO else { throw failure }
        // No spawned osascript child: the saved kernel identity remains the authorization process.
        let arguments = ["/usr/bin/osascript", "-e", PFAuthorizationTransport.script(for: start.request)]
        let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"]
        let argv = arguments.map { strdup($0) } + [nil]
        let env = environment.map { strdup($0) } + [nil]
        defer { argv.compactMap { $0 }.forEach { free($0) }; env.compactMap { $0 }.forEach { free($0) } }
        let descriptorLimit = sysconf(_SC_OPEN_MAX)
        guard descriptorLimit > 3 else { throw failure }
        for descriptor in 3..<Int32(min(descriptorLimit, 65536)) { close(descriptor) }
        guard connectorTime() < deadline else { throw failure }
        execve("/usr/bin/osascript", argv, env)
        throw LauncherError.message("授权进程替换失败；未使用备用启动方式。")
    }

    /// Requires EOF after a single JSON value; a complete prefix never authorizes execution.
    static func readStart(fd: Int32, expected: PFAuthorizationExecutionIdentity, deadline: Double) throws -> PFAuthorizationStart {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw failure }
        var data = Data(), bytes = [UInt8](repeating: 0, count: maximumInput + 1)
        while connectorTime() < deadline {
            let count = Darwin.read(fd, &bytes, bytes.count)
            if count > 0 {
                guard data.count + count <= maximumInput else { throw failure }
                data.append(contentsOf: bytes.prefix(count))
            } else if count == 0 {
                guard !data.isEmpty, let frame = try? JSONDecoder().decode(PFAuthorizationStart.self, from: data),
                      frame.execution == expected, connectorTime() < deadline else { throw failure }
                return frame
            } else if errno != EAGAIN && errno != EINTR { throw failure }
            Thread.sleep(forTimeInterval: 0.005)
        }
        throw failure
    }
}
