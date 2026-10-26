import Foundation
import Darwin

public enum ConnectorIPC {
    public static let socketURL = Paths.root.appendingPathComponent("connector.sock")
    public static let commands: Set<String> = ["status", "block", "check"]
    static func privateDirectory(create: Bool = false) throws {
        guard Paths.root.resolvingSymlinksInPath().path == Paths.root.standardizedFileURL.path else {
            throw LauncherError.message("连接器目录不能使用符号链接。")
        }
        if create && !FileManager.default.fileExists(atPath: Paths.root.path) {
            try FileManager.default.createDirectory(at: Paths.root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        var info = stat()
        guard lstat(Paths.root.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw LauncherError.message("连接器私有目录权限不正确。") }
        // Canonical ancestors must not redirect the local management endpoint.
        guard Paths.root.resolvingSymlinksInPath().path == Paths.root.standardizedFileURL.path else {
            throw LauncherError.message("连接器目录不能使用符号链接。")
        }
    }
    private static func address() throws -> sockaddr_un {
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(socketURL.path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else { throw LauncherError.message("本机控制路径过长。") }
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size); return addr
    }
    private static func verifyPeer(_ fd: Int32) throws {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0, uid == geteuid() else { throw LauncherError.message("控制接口身份不匹配。") }
    }
    private static func exchange(_ data: Data, permit: RecoveryMutationPermit? = nil) throws -> Data {
        guard data.count <= 8192 else { throw LauncherError.message("控制请求超过上限。") }
        try privateDirectory()
        let deadline = connectorTime() + 5
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw LauncherError.message("无法创建控制连接。") }
        defer { close(fd) }; try ConnectorSocket.prepare(fd)
        var addr = try address()
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if result != 0 {
            guard errno == EINPROGRESS || errno == EINTR else { throw LauncherError.message("连接器守卫未运行。") }
            try ConnectorSocket.ready(fd, events: Int16(POLLOUT), deadline: deadline)
            var error: Int32 = 0, size = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else {
                throw LauncherError.message("连接器守卫未运行。")
            }
        }
        try verifyPeer(fd)
        if let permit {
            try ConnectorSocket.ready(fd, events: Int16(POLLOUT), deadline: deadline)
            try permit.write(fd, data: data + Data([10]), deadline: deadline)
        } else {
            try ConnectorSocket.write(fd, data + Data([10]), limit: 8192, deadline: deadline)
        }
        return try ConnectorSocket.read(fd, limit: 131072, deadline: deadline)
    }
    public static func request(_ command: String) throws -> ConnectorSnapshot {
        guard commands.contains(command) else { throw LauncherError.message("不支持的连接器操作。") }
        return try JSONDecoder().decode(ConnectorSnapshot.self, from: exchange(Data(command.utf8)))
    }
    public static func request(_ request: ConnectorControlRequest) throws -> ConnectorControlReply {
        guard request.version == 1, request.binding.valid else { throw LauncherError.message("恢复请求身份无效。") }
        let response = try JSONDecoder().decode(ConnectorControlReply.self, from: exchange(JSONEncoder().encode(request)))
        guard response.version == 1, response.commandID == request.commandID,
              response.transactionID == request.binding.id else { throw LauncherError.message("恢复响应身份不匹配，结果未知。") }
        return response
    }
    public static func request(_ request: ConnectorHoldRequest, permit: RecoveryMutationPermit? = nil) throws -> ConnectorHoldReply {
        guard request.valid else { throw LauncherError.message("恢复屏障请求身份无效。") }
        guard permit == nil || permit?.command == request else { throw RecoveryMutationPermit.failure }
        let response = try JSONDecoder().decode(ConnectorHoldReply.self, from: exchange(JSONEncoder().encode(request), permit: permit))
        guard response.version == 2, response.commandID == request.commandID, response.holdID == request.hold.id else {
            throw LauncherError.message("恢复屏障响应身份不匹配，结果未知。")
        }
        return response
    }
    public static func loadRequest(from path: String) throws -> ConnectorControlRequest {
        try loadRequest(from: path, as: ConnectorControlRequest.self)
    }
    public static func loadRequest<T: Decodable>(from path: String, as type: T.Type) throws -> T {
        let fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw LauncherError.message("无法读取恢复请求文件。") }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, (1...8192).contains(info.st_size) else {
            throw LauncherError.message("恢复请求须为不超过 8 KiB 的普通 JSON 文件。")
        }
        var bytes = [UInt8](repeating: 0, count: 8193)
        let count = Darwin.read(fd, &bytes, bytes.count)
        guard count == info.st_size else { throw LauncherError.message("恢复请求文件变化或读取不完整。") }
        return try JSONDecoder().decode(type, from: Data(bytes.prefix(count)))
    }
    /// Used by the listener and socket-pair tests. No file or network configuration changes.
    static func servePeer(_ fd: Int32, acceptedAt: Double, budget: Double = 4,
                          legacy: (String) -> ConnectorSnapshot,
                          coordinated: (ConnectorControlRequest) -> ConnectorControlReply,
                          held: ((ConnectorHoldRequest) -> ConnectorHoldReply)? = nil) throws {
        let deadline = acceptedAt + budget
        try ConnectorSocket.prepare(fd); try verifyPeer(fd)
        let data = try ConnectorSocket.read(fd, limit: 8192, deadline: deadline)
        guard connectorTime() < deadline else { throw LauncherError.message("控制请求已超时。") }
        let response: Data
        if let command = String(data: data, encoding: .utf8), commands.contains(command) {
            response = try JSONEncoder().encode(legacy(command))
        } else if let request = try? JSONDecoder().decode(ConnectorHoldRequest.self, from: data), let held {
            response = try JSONEncoder().encode(held(request))
        } else {
            let request = try JSONDecoder().decode(ConnectorControlRequest.self, from: data)
            response = try JSONEncoder().encode(coordinated(request))
        }
        try ConnectorSocket.write(fd, response + Data([10]), limit: 131072, deadline: deadline)
    }
    /// Caller must hold the lifetime lock before serving or archiving a stale socket.
    static func serve(legacy: @escaping (String) -> ConnectorSnapshot,
                      coordinated: @escaping (ConnectorControlRequest) -> ConnectorControlReply,
                      held: ((ConnectorHoldRequest) -> ConnectorHoldReply)? = nil) throws {
        try privateDirectory()
        var info = stat()
        if lstat(socketURL.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFSOCK, info.st_uid == geteuid(), info.st_mode & 0o077 == 0 else { throw LauncherError.message("控制路径存在其他文件，已保留。") }
            let probe = socket(AF_UNIX, SOCK_STREAM, 0)
            guard probe >= 0 else { throw LauncherError.message("无法检查旧控制接口。") }
            do { try ConnectorSocket.prepare(probe) } catch { close(probe); throw error }
            var candidate = try address()
            let result = withUnsafePointer(to: &candidate) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(probe, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
            let failure = errno; close(probe)
            guard result != 0, failure == ECONNREFUSED else { throw LauncherError.message("控制接口仍有监听或状态未知，已保留。") }
            try FileManager.default.moveItem(at: socketURL, to: Paths.root.appendingPathComponent("connector-stale-\(UUID().uuidString).sock"))
        }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { throw LauncherError.message("控制接口创建失败。") }
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC); var addr = try address()
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard ok == 0, chmod(socketURL.path, 0o600) == 0, listen(fd, 8) == 0 else { close(fd); throw LauncherError.message("控制接口监听失败。") }
        let slots = DispatchSemaphore(value: 8)
        DispatchQueue.global(qos: .utility).async {
            while true {
                let peer = accept(fd, nil, nil), acceptedAt = connectorTime()
                if peer < 0 { if errno == EINTR { continue }; close(fd); return }
                guard slots.wait(timeout: .now()) == .success else { close(peer); continue }
                DispatchQueue.global(qos: .utility).async {
                    defer { close(peer); slots.signal() }
                    do { try servePeer(peer, acceptedAt: acceptedAt, legacy: legacy, coordinated: coordinated, held: held) }
                    catch { /* Never echo request bytes or infer that a timed-out mutation did not run. */ }
                }
            }
        }
    }
}


public enum ConnectorServiceControl {
    public static func perform(_ action: String, script: URL) -> Bool {
        guard ["start", "stop"].contains(action), script.lastPathComponent == "connector_service.py" else { return false }
        return ReadCommand.run("/usr/bin/python3", ["-E", "-s", "-B", script.path, action], timeout: 30).code == 0
    }
}
