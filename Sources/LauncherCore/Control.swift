import Foundation
import Darwin

public enum Control {
    private static func address() throws -> sockaddr_un {
        var address = sockaddr_un(); address.sun_family = sa_family_t(AF_UNIX)
        let path = Array(Paths.socket.utf8) + [0]
        guard path.count <= MemoryLayout.size(ofValue:address.sun_path) else { throw LauncherError.message("控制套接字路径过长") }
        withUnsafeMutableBytes(of:&address.sun_path) { raw in raw.copyBytes(from:path) }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return address
    }
    private static func timeout(_ fd: Int32) {
        var limit = timeval(tv_sec:2,tv_usec:0)
        setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&limit,socklen_t(MemoryLayout.size(ofValue:limit)))
        setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&limit,socklen_t(MemoryLayout.size(ofValue:limit)))
        var yes: Int32 = 1; setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&yes,socklen_t(MemoryLayout.size(ofValue:yes)))
        _ = fcntl(fd,F_SETFD,FD_CLOEXEC)
    }
    public static func request(_ command: String) throws -> Snapshot {
        let fd = socket(AF_UNIX,SOCK_STREAM,0); guard fd >= 0 else { throw LauncherError.message("守卫故障") }; defer { close(fd) }
        timeout(fd); var addr = try address()
        let result = withUnsafePointer(to:&addr) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { connect(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard result == 0 else { throw LauncherError.message("守卫未运行，请重新安装或启动守卫") }
        try write(fd, data:Data((command+"\n").utf8))
        let data = try readLine(fd)
        return try JSONDecoder().decode(Snapshot.self,from:data)
    }
    public static func serve(_ handler: @escaping (String) -> Snapshot) throws {
        let fd = socket(AF_UNIX,SOCK_STREAM,0); guard fd >= 0 else { throw LauncherError.message("控制端口创建失败") }
        // Caller owns an exclusive flock before replacing a stale socket.
        unlink(Paths.socket)
        timeout(fd); var addr = try address()
        let result = withUnsafePointer(to:&addr) { $0.withMemoryRebound(to:sockaddr.self,capacity:1) { bind(fd,$0,socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard result == 0, chmod(Paths.socket,0o600) == 0, listen(fd,8) == 0 else { close(fd); throw LauncherError.message("控制端口占用") }
        DispatchQueue.global().async {
            while true {
                let client = accept(fd,nil,nil); if client < 0 { continue }; timeout(client)
                do {
                    let request = try readLine(client)
                    guard request.count <= 64, let command = String(data:request,encoding:.utf8) else { throw LauncherError.message("无效请求") }
                    let reply = handler(command)
                    try write(client,data:try JSONEncoder().encode(reply)+Data([10]))
                } catch { /* Do not echo request data. */ }
                close(client)
            }
        }
    }
    private static func readLine(_ fd: Int32) throws -> Data {
        var data = Data(); var bytes = [UInt8](repeating:0,count:2048)
        while data.count < 65536 {
            let count = recv(fd,&bytes,bytes.count,0)
            guard count > 0 else { throw LauncherError.message("守卫响应超时") }
            data.append(contentsOf:bytes.prefix(count))
            if let newline = data.firstIndex(of:10) { return Data(data[..<newline]) }
        }
        throw LauncherError.message("控制响应过长")
    }
    private static func write(_ fd: Int32, data: Data) throws {
        try data.withUnsafeBytes { raw in
            var sent = 0
            while sent < raw.count {
                let count = send(fd,raw.baseAddress!.advanced(by:sent),raw.count-sent,0)
                guard count > 0 else { throw LauncherError.message("控制连接已断开") }; sent += count
            }
        }
    }
}

public enum Subprocess {
    public static func capture(_ executable: String, _ arguments: [String], timeout: TimeInterval = 10) throws -> (Int32, String) {
        let process = Process(); process.executableURL = URL(fileURLWithPath:executable); process.arguments = arguments
        let output = Pipe(); process.standardOutput = output; process.standardError = FileHandle.nullDevice; process.standardInput = FileHandle.nullDevice
        try process.run()
        let killer = DispatchWorkItem { if process.isRunning { kill(process.processIdentifier,SIGKILL) } }
        DispatchQueue.global().asyncAfter(deadline:.now()+timeout,execute:killer)
        let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit(); killer.cancel()
        return (process.terminationStatus,String(data:data,encoding:.utf8) ?? "")
    }
}
public struct Session: Codable { public var pid: Int32; public var started: String; public var kind: String }
public enum Sessions {
    public static func startTime(_ pid: Int32) -> String { (try? Subprocess.capture("/bin/ps",["-p",String(pid),"-o","lstart="],timeout:1).1.trimmingCharacters(in:.whitespacesAndNewlines)) ?? "" }
    public static func register(kind: String) throws {
        let session = Session(pid:getpid(),started:startTime(getpid()),kind:kind)
        guard !session.started.isEmpty else { throw LauncherError.message("会话身份检查失败") }
        try saveJSON(session,to:Paths.root.appendingPathComponent("sessions/\(getpid()).json"))
    }
    public static func active() -> [Session] {
        let files = (try? FileManager.default.contentsOfDirectory(at:Paths.root.appendingPathComponent("sessions"),includingPropertiesForKeys:nil)) ?? []
        return files.compactMap { file in
            guard let entry = try? loadJSON(Session.self,from:file), kill(entry.pid,0) == 0, startTime(entry.pid) == entry.started else { try? FileManager.default.removeItem(at:file); return nil }
            return entry
        }
    }
    public static func unmanaged(known: [Session], excludingOfficialDesktop: Bool = false) -> Bool {
        guard let result = try? Subprocess.capture("/bin/ps",["-axo","pid=,ppid=,comm="],timeout:2), result.0 == 0 else { return true }
        var parents: [Int32:Int32] = [:]; var targets: [Int32] = []
        for line in result.1.split(separator:"\n") {
            let fields = line.split(maxSplits:2,whereSeparator:{ $0.isWhitespace })
            guard fields.count == 3, let pid = Int32(fields[0]), let parent = Int32(fields[1]) else { continue }
            parents[pid] = parent
            let command = String(fields[2])
            if excludingOfficialDesktop && command.hasPrefix("/Applications/Claude.app/") { continue }
            if command.hasPrefix("/Applications/Claude.app/") || command.contains("/.local/share/claude/versions/") || command == "claude" { targets.append(pid) }
        }
        let registered = Set(known.map(\.pid))
        return targets.contains { pid in
            var cursor = pid; var visited: Set<Int32> = []
            while cursor > 1, visited.insert(cursor).inserted { if registered.contains(cursor) { return false }; cursor = parents[cursor] ?? 0 }
            return true
        }
    }
}
