import Foundation
import Network

private let ioQueue = DispatchQueue(label: "launcher.gateway.io", attributes: .concurrent)
private struct ProxyFailure: Error {}
private final class ReadyResult: @unchecked Sendable {
    private let lock = NSLock()
    private var completed = false
    let continuation: CheckedContinuation<Void,Error>
    init(_ continuation: CheckedContinuation<Void,Error>) { self.continuation = continuation }
    func finish(_ result: Result<Void,Error>) {
        lock.lock(); defer { lock.unlock() }
        guard !completed else { return }; completed = true; continuation.resume(with:result)
    }
}

/// A single reader owns the buffered bytes, including handshake read-ahead.
final class Channel {
    let connection: NWConnection
    private var buffer = Data()
    init(_ connection: NWConnection) { self.connection = connection }
    func start(failOnWaiting: Bool = false) async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            let result = ReadyResult(continuation)
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready: result.finish(.success(()))
                case .failed(let error): result.finish(.failure(error))
                case .waiting(let error) where failOnWaiting: result.finish(.failure(error))
                case .cancelled: result.finish(.failure(ProxyFailure()))
                default: break
                }
            }
            connection.start(queue: ioQueue)
        }
    }
    func receive() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 65536) { data, _, complete, error in
                if let error { continuation.resume(throwing: error) }
                else { continuation.resume(returning: data ?? Data()) }
            }
        }
    }
    func exact(_ count: Int) async throws -> Data {
        while buffer.count < count { let data = try await receive(); guard !data.isEmpty else { throw ProxyFailure() }; buffer.append(data) }
        let result = buffer.prefix(count); buffer.removeFirst(count); return Data(result)
    }
    func headers() async throws -> Data {
        let delimiter = Data("\r\n\r\n".utf8)
        while true {
            if let range = buffer.range(of: delimiter) {
                guard range.upperBound <= 32768 else { throw ProxyFailure() }
                let result = buffer.prefix(upTo: range.upperBound); buffer.removeSubrange(..<range.upperBound); return Data(result)
            }
            guard buffer.count < 32768 else { throw ProxyFailure() }
            let data = try await receive(); guard !data.isEmpty else { throw ProxyFailure() }; buffer.append(data)
        }
    }
    func send(_ data: Data) async throws {
        guard !data.isEmpty else { return }
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void, Error>) in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error { continuation.resume(throwing: error) } else { continuation.resume() }
            })
        }
    }
    func finishSending() async throws {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Void,Error>) in
            connection.send(content:nil,contentContext:.finalMessage,isComplete:true,completion:.contentProcessed { error in
                if let error { continuation.resume(throwing:error) } else { continuation.resume() }
            })
        }
    }
    func pump(to peer: Channel, transferred: @escaping (Int) -> Void = { _ in }) async throws {
        if !buffer.isEmpty { let bytes = buffer; buffer.removeAll(); try await peer.send(bytes); transferred(bytes.count) }
        while true {
            let data = try await receive()
            if data.isEmpty { try await peer.finishSending(); return }
            try await peer.send(data); transferred(data.count)
        }
    }
}
public struct Target: Equatable {
    public let host: String
    public let port: UInt16
    /// Hostnames are resolved by the upstream; this rejects only explicit IPv6.
    var permitsProxyForwarding: Bool { !host.contains(":") && !host.contains("[") && !host.contains("]") }
    public var authority: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }
    public static func parse(_ input: String) throws -> Target {
        guard !input.contains("%"), !input.contains(where: { $0.isWhitespace || $0 == "@" || $0 == "/" || $0 == "\\" }),
              let url = URLComponents(string: "http://" + input), let host = url.host,
              !host.isEmpty, let number = url.port, (1...65535).contains(number), url.query == nil, url.fragment == nil,
              url.path.isEmpty else { throw ProxyFailure() }
        let decoded = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard normalizedIP(decoded) != nil || (decoded.count <= 253 && decoded.split(separator:".",omittingEmptySubsequences:false).allSatisfy { label in
            !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-" && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }) else { throw ProxyFailure() }
        return Target(host: decoded, port: UInt16(number))
    }
}
public struct ProxyRequest {
    public let target: Target
    public let connect: Bool
    public let forwarded: Data
    public static func parse(_ bytes: Data) throws -> ProxyRequest {
        guard let text = String(data: bytes, encoding: .utf8), text.hasSuffix("\r\n\r\n") else { throw ProxyFailure() }
        let lines = text.components(separatedBy: "\r\n")
        let first = lines[0].split(separator: " ", omittingEmptySubsequences: false)
        guard first.count == 3, ["HTTP/1.0", "HTTP/1.1"].contains(String(first[2])),
              first[0].allSatisfy({ $0.isASCII && $0.isUppercase }) else { throw ProxyFailure() }
        var fields: [(String,String)] = []
        for line in lines.dropFirst() where !line.isEmpty {
            guard let colon = line.firstIndex(of: ":"), !line.hasPrefix(" "), !line.hasPrefix("\t") else { throw ProxyFailure() }
            let name = String(line[..<colon]).lowercased()
            guard !name.isEmpty, name.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }) else { throw ProxyFailure() }
            let value = String(line[line.index(after:colon)...]).trimmingCharacters(in:.whitespaces)
            guard !value.contains(where: { $0.asciiValue.map { $0 < 32 && $0 != 9 } ?? false }) else { throw ProxyFailure() }
            fields.append((name,value))
        }
        if first[0] == "CONNECT" {
            let target = try Target.parse(String(first[1]))
            guard target.permitsProxyForwarding else { throw ProxyFailure() }
            return ProxyRequest(target: target, connect: true, forwarded: Data())
        }
        guard let url = URLComponents(string:String(first[1])), url.scheme == "http", let host = url.host,
              url.user == nil, url.password == nil, url.fragment == nil else { throw ProxyFailure() }
        let target = try Target.parse("\(host):\(url.port ?? 80)")
        guard target.permitsProxyForwarding else { throw ProxyFailure() }
        // Reject ambiguous framing and proxy credentials. One origin per TCP stream.
        let lengths = fields.filter { $0.0 == "content-length" }
        let encodings = fields.filter { $0.0 == "transfer-encoding" }
        guard lengths.count <= 1, encodings.count <= 1, lengths.isEmpty || encodings.isEmpty,
              lengths.allSatisfy({ UInt64($0.1) != nil }), encodings.allSatisfy({ $0.1.lowercased() == "chunked" }) else { throw ProxyFailure() }
        let connectionFields = Set(fields.filter { $0.0 == "connection" }.flatMap { $0.1.lowercased().split(separator:",").map { $0.trimmingCharacters(in:.whitespaces) } })
        guard connectionFields.isDisjoint(with:["host","content-length","transfer-encoding"]) else { throw ProxyFailure() }
        let remove: Set<String> = ["host", "connection", "proxy-connection", "proxy-authorization", "proxy-authenticate", "keep-alive", "upgrade"]
        var result = "\(first[0]) \(url.percentEncodedPath.isEmpty ? "/" : url.percentEncodedPath)\(url.percentEncodedQuery.map { "?" + $0 } ?? "") HTTP/1.1\r\nHost: \(target.authority)\r\nConnection: close\r\n"
        for (name,value) in fields where !remove.contains(name) && !connectionFields.contains(name) { result += "\(name): \(value)\r\n" }
        result += "\r\n"
        return ProxyRequest(target:target,connect:false,forwarded:Data(result.utf8))
    }
}
final class Tunnel {
    let client: Channel
    private let lock = NSLock()
    private var upstream: Channel?
    private var cancelled = false
    init(_ connection: NWConnection) { client = Channel(connection) }
    func attach(_ channel: Channel) {
        lock.lock(); upstream = channel; let shouldCancel = cancelled; lock.unlock()
        if shouldCancel { channel.connection.cancel() }
    }
    func cancel() { lock.lock(); cancelled = true; let other = upstream; lock.unlock(); client.connection.cancel(); other?.connection.cancel() }
}
/// Mutable gateway state is confined to queue; config and credentials are immutable.
public final class Gateway: @unchecked Sendable {
    private let config: Configuration
    private let credential: Credential?
    private let queue = DispatchQueue(label: "launcher.gateway.state")
    private var listeners: [NWListener] = []
    private var active: [UUID:Tunnel] = [:]
    private var allowed = false
    private var heartbeat = ProcessInfo.processInfo.systemUptime
    private var timer: DispatchSourceTimer?
    private var readyCount = 0
    public init(config: Configuration, credential: Credential?) { self.config = config; self.credential = credential }
    public func run() throws {
        try config.validate()
        for (port,probe) in [(config.gatewayPort,false),(config.probePort,true)] {
            let parameters = NWParameters.tcp
            parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port:NWEndpoint.Port(rawValue:UInt16(port))!)
            let listener = try NWListener(using: parameters)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready: self.readyCount += 1; if self.readyCount == 2 { print("READY"); fflush(stdout) }
                case .failed: self.block(); print("LISTENER_FAILED"); fflush(stdout); exit(70)
                default: break
                }
            }
            listener.newConnectionHandler = { connection in
                guard self.active.count < 256, probe || self.allowed else { connection.cancel(); return }
                let id = UUID(); let tunnel = Tunnel(connection); self.active[id] = tunnel
                Task {
                    await self.serve(tunnel, probe:probe)
                    tunnel.cancel(); self.queue.async { self.active.removeValue(forKey:id) }
                }
            }
            listeners.append(listener); listener.start(queue:queue)
        }
        let timer = DispatchSource.makeTimerSource(queue:queue)
        timer.schedule(deadline:.now(),repeating:.milliseconds(100)); timer.setEventHandler {
            if ProcessInfo.processInfo.systemUptime - self.heartbeat >= 3 { self.block() }
        }; self.timer = timer; timer.resume()
        DispatchQueue.global().async {
            while let line = readLine() {
                self.queue.async {
                    switch line {
                    case "HEARTBEAT": self.heartbeat = ProcessInfo.processInfo.systemUptime
                    case "ALLOW": if ProcessInfo.processInfo.systemUptime - self.heartbeat < 3 { self.allowed = true }
                    case "BLOCK": self.block()
                    default: self.block()
                    }
                }
            }
            self.queue.async { self.block(); exit(0) }
        }
    }
    private func block() { allowed = false; let items = Array(active.values); active.removeAll(); items.forEach { $0.cancel() } }
    private func serve(_ tunnel: Tunnel, probe: Bool) async {
        let timeout = DispatchWorkItem { tunnel.cancel() }
        ioQueue.asyncAfter(deadline:.now()+10,execute:timeout)
        do {
            try await tunnel.client.start()
            let request = try ProxyRequest.parse(await tunnel.client.headers())
            if probe && (!request.connect || request.target.host != "api.ipify.org" || request.target.port != 443) { throw ProxyFailure() }
            let upstream = Channel(NWConnection(host:NWEndpoint.Host(config.host),port:NWEndpoint.Port(rawValue:UInt16(config.port))!,using:.tcp))
            tunnel.attach(upstream); try await upstream.start()
            if config.protocolName == "http" { try await httpConnect(upstream, target:request.target) }
            else { try await socksConnect(upstream,target:request.target) }
            if request.connect { try await tunnel.client.send(Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) }
            else { try await upstream.send(request.forwarded) }
            timeout.cancel()
            // Each direction applies NWConnection backpressure; no stream accumulation.
            await withTaskGroup(of:Void.self) { group in
                group.addTask { do { try await tunnel.client.pump(to:upstream) } catch { tunnel.cancel() } }
                group.addTask { do { try await upstream.pump(to:tunnel.client) } catch { tunnel.cancel() } }
                await group.waitForAll()
            }
        } catch {
            // Only fixed response text; never log destinations or authentication material.
            try? await tunnel.client.send(Data("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".utf8))
        }
        timeout.cancel()
    }
    private func httpConnect(_ channel: Channel, target: Target) async throws {
        var header = "CONNECT \(target.authority) HTTP/1.1\r\nHost: \(target.authority)\r\n"
        if let credential { header += "Proxy-Authorization: Basic \(Data("\(credential.username):\(credential.password)".utf8).base64EncodedString())\r\n" }
        try await channel.send(Data((header+"\r\n").utf8))
        let response = try await channel.headers()
        guard let text = String(data:response,encoding:.utf8), let first = text.components(separatedBy:"\r\n").first else { throw ProxyFailure() }
        let parts = first.split(separator:" ")
        guard parts.count >= 2, ["HTTP/1.1","HTTP/1.0"].contains(parts[0]), let code = Int(parts[1]), (200...299).contains(code) else { throw ProxyFailure() }
    }
    private func socksConnect(_ channel: Channel, target: Target) async throws {
        try await channel.send(Data([5,1,credential == nil ? 0 : 2]))
        let method = [UInt8](try await channel.exact(2))
        guard method == [5, credential == nil ? 0 : 2] else { throw ProxyFailure() }
        if let credential {
            let user = Array(credential.username.utf8), password = Array(credential.password.utf8)
            guard !user.isEmpty, user.count <= 255, password.count <= 255 else { throw ProxyFailure() }
            try await channel.send(Data([1,UInt8(user.count)] + user + [UInt8(password.count)] + password))
            guard [UInt8](try await channel.exact(2)) == [1,0] else { throw ProxyFailure() }
        }
        let name = Array(target.host.utf8); guard !name.isEmpty, name.count <= 255 else { throw ProxyFailure() }
        // ATYP domain keeps resolution on the configured upstream path.
        try await channel.send(Data([5,1,0,3,UInt8(name.count)] + name + [UInt8(target.port >> 8),UInt8(target.port & 255)]))
        let reply = [UInt8](try await channel.exact(4)); guard reply[0] == 5, reply[1] == 0, reply[2] == 0 else { throw ProxyFailure() }
        switch reply[3] {
        case 1: _ = try await channel.exact(6)
        case 4: _ = try await channel.exact(18)
        case 3: let n = try await channel.exact(1).first!; _ = try await channel.exact(Int(n)+2)
        default: throw ProxyFailure()
        }
    }
}
