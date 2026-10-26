import Foundation
import Darwin

/// Fixed loopback GETs. No DNS, proxy inheritance, redirects, cookies, or mutation endpoints.
enum RouterSystemControllerHTTP {
    enum Endpoint: String {
        case version = "/version", configs = "/configs", connections = "/connections"
        var maximumResponse: Int { self == .connections ? RouterConnectionProjection.bodyLimit + 16_388 : 65_536 }
    }
    struct Response { let status: Int; let body: Data }

    static func connections(port: UInt16, secret: String, until deadline: TimeInterval) throws -> Data {
        guard port > 1024 else { throw RouterConnectionFailure.invalidResponse }
        return try authenticatedConnections(secret: secret) { endpoint, token in
            try get(endpoint, secret: token, until: deadline, port: port)
        }
    }

    /// Shared authentication sequence, with local IO supplied separately for fault tests.
    static func authenticatedConnections(secret: String, read: (Endpoint, String) throws -> Response) throws -> Data {
        guard RouterSystemProvider.validDigest(secret) else { throw RouterConnectionFailure.invalidResponse }
        var wrong = Array(secret.utf8); wrong[0] = wrong[0] == 48 ? 49 : 48
        guard try read(.version, String(decoding: wrong, as: UTF8.self)).status == 401 else {
            throw RouterConnectionFailure.identityChanged
        }
        let version = try read(.version, secret)
        guard version.status == 200 else { throw RouterConnectionFailure.controllerUnavailable }
        try RouterSystemControllerDeclaration.version(version.body)
        let response = try read(.connections, secret)
        guard response.status == 200 else { throw RouterConnectionFailure.controllerUnavailable }
        return response.body
    }

    static func declaration(secret: String, until deadline: TimeInterval) throws -> RouterSystemControllerDeclaration {
        guard RouterSystemProvider.validDigest(secret) else { throw RouterSystemError.invalidCredentials }
        var wrong = Array(secret.utf8); wrong[0] = wrong[0] == 48 ? 49 : 48
        let denied = try get(.version, secret: String(decoding: wrong, as: UTF8.self), until: deadline)
        guard denied.status == 401 else { throw RouterSystemError.ownershipUnknown }
        let version = try get(.version, secret: secret, until: deadline)
        guard version.status == 200 else { throw RouterSystemError.ownershipUnknown }
        try RouterSystemControllerDeclaration.version(version.body)
        let configs = try get(.configs, secret: secret, until: deadline)
        guard configs.status == 200 else { throw RouterSystemError.ownershipUnknown }
        let declaration = try RouterSystemControllerDeclaration.parse(configs.body)
        try fresh(deadline)
        return declaration
    }

    private static func get(_ endpoint: Endpoint, secret: String, until deadline: TimeInterval,
                            port: UInt16 = RouterSystemCompiler.controllerPort) throws -> Response {
        try fresh(deadline)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
        defer { close(fd) }
        try configure(fd)
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        if result != 0 {
            guard errno == EINPROGRESS else { throw RouterSystemError.operationUnsettled }
            try wait(fd, events: Int16(POLLOUT), deadline: deadline)
            var error: Int32 = 0, length = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0,
                  length == socklen_t(MemoryLayout<Int32>.size), error == 0 else { throw RouterSystemError.operationUnsettled }
        }
        return try exchange(fd: fd, endpoint: endpoint, secret: secret, deadline: deadline, port: port)
    }

    private static func configure(_ fd: Int32) throws {
        let flags = fcntl(fd, F_GETFL)
        var one: Int32 = 1
        guard flags >= 0, fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw RouterSystemError.operationUnsettled
        }
    }

    /// Exercises the real IO loop through a local socketpair, without opening a network endpoint.
    static func fixtureExchange(fd: Int32, deadline: TimeInterval, endpoint: Endpoint = .configs) throws -> Response {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        try configure(fd)
        return try exchange(fd: fd, endpoint: endpoint, secret: String(repeating: "0", count: 64), deadline: deadline)
    }
    private static func exchange(fd: Int32, endpoint: Endpoint, secret: String, deadline: TimeInterval,
                                 port: UInt16 = RouterSystemCompiler.controllerPort) throws -> Response {
        guard RouterSystemProvider.validDigest(secret) else { throw RouterSystemError.invalidCredentials }
        let request = Data(("GET \(endpoint.rawValue) HTTP/1.0\r\nHost: 127.0.0.1:\(port)\r\n" +
            "Authorization: Bearer \(secret)\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").utf8)
        var offset = 0
        while offset < request.count {
            try fresh(deadline)
            let count = request.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), request.count - offset) }
            if count > 0 { offset += count }
            else if count < 0 && errno == EINTR { continue }
            else if count < 0 && errno == EAGAIN { try wait(fd, events: Int16(POLLOUT), deadline: deadline) }
            else { throw RouterSystemError.operationUnsettled }
        }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while true {
            try fresh(deadline)
            let count = Darwin.read(fd, &buffer, buffer.count)
            if count > 0 {
                guard bytes.count + count <= endpoint.maximumResponse else {
                    if endpoint == .connections { throw RouterConnectionFailure.responseTooLarge }
                    throw RouterSystemError.configurationRejected
                }
                bytes.append(contentsOf: buffer.prefix(count))
            } else if count == 0 { break }
            else if errno == EINTR { continue }
            else if errno == EAGAIN { try wait(fd, events: Int16(POLLIN), deadline: deadline) }
            else { throw RouterSystemError.operationUnsettled }
        }
        try fresh(deadline)
        let response = try parse(bytes, endpoint: endpoint)
        try fresh(deadline)
        return response
    }
    private static func fresh(_ deadline: TimeInterval) throws {
        guard deadline.isFinite, ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.operationUnsettled }
    }
    private static func wait(_ fd: Int32, events: Int16, deadline: TimeInterval) throws {
        while true {
            try fresh(deadline)
            let milliseconds = Int32(max(1, min(1000, ceil((deadline - ProcessInfo.processInfo.systemUptime) * 1000))))
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&item, 1, milliseconds)
            try fresh(deadline)
            if result < 0 && errno == EINTR { continue }
            guard result >= 0, item.revents & Int16(POLLNVAL) == 0 else { throw RouterSystemError.operationUnsettled }
            if result == 0 { continue }
            // EOF and pending errors must be consumed by IO (or SO_ERROR during connect).
            if item.revents & (events | Int16(POLLHUP | POLLERR)) != 0 { return }
            throw RouterSystemError.operationUnsettled
        }
    }

    /// Only call for a response completed at EOF; HTTP/1.0 requests prohibit chunked framing.
    static func parse(_ bytes: Data, endpoint: Endpoint = .configs) throws -> Response {
        if endpoint == .connections, bytes.count > endpoint.maximumResponse { throw RouterConnectionFailure.responseTooLarge }
        guard bytes.count <= endpoint.maximumResponse, let split = bytes.range(of: Data([13, 10, 13, 10])), split.lowerBound <= 16_384,
              let header = String(data: bytes[..<split.lowerBound], encoding: .ascii),
              header.utf8.allSatisfy({ $0 == 9 || $0 == 10 || $0 == 13 || (32...126).contains($0) }) else {
            throw RouterSystemError.configurationRejected
        }
        let lines = header.components(separatedBy: "\r\n")
        guard lines.allSatisfy({ !$0.contains("\r") && !$0.contains("\n") }) else { throw RouterSystemError.configurationRejected }
        let statusLine = lines[0].split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
        guard statusLine.count >= 2, ["HTTP/1.0", "HTTP/1.1"].contains(String(statusLine[0])),
              ["200", "401"].contains(String(statusLine[1])), let status = Int(statusLine[1]) else {
            throw RouterSystemError.configurationRejected
        }
        var headers: [String: String] = [:]
        for line in lines.dropFirst() {
            guard let colon = line.firstIndex(of: ":"), colon != line.startIndex else { throw RouterSystemError.configurationRejected }
            let name = line[..<colon]
            guard name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || "!#$%&'*+-.^_`|~".utf8.contains($0) }) else {
                throw RouterSystemError.configurationRejected
            }
            let key = name.lowercased()
            guard headers[key] == nil else { throw RouterSystemError.configurationRejected }
            headers[key] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard headers["transfer-encoding"] == nil,
              headers["content-encoding"] == nil || headers["content-encoding"]?.lowercased() == "identity" else {
            throw RouterSystemError.configurationRejected
        }
        let body = Data(bytes[split.upperBound...])
        guard endpoint != .connections || body.count <= RouterConnectionProjection.bodyLimit else {
            throw RouterConnectionFailure.responseTooLarge
        }
        if let length = headers["content-length"] {
            guard !length.isEmpty, length.utf8.allSatisfy({ (48...57).contains($0) }),
                  let count = Int(length), count == body.count else { throw RouterSystemError.configurationRejected }
        }
        if status == 200 {
            guard headers["content-type"]?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == "application/json" else {
                throw RouterSystemError.configurationRejected
            }
        }
        return .init(status: status, body: body)
    }
}
