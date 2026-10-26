import Foundation
import Darwin

public enum RouterSystemClientError: Error { case unavailable }

/// Fixed local endpoint. A request is sent once; a lost reply never triggers a reconnect.
public final class RouterSystemClient {
    public init() {}
    public func request(_ request: RouterSystemRequest) throws -> RouterSystemStatus {
        try Self.decode(transfer(Self.encode(request), timeout: 90), for: request)
    }
    public func connections(request: UUID, instance: UUID? = nil) throws -> RouterConnectionSnapshot {
        let query = RouterConnectionQuery(request: request, instance: instance)
        do {
            return try RouterConnectionWire.decode(transfer(JSONEncoder().encode(query), timeout: 8), query: query)
        } catch { throw RouterConnectionWire.classify(error) }
    }

    /// Armed hit-correlation against the helper's active instance. Never promotes accepted.
    public func hitCorrelation(_ query: RouterHitCorrelationQuery) throws -> RouterHitCorrelationReply {
        let payload = try RouterHitCorrelationWire.encode(query)
        let bytes = try transfer(payload, timeout: 90)
        return try RouterHitCorrelationWire.decodeReply(bytes, request: query.request)
    }
    private func transfer(_ payload: Data, timeout: TimeInterval) throws -> Data {
        guard getuid() >= 501, getuid() == geteuid() else { throw RouterSystemError.ownershipUnknown }
        let endpoint = try Endpoint.open()
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
        defer { close(fd) }
        try RouterSystemFrame.configure(fd)
        var address = sockaddr_un()
        let bytes = Array(RouterSystemLayout.socket.utf8) + [UInt8(0)]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw RouterSystemError.ownershipUnknown }
        address.sun_family = sa_family_t(AF_UNIX)
        address.sun_len = UInt8(2 + bytes.count)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let length = socklen_t(address.sun_len)
        let result = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, length) }
        }
        if result != 0 {
            guard errno == EINPROGRESS else { throw RouterSystemError.operationUnsettled }
            try Self.finishConnect(fd, deadline: min(deadline, ProcessInfo.processInfo.systemUptime + 3))
        }
        try endpoint.revalidate()
        let reply = try Self.exchange(payload, fd: fd, peer: 0, deadline: deadline)
        try endpoint.revalidate()
        return reply
    }

    /// Kept internal so tests exercise the same bounded transport over their own socketpair.
    static func exchange(_ data: Data, fd: Int32, peer: uid_t, deadline: TimeInterval) throws -> Data {
        try RouterSystemFrame.requirePeer(fd, uid: peer)
        try RouterSystemFrame.send(data, fd: fd, maximum: RouterSystemFrame.requestLimit,
                                   deadline: min(deadline, ProcessInfo.processInfo.systemUptime + 3))
        guard shutdown(fd, SHUT_WR) == 0 else { throw RouterSystemError.operationUnsettled }
        let reply = try RouterSystemFrame.receive(fd, maximum: RouterSystemFrame.replyLimit, deadline: deadline)
        try RouterSystemFrame.requirePeer(fd, uid: peer)
        return reply
    }

    static func decode(_ reply: Data, for request: RouterSystemRequest) throws -> RouterSystemStatus {
        let status = try RouterSystemReply.decode(reply)
        let expected: UUID?
        switch request {
        case .prepare(let id, _, _), .apply(let id, _), .stop(let id): expected = id
        case .status(let id): expected = id
        case .previewEnvironment(let id, _), .confirmEnvironment(let id, _, _): expected = id
        }
        guard expected == nil || status.instance == expected else { throw RouterSystemError.conflict }
        switch request {
        case .previewEnvironment(_, let review):
            guard status.phase == "stopping", status.reason == "external_environment_changed",
                  status.environmentReview?.id == review else { throw RouterSystemError.conflict }
        case .confirmEnvironment(_, let review, let digest):
            guard status.phase == "stopped", status.reason == "external_environment_acknowledged",
                  status.environmentReview?.id == review, status.environmentReview?.digest == digest else { throw RouterSystemError.conflict }
        default: break
        }
        return status
    }

    static func encode(_ request: RouterSystemRequest) throws -> Data {
        var object: [String: Any] = ["version": 1]
        switch request {
        case .prepare(let id, let plan, let profile):
            object["action"] = "prepare"; object["id"] = id.uuidString
            object["plan"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(plan))
            object["profile"] = try JSONSerialization.jsonObject(with: JSONEncoder().encode(profile))
        case .apply(let id, let credentials):
            object["action"] = "apply"; object["id"] = id.uuidString
            object["credentials"] = credentials.map {
                ["reference": $0.reference.uuidString, "username": $0.value.username, "password": $0.value.password]
            }
        case .status(let id):
            object["action"] = "status"; object["id"] = id?.uuidString
        case .stop(let id): object["action"] = "stop"; object["id"] = id.uuidString
        case .previewEnvironment(let id, let review):
            object["action"] = "previewEnvironment"; object["id"] = id.uuidString; object["review"] = review.uuidString
        case .confirmEnvironment(let id, let review, let digest):
            object["action"] = "confirmEnvironment"; object["id"] = id.uuidString
            object["review"] = review.uuidString; object["digest"] = digest
        }
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        _ = try RouterSystemDecoder.decode(data)
        return data
    }

    private final class Endpoint {
        let parent: Int32
        let node: stat
        init(parent: Int32, node: stat) { self.parent = parent; self.node = node }
        deinit { close(parent) }
        static func open() throws -> Endpoint {
            var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
            do {
                try RouterSystemDirectory.validateDirectory(fd, owner: 0, privateLeaf: false)
                for component in (RouterSystemLayout.root + "/run").split(separator: "/") {
                    let next = openat(fd, String(component), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    if next < 0 {
                        if errno == ENOENT { throw RouterSystemClientError.unavailable }
                        throw RouterSystemError.ownershipUnknown
                    }
                    close(fd); fd = next
                    try RouterSystemDirectory.validateDirectory(fd, owner: 0, privateLeaf: false)
                }
                var node = stat()
                if fstatat(fd, "control.sock", &node, AT_SYMLINK_NOFOLLOW) != 0 {
                    if errno == ENOENT { throw RouterSystemClientError.unavailable }
                    throw RouterSystemError.ownershipUnknown
                }
                guard node.st_mode & S_IFMT == S_IFSOCK, node.st_uid == getuid(),
                      node.st_mode & 0o7777 == 0o600, node.st_nlink == 1 else { throw RouterSystemError.ownershipUnknown }
                return .init(parent: fd, node: node)
            } catch { close(fd); throw error }
        }
        func revalidate() throws {
            let current = try Self.open()
            var before = stat(), after = stat()
            guard fstat(parent, &before) == 0, fstat(current.parent, &after) == 0,
                  before.st_dev == after.st_dev, before.st_ino == after.st_ino,
                  RouterSystemDirectory.unchanged(node, current.node) else { throw RouterSystemError.ownershipUnknown }
        }
    }
    private static func finishConnect(_ fd: Int32, deadline: TimeInterval) throws {
        while ProcessInfo.processInfo.systemUptime < deadline {
            var item = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let wait = max(1, min(1000, ceil((deadline - ProcessInfo.processInfo.systemUptime) * 1000)))
            let result = poll(&item, 1, Int32(wait))
            if result < 0 && errno == EINTR { continue }
            guard result >= 0, item.revents & Int16(POLLNVAL) == 0 else { throw RouterSystemError.operationUnsettled }
            if result == 0 { continue }
            var error: Int32 = 0, count = socklen_t(MemoryLayout<Int32>.size)
            guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &count) == 0,
                  count == MemoryLayout<Int32>.size, error == 0,
                  ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.operationUnsettled }
            return
        }
        throw RouterSystemError.operationUnsettled
    }
}
