import Foundation
import Darwin

/// One frame per connection. A caller must half-close its write side before dispatch occurs.
enum RouterSystemFrame {
    static let requestLimit = RouterInput.maximumBytes
    static let replyLimit = 65_536
    static func configure(_ fd: Int32) throws {
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0, fcntl(fd, F_SETFL, O_NONBLOCK) == 0,
              fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else { throw RouterSystemError.operationUnsettled }
    }
    static func requirePeer(_ fd: Int32, uid expected: uid_t) throws {
        var actual: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &actual, &gid) == 0, actual == expected else { throw RouterSystemError.ownershipUnknown }
    }
    static func receive(_ fd: Int32, maximum: Int, deadline: TimeInterval) throws -> Data {
        guard maximum > 0, maximum <= requestLimit else { throw RouterSystemError.invalidRequest }
        let header = try read(fd, count: 4, deadline: deadline)
        let length = header.reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard length > 0, length <= maximum else { throw RouterSystemError.invalidRequest }
        let body = try read(fd, count: Int(length), deadline: deadline)
        while true {
            try wait(fd, events: Int16(POLLIN), deadline: deadline)
            var extra: UInt8 = 0
            let count = recv(fd, &extra, 1, 0)
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count == 0 else { throw RouterSystemError.invalidRequest }
            try fresh(deadline)
            return body
        }
    }
    static func send(_ bytes: Data, fd: Int32, maximum: Int, deadline: TimeInterval) throws {
        guard !bytes.isEmpty, maximum > 0, maximum <= requestLimit, bytes.count <= maximum else { throw RouterSystemError.invalidRequest }
        var size = UInt32(bytes.count).bigEndian
        var frame = withUnsafeBytes(of: &size) { Data($0) }; frame.append(bytes)
        var offset = 0
        while offset < frame.count {
            try wait(fd, events: Int16(POLLOUT), deadline: deadline)
            let count = frame.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!.advanced(by: offset), frame.count - offset, 0) }
            if count < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard count > 0 else { throw RouterSystemError.operationUnsettled }
            offset += count
        }
        try fresh(deadline)
    }
    private static func read(_ fd: Int32, count: Int, deadline: TimeInterval) throws -> Data {
        var data = Data(), buffer = [UInt8](repeating: 0, count: min(count, 8192))
        while data.count < count {
            try wait(fd, events: Int16(POLLIN), deadline: deadline)
            let result = recv(fd, &buffer, min(buffer.count, count - data.count), 0)
            if result < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard result > 0 else { throw RouterSystemError.invalidRequest }
            data.append(contentsOf: buffer.prefix(result))
        }
        try fresh(deadline)
        return data
    }
    private static func fresh(_ deadline: TimeInterval) throws {
        guard deadline.isFinite, ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.operationUnsettled }
    }
    private static func wait(_ fd: Int32, events: Int16, deadline: TimeInterval) throws {
        while true {
            try fresh(deadline)
            let remaining = deadline - ProcessInfo.processInfo.systemUptime
            var item = pollfd(fd: fd, events: events, revents: 0)
            let result = poll(&item, 1, Int32(max(0, min(remaining * 1000 + 1, Double(Int32.max)))))
            if result < 0 && errno == EINTR { continue }
            guard result > 0, item.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw RouterSystemError.operationUnsettled }
            try fresh(deadline)
            if item.revents & (events | Int16(POLLHUP)) != 0 { return }
        }
    }
}

struct RouterSystemReply: Encodable {
    let version = 1
    let status: RouterSystemStatus?
    let error: String?
}

/// Framing may run concurrently, but the provider itself rejects concurrent mutations.
/// execute errors and lost responses do not cancel or retry an operation.
final class RouterSystemSocketServer {
    private let ownerUID: uid_t
    private let execute: (RouterSystemRequest) throws -> RouterSystemStatus
    private let connections: (RouterConnectionQuery) throws -> RouterConnectionSnapshot
    private let hitCorrelation: (RouterHitCorrelationQuery) throws -> RouterHitCorrelationReply
    private let slots = DispatchSemaphore(value: 4)
    init(ownerUID: uid_t,
         connections: @escaping (RouterConnectionQuery) throws -> RouterConnectionSnapshot = { _ in throw RouterConnectionFailure.unsupportedComponent },
         hitCorrelation: @escaping (RouterHitCorrelationQuery) throws -> RouterHitCorrelationReply = { query in
             .refused(request: query.request, reason: RouterConnectionFailure.unsupportedComponent.rawValue)
         },
         execute: @escaping (RouterSystemRequest) throws -> RouterSystemStatus) {
        self.ownerUID = ownerUID; self.execute = execute
        self.connections = connections; self.hitCorrelation = hitCorrelation
    }
    func serve(listener: Int32) throws -> Never {
        while true {
            let fd = accept(listener, nil, nil)
            if fd < 0 && errno == EINTR { continue }
            guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
            do { try RouterSystemFrame.configure(fd); try RouterSystemFrame.requirePeer(fd, uid: ownerUID) }
            catch { close(fd); continue }
            guard slots.wait(timeout: .now()) == .success else { close(fd); continue }
            let accepted = ProcessInfo.processInfo.systemUptime
            DispatchQueue.global(qos: .userInitiated).async {
                defer { close(fd); self.slots.signal() }
                self.handle(fd: fd, acceptedAt: accepted)
            }
        }
    }
    func handle(fd: Int32, acceptedAt: TimeInterval) {
        let sessionDeadline = acceptedAt + 90
        do {
            try RouterSystemFrame.requirePeer(fd, uid: ownerUID)
            let data = try RouterSystemFrame.receive(fd, maximum: RouterSystemFrame.requestLimit, deadline: acceptedAt + 5)
            let action = try RouterStrictJSON.object(data)["action"] as? String
            if action == "connections" {
                let query = try RouterConnectionQuery.decode(data)
                let bytes = try RouterConnectionWire.response(to: query) { try connections(query) }
                try RouterSystemFrame.send(bytes, fd: fd, maximum: RouterSystemFrame.replyLimit,
                    deadline: min(acceptedAt + 13, ProcessInfo.processInfo.systemUptime + 3))
                return
            }
            if action == "hitCorrelation" {
                let query = try RouterHitCorrelationQuery.decode(data)
                let bytes = try RouterHitCorrelationWire.response(to: query) { try hitCorrelation(query) }
                try RouterSystemFrame.send(bytes, fd: fd, maximum: RouterSystemFrame.replyLimit,
                    deadline: min(sessionDeadline, ProcessInfo.processInfo.systemUptime + 5))
                return
            }
            let request = try RouterSystemDecoder.decode(data)
            let result = try execute(request)
            try reply(.init(status: result, error: nil), fd: fd, deadline: min(sessionDeadline, ProcessInfo.processInfo.systemUptime + 3))
        } catch {
            let code = (error as? RouterSystemError)?.rawValue ?? "operationUnsettled"
            try? reply(.init(status: nil, error: code), fd: fd, deadline: min(sessionDeadline, ProcessInfo.processInfo.systemUptime + 3))
        }
    }
    private func reply(_ value: RouterSystemReply, fd: Int32, deadline: TimeInterval) throws {
        let data = try JSONEncoder().encode(value)
        try RouterSystemFrame.send(data, fd: fd, maximum: RouterSystemFrame.replyLimit, deadline: deadline)
    }
}
