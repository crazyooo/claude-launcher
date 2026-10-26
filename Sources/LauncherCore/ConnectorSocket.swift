import Foundation
import Darwin

/// Small local frames with one monotonic budget, including trickle reads and partial writes.
enum ConnectorSocket {
    static func prepare(_ fd: Int32) throws {
        var yes: Int32 = 1
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0,
              fcntl(fd, F_SETFD, FD_CLOEXEC) == 0,
              setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout.size(ofValue: yes))) == 0 else {
            throw LauncherError.message("无法配置控制连接。")
        }
    }
    static func ready(_ fd: Int32, events: Int16, deadline: Double) throws {
        while connectorTime() < deadline {
            var item = pollfd(fd: fd, events: events, revents: 0)
            let milliseconds = Int32(max(1, min(100, (deadline - connectorTime()) * 1000)))
            let result = poll(&item, 1, milliseconds)
            if result > 0 {
                guard item.revents & Int16(POLLNVAL) == 0 else { break }
                // Let recv/send distinguish EOF/error; HUP may accompany the final bytes.
                return
            }
            if result < 0 && errno != EINTR { break }
        }
        throw LauncherError.message("控制连接超时或不可用。")
    }
    static func write(_ fd: Int32, _ data: Data, limit: Int, deadline: Double) throws {
        guard data.count <= limit + 1 else { throw LauncherError.message("控制消息超过上限。") }
        try data.withUnsafeBytes { ptr in
            var offset = 0
            while offset < ptr.count {
                guard connectorTime() < deadline else { throw LauncherError.message("控制连接写入超时。") }
                let count = send(fd, ptr.baseAddress!.advanced(by: offset), ptr.count - offset, 0)
                if count > 0 { offset += count; continue }
                guard count < 0, [EAGAIN, EWOULDBLOCK, EINTR].contains(errno) else { throw LauncherError.message("控制连接写入失败。") }
                try ready(fd, events: Int16(POLLOUT), deadline: deadline)
            }
        }
    }
    static func read(_ fd: Int32, limit: Int, deadline: Double) throws -> Data {
        var result = Data(), buffer = [UInt8](repeating: 0, count: 4096)
        while result.count <= limit && connectorTime() < deadline {
            let count = recv(fd, &buffer, min(buffer.count, limit + 1 - result.count), 0)
            if count > 0 {
                result.append(contentsOf: buffer.prefix(count))
                if let end = result.firstIndex(of: 10) {
                    guard end == result.count - 1, end <= limit else { throw LauncherError.message("控制消息格式无效。") }
                    return Data(result[..<end])
                }
            } else if count < 0, [EAGAIN, EWOULDBLOCK, EINTR].contains(errno) {
                try ready(fd, events: Int16(POLLIN), deadline: deadline)
            } else { throw LauncherError.message("控制连接已结束。") }
        }
        throw LauncherError.message("控制消息超时或超过上限。")
    }
}
