import Foundation
import Darwin

/// Bounded I/O on the descriptor held by RouterOwnedTCPProbe. Never opens or retries a connection.
enum RouterOwnedTCPIO {
    struct Effects {
        var send: (Int32, Data) -> (Int, Int32)
        /// nil is a syscall error; empty data is EOF.
        var receive: (Int32, Int) -> (Data?, Int32)
        var poll: (Int32, Int16, Int32) -> (Int32, Int32, Int16)

        static var native: Self {
            .init(send: { fd, bytes in
                let count = bytes.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, $0.count, 0) }
                return (count, count < 0 ? errno : 0)
            }, receive: { fd, maximum in
                var bytes = [UInt8](repeating: 0, count: maximum)
                let count = Darwin.recv(fd, &bytes, maximum, 0)
                return count < 0 ? (nil, errno) : (Data(bytes.prefix(count)), 0)
            }, poll: { fd, events, milliseconds in
                var item = pollfd(fd: fd, events: events, revents: 0)
                let count = Darwin.poll(&item, 1, milliseconds)
                return (count, count < 0 ? errno : 0, item.revents)
            })
        }
    }

    struct Observation {
        let interval: RouterTrafficInterval
        let reply: RouterTCPEchoWire.Reply
        let peerAuthenticated = false
        let egressVerified = false
    }

    static func exchange(fd: Int32, nonce: UUID, until originalDeadline: TimeInterval,
                         clock: () throws -> RouterSystemClock, io: Effects) throws -> Observation {
        let began = try clock()
        guard originalDeadline.isFinite else { throw RouterOwnedProbeError.timedOut }
        let deadline = min(originalDeadline, began.uptime + 5)
        var previous = began

        func checkpoint() throws -> RouterSystemClock {
            let now = try clock()
            try RouterOwnedTCPProbe.requireFresh(start: began, now: now, deadline: deadline)
            try RouterOwnedTCPProbe.requireFresh(start: previous, now: now, deadline: deadline)
            previous = now
            return now
        }
        func waitFor(_ direction: Int16) throws {
            while true {
                let now = try checkpoint()
                let milliseconds = Int32(min(100, max(1, ceil((deadline - now.uptime) * 1000))))
                let (count, error, events) = io.poll(fd, direction, milliseconds)
                _ = try checkpoint()
                if count < 0, error == EINTR { continue }
                guard count >= 0, count <= 1, events & Int16(POLLNVAL | POLLERR) == 0 else {
                    throw RouterTCPEchoError.ioFailed
                }
                guard events & Int16(POLLHUP) == 0 else { throw RouterTCPEchoError.eof }
                if count == 0 { continue }
                guard events & direction != 0 else { throw RouterTCPEchoError.ioFailed }
                return
            }
        }
        func readExactly(_ length: Int) throws -> Data {
            guard (1...RouterTCPEchoWire.maximumBody).contains(length) else { throw RouterTCPEchoError.malformed }
            var result = Data()
            while result.count < length {
                _ = try checkpoint()
                let remaining = length - result.count
                let (bytes, error) = io.receive(fd, remaining)
                _ = try checkpoint()
                if bytes == nil, error == EINTR { continue }
                if bytes == nil, error == EAGAIN || error == EWOULDBLOCK {
                    try waitFor(Int16(POLLIN))
                    continue
                }
                guard let bytes, error == 0, bytes.count <= remaining else { throw RouterTCPEchoError.ioFailed }
                guard !bytes.isEmpty else { throw RouterTCPEchoError.eof }
                result.append(bytes)
            }
            return result
        }

        let request = try RouterTCPEchoWire.request(nonce)
        var offset = 0
        while offset < request.count {
            _ = try checkpoint()
            let pending = Data(request.dropFirst(offset))
            let (count, error) = io.send(fd, pending)
            _ = try checkpoint()
            if count < 0, error == EINTR { continue }
            if count < 0, error == EAGAIN || error == EWOULDBLOCK {
                try waitFor(Int16(POLLOUT))
                continue
            }
            guard count > 0, count <= pending.count, error == 0 else { throw RouterTCPEchoError.ioFailed }
            offset += count
        }
        // Consume exactly one bounded frame, without EOF or an unbounded trailing read.
        let length = try RouterTCPEchoWire.bodyLength(readExactly(4))
        let reply = try RouterTCPEchoWire.parseResponse(readExactly(length), expected: nonce)
        let ended = try checkpoint()
        return .init(interval: .init(start: began, end: ended), reply: reply)
    }
}
