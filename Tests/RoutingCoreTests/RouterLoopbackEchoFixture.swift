import Foundation
import Darwin
@testable import RoutingCore

/// Test-only TCP responder: actual accepted peer, split reply, held until client close.
/// One background owner closes the accepted socket; the test joins before releasing the listener.
final class RouterLoopbackEchoFixture {
    let target: RouterOwnedTCPProbe.Endpoint
    private let listener: Int32
    private let group = DispatchGroup()
    private let lock = NSLock()
    private var cancelled = false
    private var result: Result<(UUID, String), Error>?

    init(family: Int32) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterOwnedProbeError.unavailable }
        listener = socket(family, SOCK_STREAM, IPPROTO_TCP)
        let listener = self.listener
        guard listener >= 0 else { throw RouterOwnedProbeError.unavailable }
        var transferred = false
        defer { if !transferred { _ = Darwin.close(listener) } }
        guard fcntl(listener, F_SETFL, O_NONBLOCK) == 0 else { throw RouterOwnedProbeError.unavailable }
        var storage = sockaddr_storage()
        let length: socklen_t
        if family == AF_INET {
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1")
            length = socklen_t(MemoryLayout<sockaddr_in>.size)
            withUnsafeMutableBytes(of: &storage) { destination in
                withUnsafeBytes(of: address) { destination.copyBytes(from: $0) }
            }
        } else {
            guard family == AF_INET6 else { throw RouterOwnedProbeError.invalidTarget }
            var address = sockaddr_in6()
            address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
            address.sin6_family = sa_family_t(AF_INET6)
            guard inet_pton(AF_INET6, "::1", &address.sin6_addr) == 1 else { throw RouterOwnedProbeError.invalidTarget }
            length = socklen_t(MemoryLayout<sockaddr_in6>.size)
            withUnsafeMutableBytes(of: &storage) { destination in
                withUnsafeBytes(of: address) { destination.copyBytes(from: $0) }
            }
        }
        let bound = withUnsafePointer(to: &storage) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, length) }
        }
        guard bound == 0, listen(listener, 1) == 0 else { throw RouterOwnedProbeError.unavailable }
        var size = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard withUnsafeMutablePointer(to: &storage, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) }
        }) == 0 else { throw RouterOwnedProbeError.unavailable }
        target = try RouterOwnedTCPProbe.decodeAddress(storage, length: size)
        transferred = true
        group.enter()
        DispatchQueue.global().async {
            let result = Result { try self.serve() }
            self.lock.lock(); self.result = result; self.lock.unlock()
            self.group.leave()
        }
    }

    func finish() throws -> (UUID, String) {
        guard group.wait(timeout: .now() + 6) == .success else { throw RouterOwnedProbeError.timedOut }
        lock.lock(); let saved = result; lock.unlock()
        guard let saved else { throw RouterOwnedProbeError.unavailable }
        return try saved.get()
    }

    func stop() {
        lock.lock(); cancelled = true; lock.unlock()
        group.wait()
    }
    deinit { _ = Darwin.close(listener) }

    private func serve() throws -> (UUID, String) {
        let deadline = ProcessInfo.processInfo.systemUptime + 5
        func check() throws {
            lock.lock(); let stopped = cancelled; lock.unlock()
            guard !stopped, ProcessInfo.processInfo.systemUptime < deadline else { throw RouterOwnedProbeError.timedOut }
        }
        func wait(_ fd: Int32, _ direction: Int16) throws {
            while true {
                try check()
                var item = pollfd(fd: fd, events: direction, revents: 0)
                let count = Darwin.poll(&item, 1, 50)
                if count < 0, errno == EINTR { continue }
                guard count >= 0, item.revents & Int16(POLLERR | POLLNVAL) == 0 else { throw RouterTCPEchoError.ioFailed }
                if count > 0, item.revents & (direction | Int16(POLLHUP)) != 0 { return }
            }
        }
        var peerStorage = sockaddr_storage(), peerSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        let peer: Int32
        while true {
            try wait(listener, Int16(POLLIN))
            let accepted = withUnsafeMutablePointer(to: &peerStorage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(listener, $0, &peerSize) }
            }
            if accepted < 0, errno == EINTR || errno == EAGAIN { continue }
            guard accepted >= 0 else { throw RouterTCPEchoError.ioFailed }
            peer = accepted; break
        }
        defer { _ = Darwin.close(peer) }
        var noSignal: Int32 = 1
        guard fcntl(peer, F_SETFL, O_NONBLOCK) == 0,
              setsockopt(peer, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw RouterTCPEchoError.ioFailed
        }
        // Read it again from the accepted FD, never from a field supplied by the client.
        peerSize = socklen_t(MemoryLayout<sockaddr_storage>.size)
        guard withUnsafeMutablePointer(to: &peerStorage, {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(peer, $0, &peerSize) }
        }) == 0 else { throw RouterTCPEchoError.ioFailed }
        let actualPeer = try RouterOwnedTCPProbe.decodeAddress(peerStorage, length: peerSize)
        guard actualPeer.isLoopback else { throw RouterTCPEchoError.ioFailed }
        func receive(_ count: Int) throws -> Data {
            var result = Data()
            while result.count < count {
                try wait(peer, Int16(POLLIN))
                let (bytes, error) = RouterOwnedTCPIO.Effects.native.receive(peer, count - result.count)
                if bytes == nil, error == EINTR || error == EAGAIN { continue }
                guard let bytes, !bytes.isEmpty else { throw RouterTCPEchoError.eof }
                result.append(bytes)
            }
            return result
        }
        let count = try RouterTCPEchoWire.bodyLength(receive(4))
        let nonce = try RouterTCPEchoWire.parseRequest(receive(count))
        let frame = try RouterTCPEchoWire.response(nonce, actualPeerIP: actualPeer.address)
        var offset = 0
        while offset < frame.count {
            try wait(peer, Int16(POLLOUT))
            let (count, error) = RouterOwnedTCPIO.Effects.native.send(peer, Data(frame.dropFirst(offset).prefix(3)))
            if count < 0, error == EINTR || error == EAGAIN { continue }
            guard count > 0 else { throw RouterTCPEchoError.ioFailed }
            offset += count
        }
        // Keep the peer open through the coordinator's final source checks.
        while true {
            try wait(peer, Int16(POLLIN))
            let (bytes, error) = RouterOwnedTCPIO.Effects.native.receive(peer, 1)
            if bytes == nil, error == EINTR || error == EAGAIN { continue }
            guard let bytes else { throw RouterTCPEchoError.ioFailed }
            if bytes.isEmpty { return (nonce, actualPeer.address) }
            throw RouterTCPEchoError.malformed
        }
    }
}
