import Foundation
import Darwin

/// Pre-apply reachability for the profile's upstream resolver path.
///
/// A dead core-side resolver under fake-ip silently blackholes every hostname on
/// the host (live evidence 2026-10-25 DoH/1.1.1.1 unreachable on this LAN). This
/// gate refuses apply when none of the bootstrap UDP/53 endpoints answer within
/// a short bound. It never sets routing_verified / accepted / protection flags.
enum RouterSystemResolverHealth {
    static let defaultTimeout: TimeInterval = 1.5
    static let maxServers = 8

    /// Injected probe returns true when the server answered a DNS query.
    static func requireReachable(profile: RouterSystemProfile,
                                 timeout: TimeInterval = defaultTimeout,
                                 probe: (String, UInt16, TimeInterval) throws -> Bool = udpDNSProbe) throws {
        guard timeout > 0, timeout <= 5, timeout.isFinite else { throw RouterSystemError.operationUnsettled }
        let resolver = RouterSystemCompiler.Resolver(profile.resolver)
        let endpoints = Array(resolver.bootstrap.prefix(maxServers))
        guard !endpoints.isEmpty else { throw RouterSystemError.configurationRejected }
        var any = false
        for address in endpoints {
            if (try? probe(address, 53, timeout)) == true {
                any = true
                break
            }
        }
        // Refuse apply rather than arm a known blackhole. Mapped to networkConflict so
        // callers treat it like requireClear failure (environment not ready).
        guard any else { throw RouterSystemError.networkConflict }
    }

    /// Minimal DNS A query for "a.root-servers.net." — any reply (including NXDOMAIN/
    /// FORMERR) proves the UDP/53 path is live. Timeout / send failure = unreachable.
    static func udpDNSProbe(_ address: String, port: UInt16, timeout: TimeInterval) throws -> Bool {
        guard timeout > 0, timeout <= 5, port > 0 else { throw RouterSystemError.operationUnsettled }
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM,
                             ai_protocol: IPPROTO_UDP, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>?
        defer { if let info { freeaddrinfo(info) } }
        let portText = String(port)
        guard getaddrinfo(address, portText, &hints, &info) == 0, let first = info else {
            throw RouterSystemError.networkConflict
        }
        let fd = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
        guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
        defer { close(fd) }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw RouterSystemError.operationUnsettled }
        // Transaction ID 0xCAFE, RD=1, one question: a.root-servers.net. IN A
        let query: [UInt8] = [
            0xCA, 0xFE, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x61, 0x0c, 0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76,
            0x65, 0x72, 0x73, 0x03, 0x6e, 0x65, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01,
        ]
        let sent = query.withUnsafeBytes { raw -> Int in
            guard let base = raw.baseAddress else { return -1 }
            return sendto(fd, base, query.count, 0, first.pointee.ai_addr, first.pointee.ai_addrlen)
        }
        guard sent == query.count else { throw RouterSystemError.networkConflict }
        let deadline = ProcessInfo.processInfo.systemUptime + timeout
        var buffer = [UInt8](repeating: 0, count: 512)
        while ProcessInfo.processInfo.systemUptime < deadline {
            var pollFD = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let remaining = max(0, deadline - ProcessInfo.processInfo.systemUptime)
            let ms = Int32(min(remaining * 1000, Double(Int32.max)))
            let pr = poll(&pollFD, 1, ms)
            if pr < 0 {
                if errno == EINTR { continue }
                throw RouterSystemError.operationUnsettled
            }
            if pr == 0 { break }
            let n = recv(fd, &buffer, buffer.count, 0)
            if n >= 12 { return true } // DNS header present
            if n < 0, errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { continue }
            break
        }
        return false
    }
}
