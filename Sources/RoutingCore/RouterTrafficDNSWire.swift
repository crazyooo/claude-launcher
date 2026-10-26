import Foundation
import Darwin

enum RouterTrafficDNSWireError: String, Error {
    case invalidWire, unsupportedAlias, unsupportedAnswer, endpointMismatch, expired
}

/// Derived from a bounded declared exchange, not authenticated packet provenance.
/// Only this file constructs mappings; there is no Codable success input.
struct RouterTrafficDNSMapping {
    let attempt: UUID
    let bindingDigest: String
    let queryName: String
    let queryType: UInt16
    let answerIP: String
    let exchange: RouterTrafficInterval
    let expiresAt: Date
    let expiresUptime: TimeInterval

    fileprivate init(attempt: UUID, bindingDigest: String, queryName: String, queryType: UInt16,
                     answerIP: String, exchange: RouterTrafficInterval, lifetime: TimeInterval) {
        self.attempt = attempt; self.bindingDigest = bindingDigest
        self.queryName = queryName; self.queryType = queryType; self.answerIP = answerIP
        self.exchange = exchange
        // Start at the pre-send sample. Never extend the server's TTL by request time.
        expiresAt = exchange.start.date.addingTimeInterval(lifetime)
        expiresUptime = exchange.start.uptime + lifetime
    }

    func matches(attempt facts: RouterTrafficAttemptFacts, binding: RouterTrafficBinding) -> Bool {
        guard let domain = facts.domain, let digest = try? binding.digest() else { return false }
        return attempt == facts.attempt && bindingDigest == digest &&
            queryName == domain.lowercased() && queryType == (facts.id.family == .ipv4 ? 1 : 28) &&
            exchange.start.bootID == binding.work.bootID && exchange.end.bootID == binding.work.bootID &&
            RouterTrafficAddress.isFake(answerIP) && RouterTrafficAddress.equal(answerIP, facts.destinationIP) &&
            exchange.end.date <= facts.interval.start.date && exchange.end.uptime <= facts.interval.start.uptime &&
            expiresAt > facts.interval.end.date && expiresUptime > facts.interval.end.uptime
    }
}

private struct RouterTrafficDNSMessage {
    struct Answer { let bytes: Data; let ttl: UInt32 }
    let id: UInt16
    let name: String
    let type: UInt16
    let answers: [Answer]

    private struct Reader {
        let bytes: [UInt8]
        var offset = 0
        var labelOffsets = Set<Int>()

        mutating func number() throws -> UInt16 {
            guard offset + 2 <= bytes.count else { throw RouterTrafficDNSWireError.invalidWire }
            defer { offset += 2 }
            return UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
        }
        mutating func wide() throws -> UInt32 {
            let high = try number(), low = try number()
            return UInt32(high) << 16 | UInt32(low)
        }
        mutating func take(_ count: Int) throws -> Data {
            guard count >= 0, offset + count <= bytes.count else { throw RouterTrafficDNSWireError.invalidWire }
            defer { offset += count }
            return Data(bytes[offset..<offset + count])
        }
        mutating func domain() throws -> String {
            var cursor = offset, jumped = false, visited = Set<Int>(), labels: [String] = []
            var wireLength = 1
            for _ in 0..<128 {
                guard cursor < bytes.count, visited.insert(cursor).inserted else { throw RouterTrafficDNSWireError.invalidWire }
                let length = Int(bytes[cursor])
                if length & 0xc0 == 0xc0 {
                    guard cursor + 1 < bytes.count else { throw RouterTrafficDNSWireError.invalidWire }
                    let target = ((length & 0x3f) << 8) | Int(bytes[cursor + 1])
                    // A prior byte is insufficient: it must be a parsed label boundary.
                    guard target < cursor, labelOffsets.contains(target) else { throw RouterTrafficDNSWireError.invalidWire }
                    labelOffsets.insert(cursor)
                    if !jumped { offset = cursor + 2 }
                    jumped = true; cursor = target
                    continue
                }
                guard length <= 63 else { throw RouterTrafficDNSWireError.invalidWire }
                labelOffsets.insert(cursor)
                cursor += 1
                if length == 0 {
                    if !jumped { offset = cursor }
                    let name = labels.joined(separator: ".").lowercased()
                    guard name.isEmpty || RouterValidation.validDomain(name) else { throw RouterTrafficDNSWireError.invalidWire }
                    return name
                }
                guard cursor + length <= bytes.count,
                      let label = String(bytes: bytes[cursor..<cursor + length], encoding: .ascii),
                      !label.contains(".") else { throw RouterTrafficDNSWireError.invalidWire }
                wireLength += length + 1
                guard wireLength <= 255 else { throw RouterTrafficDNSWireError.invalidWire }
                labels.append(label); cursor += length
                if !jumped { offset = cursor }
            }
            throw RouterTrafficDNSWireError.invalidWire
        }
    }

    static func parse(_ wire: Data, transport: RouterTrafficTransport, response: Bool) throws -> Self {
        guard wire.count <= 4098 else { throw RouterTrafficDNSWireError.invalidWire }
        var bytes = Array(wire)
        if transport == .tcp {
            guard bytes.count >= 2, (Int(bytes[0]) << 8 | Int(bytes[1])) == bytes.count - 2 else {
                throw RouterTrafficDNSWireError.invalidWire
            }
            bytes = Array(bytes.dropFirst(2))
        }
        guard (12...4096).contains(bytes.count) else { throw RouterTrafficDNSWireError.invalidWire }
        var reader = Reader(bytes: bytes)
        let id = try reader.number(), flags = try reader.number(), questions = try reader.number()
        let answerCount = Int(try reader.number()), authorityCount = Int(try reader.number())
        let additionalCount = Int(try reader.number())
        guard questions == 1, ((flags & 0x8000) != 0) == response,
              flags & 0x7800 == 0, flags & 0x0200 == 0, flags & 0x0040 == 0, flags & 0x000f == 0,
              answerCount <= 16, authorityCount <= 32, additionalCount <= 32 else {
            throw RouterTrafficDNSWireError.invalidWire
        }
        if !response {
            guard flags & ~UInt16(0x0110) == 0, answerCount == 0, authorityCount == 0,
                  additionalCount <= 1 else { throw RouterTrafficDNSWireError.invalidWire }
        }
        let name = try reader.domain(), type = try reader.number(), qclass = try reader.number()
        guard !name.isEmpty, type == 1 || type == 28, qclass == 1 else { throw RouterTrafficDNSWireError.invalidWire }
        var answers: [Answer] = []
        var seenOPT = false
        for index in 0..<(answerCount + authorityCount + additionalCount) {
            let owner = try reader.domain(), rrType = try reader.number(), rrClass = try reader.number()
            let ttl = try reader.wide(), length = Int(try reader.number())
            let payload = try reader.take(length)
            if index < answerCount {
                guard rrType != 5, rrType != 39 else { throw RouterTrafficDNSWireError.unsupportedAlias }
                guard owner == name, rrType == type, rrClass == 1, payload.count == (type == 1 ? 4 : 16) else {
                    throw RouterTrafficDNSWireError.unsupportedAnswer
                }
                answers.append(.init(bytes: payload, ttl: ttl))
            } else if rrType == 41 {
                guard !seenOPT, index >= answerCount + authorityCount, owner.isEmpty,
                      rrClass >= 512, ttl >> 16 == 0 else { throw RouterTrafficDNSWireError.invalidWire }
                seenOPT = true
                var options = Reader(bytes: Array(payload)), count = 0
                while options.offset < payload.count {
                    _ = try options.number()
                    let size = Int(try options.number())
                    _ = try options.take(size)
                    count += 1
                    guard count <= 32 else { throw RouterTrafficDNSWireError.invalidWire }
                }
            } else if !response { throw RouterTrafficDNSWireError.invalidWire }
        }
        guard reader.offset == bytes.count, !response || !answers.isEmpty else { throw RouterTrafficDNSWireError.invalidWire }
        return .init(id: id, name: name, type: type, answers: answers)
    }
}

enum RouterTrafficDNSWire {
    /// TCP input contains its length prefix. Plain DNS has no probe nonce; matching
    /// ID/question/peer is correlation only. Packet bytes are never persisted here.
    static func mappings(query: Data, response: Data, transport: RouterTrafficTransport,
                         queryDestinationIP: String, queryDestinationPort: UInt16,
                         responseSourceIP: String, responseSourcePort: UInt16,
                         domain: String, family: RouterTrafficFamily, attempt: UUID,
                         binding: RouterTrafficBinding, exchange: RouterTrafficInterval) throws -> [RouterTrafficDNSMapping] {
        try binding.validate()
        try exchange.validate(boot: binding.work.bootID, maximumDuration: 15)
        guard Double(binding.work.birthSeconds) + Double(binding.work.birthMicroseconds) / 1_000_000 <=
                exchange.start.date.timeIntervalSince1970 else { throw RouterTrafficDNSWireError.invalidWire }
        guard queryDestinationPort == 53, responseSourcePort == 53,
              RouterTrafficAddress.equal(queryDestinationIP, responseSourceIP) else {
            throw RouterTrafficDNSWireError.endpointMismatch
        }
        guard RouterValidation.validDomain(domain) else { throw RouterTrafficDNSWireError.invalidWire }
        let sent = try RouterTrafficDNSMessage.parse(query, transport: transport, response: false)
        let received = try RouterTrafficDNSMessage.parse(response, transport: transport, response: true)
        guard sent.id == received.id, sent.name == received.name, sent.type == received.type,
              sent.name == domain.lowercased(), sent.type == (family == .ipv4 ? 1 : 28) else {
            throw RouterTrafficDNSWireError.invalidWire
        }
        var addresses: [Data: UInt32] = [:]
        for answer in received.answers {
            guard answer.ttl <= 0x7fff_ffff else { throw RouterTrafficDNSWireError.invalidWire }
            addresses[answer.bytes] = min(addresses[answer.bytes] ?? UInt32.max, answer.ttl)
        }
        return try addresses.sorted { $0.key.lexicographicallyPrecedes($1.key) }.map { address, ttl in
            var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
            let valid = address.withUnsafeBytes {
                inet_ntop(address.count == 4 ? AF_INET : AF_INET6, $0.baseAddress!, &output, socklen_t(output.count)) != nil
            }
            guard valid else { throw RouterTrafficDNSWireError.invalidWire }
            let text = String(cString: output)
            guard RouterTrafficAddress.isFake(text) else { throw RouterTrafficDNSWireError.unsupportedAnswer }
            let lifetime = TimeInterval(min(ttl, 3600))
            guard lifetime > 0, exchange.start.date.addingTimeInterval(lifetime) > exchange.end.date,
                  exchange.start.uptime + lifetime > exchange.end.uptime else { throw RouterTrafficDNSWireError.expired }
            return .init(attempt: attempt, bindingDigest: try binding.digest(), queryName: sent.name,
                         queryType: sent.type, answerIP: text, exchange: exchange, lifetime: lifetime)
        }
    }
}
