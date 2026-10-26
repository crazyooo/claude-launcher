import Foundation
import Darwin

/// Private, ephemeral metadata. It is deliberately not Codable or a public UI row.
struct RouterTrafficTracker {
    let id: UUID
    let startedAt: Date
    let transport: String
    let origin: String
    let processPath: String
    let sourceIP: String
    let sourcePort: UInt16
    let destinationIP: String?
    let destinationPort: UInt16
    let host: String?
    let sniffHost: String?
    let dnsMode: String
    let rule: String
    let payload: String
    let chains: [String]
    let hasOverride: Bool
}

enum RouterTrafficAddress {
    static func bytes(_ value: String) -> Data? {
        guard !value.utf8.contains(0), value.utf8.count <= 45 else { return nil }
        var v4 = in_addr(), v6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 {
            return withUnsafeBytes(of: v4) { Data($0) }
        }
        if value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 {
            return withUnsafeBytes(of: v6) { Data($0) }
        }
        return nil
    }
    static func equal(_ lhs: String, _ rhs: String) -> Bool {
        guard let left = bytes(lhs), let right = bytes(rhs) else { return false }
        return left == right
    }
    static func isFake(_ value: String) -> Bool {
        guard let address = bytes(value) else { return false }
        // The exact configured prefixes, not the larger RFC benchmarking range.
        let range = address.count == 4 ? RouterSystemCompiler.fakeIPv4 : RouterSystemCompiler.fakeIPv6
        let parts = range.split(separator: "/")
        guard parts.count == 2, let base = bytes(String(parts[0])), base.count == address.count,
              let bits = Int(parts[1]), bits % 8 == 0, bits <= base.count * 8 else { return false }
        return address.prefix(bits / 8) == base.prefix(bits / 8)
    }
}

/// Fixed v1.19.32 tracker format. Parsing proves shape only, never provenance.
/// Keep the complete bounded set: UI truncation must not hide an ambiguous match.
enum RouterTrafficTrackerParser {
    private struct Response: Decodable {
        let uploadTotal: Int64
        let downloadTotal: Int64
        let connections: [Row]?
    }
    private struct Row: Decodable {
        let id: UUID
        let start: String
        let upload: Int64
        let download: Int64
        let metadata: Metadata
        let rule: String
        let rulePayload: String
        let chains: [String]?
    }
    private struct Metadata: Decodable {
        let network: String
        let type: String
        let processPath: String
        let sourceIP: String
        let sourcePort: String
        let destinationIP: String
        let destinationPort: String
        let host: String
        let sniffHost: String
        let dnsMode: String
        let specialProxy: String
        let specialRules: String
        let rematchName: String
    }

    static func parse(_ data: Data) throws -> [RouterTrafficTracker] {
        do {
            let object = try RouterStrictJSON.object(data, maximumBytes: RouterConnectionProjection.bodyLimit,
                                                    maximumValues: 100_000)
            guard ["connections", "uploadTotal", "downloadTotal"].allSatisfy({ object[$0] != nil }) else {
                throw RouterTrafficEvidenceError.invalidReceipt
            }
            let response = try JSONDecoder().decode(Response.self, from: data)
            let rows = response.connections ?? []
            guard response.uploadTotal >= 0, response.downloadTotal >= 0,
                  rows.count <= RouterConnectionProjection.connectionLimit,
                  Set(rows.map(\.id)).count == rows.count else { throw RouterTrafficEvidenceError.invalidReceipt }
            let integral = ISO8601DateFormatter()
            integral.formatOptions = [.withInternetDateTime]
            func timestamp(_ text: String) -> Date? {
                guard text.range(of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$"#,
                                 options: .regularExpression) != nil else { return nil }
                guard let dot = text.firstIndex(of: ".") else { return integral.date(from: text) }
                let tail = text[text.index(after: dot)...], digits = tail.prefix { $0.isNumber }
                guard let nanos = Double(digits),
                      let seconds = integral.date(from: String(text[..<dot]) + tail.dropFirst(digits.count)) else { return nil }
                // ISO8601DateFormatter truncates fractions to milliseconds on macOS.
                // Preserve Date's available precision; do not add a time tolerance.
                return seconds.addingTimeInterval(nanos / pow(10, Double(digits.count)))
            }
            return try rows.map { row in
                let m = row.metadata
                func bounded(_ text: String, _ count: Int) -> Bool {
                    text.utf8.count <= count && !text.unicodeScalars.contains {
                        CharacterSet.controlCharacters.contains($0) || $0.properties.generalCategory == .format
                    }
                }
                func port(_ text: String) -> UInt16? {
                    guard !text.isEmpty, text.utf8.allSatisfy({ (48...57).contains($0) }),
                          let value = UInt16(text), String(value) == text else { return nil }
                    return value
                }
                guard row.upload >= 0, row.download >= 0,
                      let start = timestamp(row.start),
                      start.timeIntervalSince1970.isFinite,
                      [m.network, m.type, m.dnsMode, row.rule].allSatisfy({ bounded($0, 64) }),
                      bounded(m.processPath, 4096), bounded(row.rulePayload, 16_384),
                      [m.host, m.sniffHost].allSatisfy({ $0.isEmpty || RouterValidation.validDomain($0) }),
                      [m.sourceIP, m.destinationIP].allSatisfy({ $0.isEmpty || RouterTrafficAddress.bytes($0) != nil }),
                      let sourcePort = port(m.sourcePort), let destinationPort = port(m.destinationPort),
                      [m.specialProxy, m.specialRules, m.rematchName].allSatisfy({ bounded($0, 4096) }),
                      (row.chains?.count ?? 0) <= 32,
                      (row.chains ?? []).allSatisfy({ !$0.isEmpty && bounded($0, 160) }) else {
                    throw RouterTrafficEvidenceError.invalidReceipt
                }
                return .init(id: row.id, startedAt: start, transport: m.network, origin: m.type,
                    processPath: m.processPath, sourceIP: m.sourceIP, sourcePort: sourcePort,
                    destinationIP: m.destinationIP.isEmpty ? nil : m.destinationIP, destinationPort: destinationPort,
                    host: m.host.isEmpty ? nil : m.host.lowercased(),
                    sniffHost: m.sniffHost.isEmpty ? nil : m.sniffHost.lowercased(), dnsMode: m.dnsMode,
                    rule: row.rule, payload: row.rulePayload, chains: row.chains ?? [],
                    hasOverride: [m.specialProxy, m.specialRules, m.rematchName].contains { !$0.isEmpty })
            }
        } catch {
            // Never include raw metadata, credentials or decoder descriptions in errors.
            throw RouterTrafficEvidenceError.invalidReceipt
        }
    }
}
