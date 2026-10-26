import Foundation

public enum RouterConnectionMode: String, Codable, CaseIterable { case userManaged, system }
public enum RouterConnectionFailure: String, Error, Codable {
    case unavailable, notInstalled, noActiveInstance, busy, identityChanged
    case unsupportedComponent, responseTooLarge, invalidResponse, stale, controllerUnavailable
}

/// Observation identity only; this cannot authorize a routing operation.
public struct RouterConnectionBinding: Codable, Equatable {
    public let mode: RouterConnectionMode
    public let installation: UUID?
    public let instance: UUID
    public let epoch: String
    public let configurationDigest: String

    func validate() throws {
        guard (mode == .system) == (installation != nil),
              RouterSystemProvider.validDigest(epoch), RouterSystemProvider.validDigest(configurationDigest) else {
            throw RouterConnectionFailure.invalidResponse
        }
    }
}

public struct RouterConnectionRow: Codable, Equatable, Identifiable {
    public let id: UUID
    public let transport: String
    public let origin: String
    public let process: String?
    public let host: String?
    public let destinationIP: String?
    public let destinationPort: UInt16?
    public let chain: [String]
    public let rule: String?
    public let upload: Int64
    public let download: Int64
}

public struct RouterConnectionSnapshot: Codable {
    static let wireLimit = 49_152
    public let version: Int
    public let request: UUID
    public let binding: RouterConnectionBinding
    public let startedAt: Date
    public let completedAt: Date
    public let startedUptime: TimeInterval
    public let completedUptime: TimeInterval
    public let uploadTotal: Int64
    public let downloadTotal: Int64
    public let totalConnections: Int
    public private(set) var rows: [RouterConnectionRow]
    public var omittedConnections: Int { totalConnections - rows.count }
    public var routingVerified: Bool { false }
    public var protectionVerified: Bool { false }
    public var launchAuthorized: Bool { false }

    public func validate(request expected: UUID, instance: UUID?, mode: RouterConnectionMode,
                         now: Date, uptime: TimeInterval) throws {
        try binding.validate()
        guard version == 1, request == expected, binding.mode == mode,
              instance == nil || instance == binding.instance,
              uploadTotal >= 0, downloadTotal >= 0,
              (0...RouterConnectionProjection.connectionLimit).contains(totalConnections),
              rows.count <= RouterConnectionProjection.rowLimit, rows.count <= totalConnections,
              Set(rows.map(\.id)).count == rows.count else { throw RouterConnectionFailure.invalidResponse }
        let times = [startedAt.timeIntervalSince1970, completedAt.timeIntervalSince1970,
                     now.timeIntervalSince1970, startedUptime, completedUptime, uptime]
        guard times.allSatisfy(\.isFinite), startedUptime >= 0,
              startedAt <= completedAt, completedAt <= now, now.timeIntervalSince(startedAt) <= 15,
              startedUptime <= completedUptime, completedUptime <= uptime, uptime - startedUptime <= 15,
              completedUptime - startedUptime <= 5 else { throw RouterConnectionFailure.stale }
        for row in rows { try RouterConnectionProjection.validate(row) }
    }

    /// Decode the original bytes, preserving Int64 precision. Never round-trip through NSNumber.
    static func decode(_ bytes: Data) throws -> Self {
        do {
            let object = try RouterStrictJSON.object(bytes, maximumBytes: wireLimit)
            let keys: Set<String> = ["version", "request", "binding", "startedAt", "completedAt", "startedUptime",
                                    "completedUptime", "uploadTotal", "downloadTotal", "totalConnections", "rows"]
            let bindingKeys: Set<String> = ["mode", "installation", "instance", "epoch", "configurationDigest"]
            let rowKeys: Set<String> = ["id", "transport", "origin", "process", "host", "destinationIP",
                                       "destinationPort", "chain", "rule", "upload", "download"]
            guard Set(object.keys) == keys, let binding = object["binding"] as? [String: Any],
                  Set(binding.keys).isSubset(of: bindingKeys), let rows = object["rows"] as? [[String: Any]],
                  rows.count <= RouterConnectionProjection.rowLimit,
                  rows.allSatisfy({ Set($0.keys).isSubset(of: rowKeys) }) else { throw RouterConnectionFailure.invalidResponse }
            return try JSONDecoder().decode(Self.self, from: bytes)
        } catch { throw RouterConnectionFailure.invalidResponse }
    }

    mutating func fitWireBudget() throws {
        while try JSONEncoder().encode(self).count > Self.wireLimit {
            guard !rows.isEmpty else { throw RouterConnectionFailure.responseTooLarge }
            rows.removeLast()
        }
    }
}

/// Fixed Mihomo 1.19.32 /connections. Raw metadata stays in memory and is never exported.
enum RouterConnectionProjection {
    static let bodyLimit = 524_288
    static let connectionLimit = 512
    static let rowLimit = 100
    struct Result {
        let upload: Int64
        let download: Int64
        let count: Int
        let rows: [RouterConnectionRow]
    }
    private struct Response: Decodable {
        let uploadTotal: Int64
        let downloadTotal: Int64
        let connections: [Connection]?
    }
    private struct Connection: Decodable {
        let id: UUID
        let metadata: Metadata
        let upload: Int64
        let download: Int64
        let chains: [String]?
        let rule: String
    }
    private struct Metadata: Decodable {
        let network: String
        let type: String
        let process: String
        let host: String
        let destinationIP: String
        let destinationPort: String
    }
    private static let rules: Set<String> = ["Domain", "DomainSuffix", "ProcessPath", "Network", "AND", "Match"]
    private static let origins: Set<String> = ["Tun", "Inner", "HTTP", "HTTPS", "Socks4", "Socks5", "unknown"]

    static func parse(_ bytes: Data, redactions: [String]) throws -> Result {
        guard bytes.count <= bodyLimit else { throw RouterConnectionFailure.responseTooLarge }
        let response: Response
        do {
            let object = try RouterStrictJSON.object(bytes, maximumBytes: bodyLimit, maximumValues: 100_000)
            guard Set(["uploadTotal", "downloadTotal", "connections"]).isSubset(of: Set(object.keys)) else {
                throw RouterConnectionFailure.invalidResponse
            }
            response = try JSONDecoder().decode(Response.self, from: bytes)
        } catch { throw RouterConnectionFailure.invalidResponse }
        // The pinned manager serializes a nil slice as null when there are no connections.
        let connections = response.connections ?? []
        guard connections.count <= connectionLimit else { throw RouterConnectionFailure.responseTooLarge }
        guard response.uploadTotal >= 0, response.downloadTotal >= 0,
              Set(connections.map(\.id)).count == connections.count,
              connections.allSatisfy({ $0.upload >= 0 && $0.download >= 0 && ($0.chains?.count ?? 0) <= 32 }) else {
            throw RouterConnectionFailure.invalidResponse
        }
        func visible(_ text: String, valid: (String) -> Bool) -> String? {
            guard !text.isEmpty, valid(text), !redactions.contains(where: { !$0.isEmpty && text.contains($0) }) else { return nil }
            return text
        }
        let rows = connections.sorted { $0.id.uuidString < $1.id.uuidString }.prefix(rowLimit).map { connection in
            let meta = connection.metadata
            let chain = (connection.chains ?? []).prefix(4).map { visible($0, valid: validChain) ?? "UNKNOWN" }
            return RouterConnectionRow(id: connection.id,
                transport: ["tcp", "udp"].contains(meta.network) ? meta.network : "unknown",
                origin: origins.contains(meta.type) ? meta.type : "unknown",
                process: visible(meta.process, valid: validProcess),
                host: visible(meta.host, valid: RouterValidation.validDomain)?.lowercased(),
                destinationIP: visible(meta.destinationIP, valid: RouterValidation.isIP),
                destinationPort: UInt16(meta.destinationPort).flatMap { $0 > 0 ? $0 : nil },
                chain: chain, rule: visible(connection.rule, valid: rules.contains),
                upload: connection.upload, download: connection.download)
        }
        return .init(upload: response.uploadTotal, download: response.downloadTotal, count: connections.count, rows: rows)
    }

    private static func validProcess(_ text: String) -> Bool {
        !text.isEmpty && text.utf8.count <= 80 && !text.contains("/") && !text.contains("\\") &&
            text.unicodeScalars.allSatisfy { !CharacterSet.controlCharacters.contains($0) &&
                !CharacterSet.newlines.contains($0) && $0.properties.generalCategory != .format }
    }
    private static func validChain(_ text: String) -> Bool {
        if ["DIRECT", "REJECT", "UNKNOWN"].contains(text) { return true }
        guard text.hasPrefix("route_"), let id = UUID(uuidString: String(text.dropFirst(6))) else { return false }
        return text == "route_" + id.uuidString.lowercased()
    }
    static func validate(_ row: RouterConnectionRow) throws {
        guard ["tcp", "udp", "unknown"].contains(row.transport), origins.contains(row.origin),
              row.process.map(validProcess) ?? true, row.host.map(RouterValidation.validDomain) ?? true,
              row.destinationIP.map(RouterValidation.isIP) ?? true, row.destinationPort.map({ $0 > 0 }) ?? true,
              row.chain.count <= 4, row.chain.allSatisfy(validChain), row.rule.map(rules.contains) ?? true,
              row.upload >= 0, row.download >= 0 else { throw RouterConnectionFailure.invalidResponse }
    }
}

/// Adapters must observe without writing journals or performing cleanup; status() is not suitable.
enum RouterConnectionCollector {
    static func read(request: UUID, expectedInstance: UUID?, mode: RouterConnectionMode,
                     observe: () throws -> RouterConnectionBinding,
                     readBody: (RouterConnectionBinding) throws -> (Data, [String]),
                     clock: () -> (Date, TimeInterval)) throws -> RouterConnectionSnapshot {
        let began = clock()
        let binding = try observe()
        try binding.validate()
        guard binding.mode == mode, expectedInstance == nil || expectedInstance == binding.instance else {
            throw RouterConnectionFailure.identityChanged
        }
        let (body, redactions) = try readBody(binding)
        let result = try RouterConnectionProjection.parse(body, redactions: redactions)
        guard try observe() == binding else { throw RouterConnectionFailure.identityChanged }
        let ended = clock()
        var snapshot = RouterConnectionSnapshot(version: 1, request: request, binding: binding,
            startedAt: began.0, completedAt: ended.0, startedUptime: began.1, completedUptime: ended.1,
            uploadTotal: result.upload, downloadTotal: result.download, totalConnections: result.count, rows: result.rows)
        try snapshot.fitWireBudget()
        try snapshot.validate(request: request, instance: expectedInstance, mode: mode, now: ended.0, uptime: ended.1)
        return snapshot
    }
}

public struct RouterConnectionRate: Equatable {
    public let uploadBytesPerSecond: Double
    public let downloadBytesPerSecond: Double

    /// Totals are core counters, not sums of current rows; a reset starts a new baseline.
    public static func between(_ old: RouterConnectionSnapshot, _ new: RouterConnectionSnapshot) -> Self? {
        let elapsed = new.completedUptime - old.completedUptime
        guard elapsed.isFinite, old.binding == new.binding, elapsed >= 0.25, elapsed <= 15,
              new.startedUptime >= old.completedUptime, new.completedAt >= old.completedAt,
              old.uploadTotal >= 0, old.downloadTotal >= 0,
              new.uploadTotal >= old.uploadTotal, new.downloadTotal >= old.downloadTotal else { return nil }
        return .init(uploadBytesPerSecond: Double(new.uploadTotal - old.uploadTotal) / elapsed,
                     downloadBytesPerSecond: Double(new.downloadTotal - old.downloadTotal) / elapsed)
    }
}
