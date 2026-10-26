import Foundation

/// Separate IPC from connections sampling. No credentials in the request.
public struct RouterHitCorrelationQuery: Codable, Equatable, Sendable {
    public let version: Int
    public let action: String
    public let request: UUID
    public let instance: UUID
    public let mode: String
    public let armingID: UUID
    public let armingIssuedAt: TimeInterval
    public let armingExpiresAt: TimeInterval
    public let address: String
    public let port: UInt16
    public let serverName: String?

    public init(request: UUID, instance: UUID, mode: RouterHitCorrelationEntry.Mode,
                arming: RouterHitCorrelationEntry.Arming, address: String, port: UInt16,
                serverName: String?) {
        version = 1
        action = "hitCorrelation"
        self.request = request
        self.instance = instance
        self.mode = mode.rawValue
        armingID = arming.id
        armingIssuedAt = arming.issuedAt.timeIntervalSince1970
        armingExpiresAt = arming.expiresAt.timeIntervalSince1970
        self.address = address
        self.port = port
        self.serverName = serverName
    }

    public var reconstructedArming: RouterHitCorrelationEntry.Arming? {
        guard let mode = RouterHitCorrelationEntry.Mode(rawValue: mode) else { return nil }
        return .init(id: armingID, mode: mode,
                     issuedAt: Date(timeIntervalSince1970: armingIssuedAt),
                     expiresAt: Date(timeIntervalSince1970: armingExpiresAt))
    }

    public static func decode(_ bytes: Data) throws -> Self {
        let object = try RouterStrictJSON.object(bytes, maximumBytes: 4096)
        guard (object["action"] as? String) == "hitCorrelation" else {
            throw RouterConnectionFailure.invalidResponse
        }
        let query = try JSONDecoder().decode(Self.self, from: bytes)
        guard query.version == 1, query.action == "hitCorrelation",
              query.port > 0, !query.address.isEmpty, query.address.count <= 128,
              query.armingExpiresAt > query.armingIssuedAt,
              query.serverName.map({ !$0.isEmpty && $0.count <= 253 }) ?? true else {
            throw RouterConnectionFailure.invalidResponse
        }
        return query
    }
}

public struct RouterHitCorrelationReply: Codable, Equatable, Sendable {
    public let version: Int
    public let request: UUID
    public let outcome: String
    public let reason: String
    public let relation: String?
    public let collectorAuthenticated: Bool
    public let canPromoteAccepted: Bool
    public let journalMutated: Bool
    public let summary: String

    public static func refused(request: UUID, reason: String) -> Self {
        .init(version: 1, request: request, outcome: "refused", reason: reason, relation: nil,
              collectorAuthenticated: false, canPromoteAccepted: false, journalMutated: false,
              summary: "命中关联 IPC 拒绝：\(reason)。未写 accepted，未改网络。")
    }

    /// `collectorAuthenticated` may be true only as loopback matrix attestation under an
    /// active helper binding. `canPromoteAccepted` stays false — never promotes accepted.
    public static func correlated(request: UUID, report: RouterHitCorrelationEntry.Report,
                                  collectorAuthenticated: Bool = false) -> Self {
        .init(version: 1, request: request, outcome: "correlated", reason: report.reason,
              relation: report.relation,
              collectorAuthenticated: collectorAuthenticated && !report.canPromoteAccepted,
              canPromoteAccepted: false, journalMutated: false, summary: report.summary)
    }
}

enum RouterHitCorrelationWire {
    static func encode(_ query: RouterHitCorrelationQuery) throws -> Data {
        let data = try JSONEncoder().encode(query)
        _ = try RouterHitCorrelationQuery.decode(data)
        return data
    }

    static func decodeReply(_ bytes: Data, request: UUID) throws -> RouterHitCorrelationReply {
        let reply = try JSONDecoder().decode(RouterHitCorrelationReply.self, from: bytes)
        // canPromoteAccepted / journalMutated must stay false; collectorAuthenticated may
        // attest loopback matrix cells without promoting accepted.
        guard reply.version == 1, reply.request == request,
              reply.canPromoteAccepted == false, reply.journalMutated == false else {
            throw RouterConnectionFailure.invalidResponse
        }
        return reply
    }

    static func response(to query: RouterHitCorrelationQuery,
                         run: () throws -> RouterHitCorrelationReply) throws -> Data {
        do {
            let reply = try run()
            guard reply.request == query.request,
                  reply.canPromoteAccepted == false, reply.journalMutated == false else {
                throw RouterConnectionFailure.invalidResponse
            }
            return try JSONEncoder().encode(reply)
        } catch let failure as RouterConnectionFailure {
            return try JSONEncoder().encode(RouterHitCorrelationReply.refused(
                request: query.request, reason: failure.rawValue))
        } catch {
            return try JSONEncoder().encode(RouterHitCorrelationReply.refused(
                request: query.request, reason: "operationUnsettled"))
        }
    }
}
