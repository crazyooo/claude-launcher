import Foundation

/// Controllable production entry for own TCP/TLS capture → hit correlation.
/// Reuses `RouterSystemConnections.observeOwn*` and `RouterTrafficCorrelator.evaluateOwn*`.
/// Requires explicit short-lived arming. Never mutates journal, never writes accepted,
/// and never claims `canPromoteAccepted` / `collectorAuthenticated`.
public enum RouterHitCorrelationEntry {
    public static let policyVersion = 1

    public enum Mode: String, Equatable, Sendable {
        case tcpNumeric
        case tlsHeld
    }

    public struct Arming: Equatable, Sendable {
        public let id: UUID
        public let mode: Mode
        public let issuedAt: Date
        public let expiresAt: Date

        public init(id: UUID, mode: Mode, issuedAt: Date, expiresAt: Date) {
            self.id = id
            self.mode = mode
            self.issuedAt = issuedAt
            self.expiresAt = expiresAt
        }

        public func isValid(now: Date = Date()) -> Bool {
            now >= issuedAt && now < expiresAt && expiresAt.timeIntervalSince(issuedAt) <= 120
        }
    }

    public struct Report: Equatable, Sendable {
        public let armingID: UUID
        public let mode: Mode
        public let relation: String
        public let reason: String
        public let connection: UUID?
        public let compiledOrdinal: Int?
        public let collectorAuthenticated: Bool
        public let canPromoteAccepted: Bool
        public let journalMutated: Bool
        public let gaps: [String]
        public let summary: String
    }

    public enum Failure: Error, Equatable {
        case disarmed
        case expired
        case modeMismatch
    }

    /// Explicit one-shot arming. Auto/background capture remains forbidden.
    public static func arm(mode: Mode, now: Date = Date(), ttl: TimeInterval = 60) -> Arming {
        let window = min(max(ttl, 1), 120)
        return .init(id: UUID(), mode: mode, issuedAt: now, expiresAt: now.addingTimeInterval(window))
    }

    public static func requireArmed(_ arming: Arming?, mode: Mode, now: Date = Date()) throws {
        guard let arming else { throw Failure.disarmed }
        guard arming.mode == mode else { throw Failure.modeMismatch }
        guard arming.isValid(now: now) else { throw Failure.expired }
    }

    /// UI/status helper. Live capture still needs an active system Connections owner.
    public static func status(arming: Arming?, last: Report?, now: Date = Date()) -> String {
        if let last {
            return last.summary
        }
        if let arming, arming.isValid(now: now) {
            return "已武装 \(arming.mode.rawValue)（至 \(arming.expiresAt.formatted())）。须经此入口显式捕获；不自动采样，不写 accepted。"
        }
        return "受控命中关联入口未武装。既有 TCP/TLS 采集保持休眠，直到你显式武装并触发；不会静默改网络或写 accepted。"
    }

    /// Correlate an already-captured TCP observation. No network I/O; no journal write.
    static func correlateTCP(arming: Arming?,
                             observation: RouterSystemConnections.OwnProbeObservation,
                             plan: RouterPlan, profile: RouterSystemProfile,
                             now: Date = Date()) throws -> Report {
        try requireArmed(arming, mode: .tcpNumeric, now: now)
        let result = try RouterTrafficCorrelator.evaluateOwn(observation, plan: plan, profile: profile)
        return report(arming: arming!, mode: .tcpNumeric, result: result, label: "own_tcp")
    }

    /// Correlate an already-captured TLS observation. No network I/O; no journal write.
    static func correlateTLS(arming: Arming?,
                             observation: RouterSystemConnections.OwnTLSObservation,
                             plan: RouterPlan, profile: RouterSystemProfile,
                             now: Date = Date()) throws -> Report {
        try requireArmed(arming, mode: .tlsHeld, now: now)
        let result = try RouterTrafficCorrelator.evaluateOwnTLS(observation, plan: plan, profile: profile)
        return report(arming: arming!, mode: .tlsHeld, result: result, label: "own_tls")
    }

    /// Capture via existing Connections probe, then correlate. Does not write journal/accepted.
    /// Production IPC may invoke this only through the armed `hitCorrelation` control path.
    static func captureAndCorrelateTCP(arming: Arming?,
                                       connections: RouterSystemConnections,
                                       address: String, port: UInt16,
                                       plan: RouterPlan, profile: RouterSystemProfile,
                                       now: Date = Date()) throws -> Report {
        try requireArmed(arming, mode: .tcpNumeric, now: now)
        let observation = try connections.observeOwnTCP(address: address, port: port)
        return try correlateTCP(arming: arming, observation: observation, plan: plan, profile: profile, now: now)
    }

    /// Capture via existing TLS owner, then correlate. Does not write journal/accepted.
    /// Production IPC may invoke this only through the armed `hitCorrelation` control path.
    static func captureAndCorrelateTLS(arming: Arming?,
                                       connections: RouterSystemConnections,
                                       target: RouterTLSConnection.Endpoint,
                                       serverName: String,
                                       plan: RouterPlan, profile: RouterSystemProfile,
                                       now: Date = Date()) async throws -> Report {
        try requireArmed(arming, mode: .tlsHeld, now: now)
        let observation = try await connections.observeOwnTLS(target: target, serverName: serverName)
        return try correlateTLS(arming: arming, observation: observation, plan: plan, profile: profile, now: now)
    }

    private static func report(arming: Arming, mode: Mode,
                               result: RouterTrafficCorrelationResult, label: String) -> Report {
        .init(armingID: arming.id, mode: mode, relation: result.relation.rawValue,
              reason: result.reason, connection: result.connection,
              compiledOrdinal: result.compiledOrdinal,
              collectorAuthenticated: false, canPromoteAccepted: false, journalMutated: false,
              gaps: result.gaps.map(\.rawValue),
              summary: "受控命中关联（\(label)）· \(result.relation.rawValue)：\(result.reason)。未写 journal/accepted；collectorAuthenticated=false。")
    }
}
