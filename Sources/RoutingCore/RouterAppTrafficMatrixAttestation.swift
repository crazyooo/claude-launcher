import Foundation

/// App-traffic matrix **attestation scaffolding**. Enumerates every application /
/// existing-connection cell with a precise blocked / refused / untested reason until
/// the conversation clear window (`tun-apply-clear-window-v1`) is granted and
/// `requireClear` would pass. Never invents `livePassed`, never sets
/// `canPromoteAccepted`, never mutates the network.
public enum RouterAppTrafficMatrixAttestation {
    public static let policyVersion = 1
    public static let clearWindowID = RouterTunApplyExecuteGate.clearWindowID

    public struct ClearWindowState: Equatable, Sendable {
        public let windowID: String
        public let grantedInConversation: Bool
        public let requireClearWouldPass: Bool?
        public let refuseOwnTun: Bool?
        public let foreignTunnelPresent: Bool?
        public let systemPhase: String?
        public let systemInstance: UUID?

        public init(windowID: String = RouterAppTrafficMatrixAttestation.clearWindowID,
                    grantedInConversation: Bool,
                    requireClearWouldPass: Bool?,
                    refuseOwnTun: Bool?,
                    foreignTunnelPresent: Bool? = nil,
                    systemPhase: String?,
                    systemInstance: UUID?) {
            self.windowID = windowID
            self.grantedInConversation = grantedInConversation
            self.requireClearWouldPass = requireClearWouldPass
            self.refuseOwnTun = refuseOwnTun
            self.foreignTunnelPresent = foreignTunnelPresent
            self.systemPhase = systemPhase
            self.systemInstance = systemInstance
        }

        /// Production default: conversation has not granted the TUN clear window.
        public static func productionDefault(systemPhase: String? = nil,
                                             systemInstance: UUID? = nil,
                                             refuseOwnTun: Bool? = nil,
                                             requireClearWouldPass: Bool? = nil) -> ClearWindowState {
            .init(grantedInConversation: false,
                  requireClearWouldPass: requireClearWouldPass ?? refuseOwnTun.map { !$0 },
                  refuseOwnTun: refuseOwnTun,
                  foreignTunnelPresent: refuseOwnTun,
                  systemPhase: systemPhase,
                  systemInstance: systemInstance)
        }

        public var foreignTunnelLikely: Bool {
            foreignTunnelPresent == true || refuseOwnTun == true || requireClearWouldPass == false
        }

        public var hasActiveInstance: Bool {
            systemPhase == "active" && systemInstance != nil
        }

        /// Clear enough to *attempt* app-path attestation (still needs authenticated evidence).
        public var clearWindowProvenForAttempt: Bool {
            windowID == clearWindowID
                && grantedInConversation
                && requireClearWouldPass == true
                && refuseOwnTun != true
                && foreignTunnelPresent != true
                && hasActiveInstance
        }
    }

    public enum CellOutcome: String, Equatable, Sendable {
        case blocked
        case refused
        case untested
        case livePassed
    }

    public struct CellAttestation: Equatable, Sendable {
        public let kind: RouterTrafficMatrix.CellKind
        public let label: String
        public let transport: String?
        public let family: String?
        public let outcome: CellOutcome
        public let reason: String
        public let gaps: [String]
        public let canPromoteAccepted: Bool
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let planDigest: String
        public let clearWindowID: String
        public let clearWindowGranted: Bool
        public let cells: [CellAttestation]
        public let applicationCellCount: Int
        public let blockedCount: Int
        public let refusedCount: Int
        public let untestedCount: Int
        public let livePassedCount: Int
        public let networkMutated: Bool
        public let canPromoteAccepted: Bool
        public let canClaimAppTrafficComplete: Bool
        public let summary: String
    }

    /// Decide a precise reason for one app / existing-connection inventory cell.
    public static func decide(kind: RouterTrafficMatrix.CellKind,
                              window: ClearWindowState,
                              evidence: RouterTrafficMatrixLiveRunner.CellEvidence?) -> (CellOutcome, String, [String]) {
        precondition(kind == .applicationTraffic || kind == .existingConnectionMigration)

        if let evidence, evidence.countsAsLivePass,
           window.clearWindowProvenForAttempt {
            return (.livePassed, "authenticated_app_path_evidence",
                    ["clear_window_granted", "collectorAuthenticated"])
        }
        if let evidence, evidence.routingVerified {
            return (.untested, "routing_verified_is_not_app_traffic_pass",
                    ["forged_or_premature_routing_verified_ignored", clearWindowID])
        }

        var gaps = [clearWindowID, "app_path_attestation_scaffolding"]

        if window.refuseOwnTun == true {
            return (.blocked, "app_traffic_blocked_refuseOwnTun",
                    gaps + ["refuseOwnTun_blocks_app_attestation", "no_silent_stop_of_peers"])
        }
        if window.requireClearWouldPass == false {
            return (.blocked, "app_traffic_blocked_requireClear_unmet",
                    gaps + ["requireClear_would_fail", "no_silent_stop_of_peers"])
        }
        if window.foreignTunnelPresent == true || window.foreignTunnelLikely {
            return (.blocked, "app_traffic_blocked_foreign_tunnel_clear_window",
                    gaps + ["foreign_tunnel_clear_window_required"])
        }
        if window.windowID != clearWindowID || !window.grantedInConversation {
            return (.blocked, "app_traffic_blocked_clear_window_unconfirmed",
                    gaps + ["conversation_grant_missing:\(clearWindowID)"])
        }
        if !window.hasActiveInstance {
            return (.refused, "app_traffic_refused_no_active_system_instance",
                    gaps + ["no_active_system_instance"])
        }
        // Window granted and clear, but no authenticated evidence yet.
        return (.untested, "app_traffic_untested_awaiting_authenticated_evidence",
                gaps + ["awaiting_authenticated_app_path_evidence", "canPromoteAccepted_false"])
    }

    public static func attest(plan: RouterPlan, profile: RouterSystemProfile,
                              window: ClearWindowState,
                              evidence: [RouterTrafficMatrixLiveRunner.CellEvidence] = []) throws -> Report {
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let evidenceIndex = Dictionary(
            evidence.map { ("\($0.kind.rawValue)|\($0.label)", $0) },
            uniquingKeysWith: { first, _ in first })
        let appCells = inventory.cells.filter {
            $0.kind == .applicationTraffic || $0.kind == .existingConnectionMigration
        }
        let attested: [CellAttestation] = appCells.map { cell in
            let (outcome, reason, extraGaps) = decide(
                kind: cell.kind, window: window,
                evidence: evidenceIndex["\(cell.kind.rawValue)|\(cell.label)"])
            return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                         family: cell.family, outcome: outcome, reason: reason,
                         gaps: Array(Set(cell.gaps + extraGaps)).sorted(),
                         canPromoteAccepted: false)
        }
        let blocked = attested.filter { $0.outcome == .blocked }.count
        let refused = attested.filter { $0.outcome == .refused }.count
        let untested = attested.filter { $0.outcome == .untested }.count
        let livePassed = attested.filter { $0.outcome == .livePassed }.count
        let summary: String
        if !window.grantedInConversation {
            summary = "应用流量矩阵取证脚手架：清场窗口 \(clearWindowID) 未授予；应用/已有连接格 blocked=\(blocked) refused=\(refused)；livePassed=\(livePassed)；canPromoteAccepted=false；未改网络。"
        } else if window.foreignTunnelLikely {
            summary = "应用流量矩阵取证脚手架：清场窗口已声明但仍有外隧道/requireClear 未过；blocked=\(blocked)；livePassed=\(livePassed)；canPromoteAccepted=false。"
        } else {
            summary = "应用流量矩阵取证脚手架：清场条件可尝试；untested=\(untested) livePassed=\(livePassed)（仅认证证据）；complete=false；canPromoteAccepted=false；未改网络。"
        }
        return .init(policyVersion: policyVersion, planDigest: inventory.planDigest,
                     clearWindowID: clearWindowID,
                     clearWindowGranted: window.grantedInConversation,
                     cells: attested, applicationCellCount: attested.count,
                     blockedCount: blocked, refusedCount: refused, untestedCount: untested,
                     livePassedCount: livePassed, networkMutated: false,
                     canPromoteAccepted: false, canClaimAppTrafficComplete: false,
                     summary: summary)
    }

    /// Map scaffolding outcome into live-runner cells for application / existing-connection kinds.
    public static func liveCell(from inventory: RouterTrafficMatrix.Cell,
                                window: ClearWindowState,
                                evidence: RouterTrafficMatrixLiveRunner.CellEvidence?) -> RouterTrafficMatrixLiveRunner.LiveCell {
        let (outcome, reason, extraGaps) = decide(kind: inventory.kind, window: window, evidence: evidence)
        let mapped: RouterTrafficMatrixLiveRunner.Outcome
        switch outcome {
        case .blocked: mapped = .blocked
        case .refused: mapped = .refused
        case .untested: mapped = .untested
        case .livePassed: mapped = .livePassed
        }
        return .init(kind: inventory.kind, label: inventory.label,
                     transport: inventory.transport, family: inventory.family,
                     outcome: mapped, reason: reason,
                     gaps: Array(Set(inventory.gaps + extraGaps)).sorted())
    }
}
