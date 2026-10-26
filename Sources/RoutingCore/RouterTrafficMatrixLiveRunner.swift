import Foundation

/// Live matrix attempt that never mutates the network and never invents livePassed.
/// Cells are attempted only when the system instance is active and requireClear would pass;
/// otherwise each cell is recorded as refused / blocked / untested with an honest reason.
public enum RouterTrafficMatrixLiveRunner {
    public static let policyVersion = 1

    public enum GateDecision: Equatable, Sendable {
        case allow(instance: UUID)
        case refuse(String)
    }

    public enum Outcome: String, Equatable, Sendable {
        /// Gate refused before any live attempt.
        case refused
        /// Needs an external clear window or independent capability (e.g. PF).
        case blocked
        /// Window open or inventory present, but no authenticated live evidence yet.
        case untested
        /// Independent system layer still missing.
        case capabilityGap
        /// Only set when authenticated live evidence is supplied for that cell.
        case livePassed
    }

    public struct Context: Equatable, Sendable {
        public let systemPhase: String?
        public let systemInstance: UUID?
        public let refuseOwnTun: Bool?
        /// Explicit mirror of `RouterSystemProvider.requireClear` outcome when known.
        /// `nil` falls back to `refuseOwnTun != true` (still not a silent clear).
        public let requireClearWouldPass: Bool?
        /// Conversation clear-window grant for app-path cells (`tun-apply-clear-window-v1`).
        /// Production default stays false — never invents confirmation.
        public let clearWindowGrantedInConversation: Bool

        public init(systemPhase: String?, systemInstance: UUID?,
                    refuseOwnTun: Bool?, requireClearWouldPass: Bool? = nil,
                    clearWindowGrantedInConversation: Bool = false) {
            self.systemPhase = systemPhase
            self.systemInstance = systemInstance
            self.refuseOwnTun = refuseOwnTun
            self.requireClearWouldPass = requireClearWouldPass
            self.clearWindowGrantedInConversation = clearWindowGrantedInConversation
        }

        public var appTrafficClearWindow: RouterAppTrafficMatrixAttestation.ClearWindowState {
            .init(grantedInConversation: clearWindowGrantedInConversation,
                  requireClearWouldPass: requireClearWouldPass ?? refuseOwnTun.map { !$0 },
                  refuseOwnTun: refuseOwnTun,
                  foreignTunnelPresent: refuseOwnTun,
                  systemPhase: systemPhase,
                  systemInstance: systemInstance)
        }
    }

    /// Authenticated per-cell evidence. Production UI/IPC must not fabricate this.
    /// `routingVerified` must stay false; a true flag is ignored and never counts as livePassed.
    public struct CellEvidence: Equatable, Sendable {
        public let kind: RouterTrafficMatrix.CellKind
        public let label: String
        public let collectorAuthenticated: Bool
        public let routingVerified: Bool

        public init(kind: RouterTrafficMatrix.CellKind, label: String,
                    collectorAuthenticated: Bool, routingVerified: Bool = false) {
            self.kind = kind
            self.label = label
            self.collectorAuthenticated = collectorAuthenticated
            self.routingVerified = routingVerified
        }

        /// Live pass needs an authenticated collector and must not lean on routing_verified.
        public var countsAsLivePass: Bool {
            collectorAuthenticated && !routingVerified
        }
    }

    public struct LiveCell: Equatable, Sendable {
        public let kind: RouterTrafficMatrix.CellKind
        public let label: String
        public let transport: String?
        public let family: String?
        public let outcome: Outcome
        public let reason: String
        public let gaps: [String]
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let planDigest: String
        public let gate: GateDecision
        public let cells: [LiveCell]
        public let applicationCaseCount: Int
        public let controlPlaneCaseCount: Int
        public let livePassedCount: Int
        public let refusedCount: Int
        public let blockedCount: Int
        public let untestedCount: Int
        public let canClaimMatrixComplete: Bool
        public let networkMutated: Bool
        public let acceptedWritten: Bool
        public let summary: String
    }

    public static func decideGate(_ context: Context) -> GateDecision {
        if context.refuseOwnTun == true {
            return .refuse("refuseOwnTun_blocks_live_matrix")
        }
        if context.requireClearWouldPass == false {
            return .refuse("requireClear_would_fail")
        }
        guard context.systemPhase == "active", let instance = context.systemInstance else {
            return .refuse("no_active_system_instance")
        }
        // requireClearWouldPass == nil with refuseOwnTun != true: allow inventory remapping
        // only; still no silent claim that the network is clear for TUN apply.
        return .allow(instance: instance)
    }

    public static func run(plan: RouterPlan, profile: RouterSystemProfile,
                           context: Context,
                           evidence: [CellEvidence] = []) throws -> Report {
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let gate = decideGate(context)
        let evidenceIndex = Dictionary(
            evidence.map { ("\($0.kind.rawValue)|\($0.label)", $0) },
            uniquingKeysWith: { first, _ in first })

        let cells: [LiveCell] = inventory.cells.map { cell in
            remap(cell, gate: gate, context: context,
                  evidence: evidenceIndex["\(cell.kind.rawValue)|\(cell.label)"])
        }
        let livePassed = cells.filter { $0.outcome == .livePassed }.count
        // Never claim complete: production evidence path cannot set routing_verified.
        let complete = false
        let refused = cells.filter { $0.outcome == .refused }.count
        let blocked = cells.filter { $0.outcome == .blocked }.count
        let untested = cells.filter { $0.outcome == .untested }.count
        let summary: String
        switch gate {
        case .refuse(let reason):
            summary = "流量矩阵 live runner 拒绝执行（\(reason)）：已诚实标记 refused/blocked/untested；livePassed=\(livePassed)；未改网络、未写 accepted。"
        case .allow:
            summary = "流量矩阵 live 窗口开启（active+清场门禁未挡）：逐格结果已记录；livePassed=\(livePassed) 仅计认证证据；complete=false；未改网络、未写 accepted。"
        }
        return .init(policyVersion: policyVersion, planDigest: inventory.planDigest, gate: gate,
                     cells: cells, applicationCaseCount: inventory.applicationCaseCount,
                     controlPlaneCaseCount: inventory.controlPlaneCaseCount,
                     livePassedCount: livePassed, refusedCount: refused, blockedCount: blocked,
                     untestedCount: untested, canClaimMatrixComplete: complete,
                     networkMutated: false, acceptedWritten: false, summary: summary)
    }

    private static func remap(_ cell: RouterTrafficMatrix.Cell, gate: GateDecision,
                              context: Context, evidence: CellEvidence?) -> LiveCell {
        switch cell.kind {
        case .applicationTraffic, .existingConnectionMigration:
            // App-path cells always go through clear-window scaffolding; evidence alone
            // cannot invent livePassed without tun-apply-clear-window-v1.
            return RouterAppTrafficMatrixAttestation.liveCell(
                from: cell, window: context.appTrafficClearWindow, evidence: evidence)
        case .coreExitFailClosed:
            return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                         family: cell.family, outcome: .capabilityGap,
                         reason: "pf_arming_not_confirmed",
                         gaps: cell.gaps + ["pf_preview_only_until_user_confirms"])
        case .foreignTunnelCoexistence:
            if context.refuseOwnTun == true || context.requireClearWouldPass == false {
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .blocked,
                             reason: "foreign_tunnel_or_proxy_clear_window_required",
                             gaps: cell.gaps)
            }
            switch gate {
            case .refuse(let reason):
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .blocked, reason: reason, gaps: cell.gaps)
            case .allow:
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .untested,
                             reason: "clear_window_open_coexistence_not_revalidated_as_traffic_pass",
                             gaps: cell.gaps + ["not_live_matrix_pass"])
            }
        case .controlPlaneDNS:
            if let evidence, evidence.kind == cell.kind, evidence.label == cell.label {
                if evidence.countsAsLivePass {
                    return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                                 family: cell.family, outcome: .livePassed,
                                 reason: "authenticated_live_evidence",
                                 gaps: cell.gaps.filter { $0 != "not_live_matrix_pass" })
                }
                if evidence.routingVerified {
                    return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                                 family: cell.family, outcome: .untested,
                                 reason: "routing_verified_is_not_live_matrix_pass",
                                 gaps: cell.gaps + ["forged_or_premature_routing_verified_ignored"])
                }
            }
            switch gate {
            case .refuse(let reason):
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .refused, reason: reason,
                             gaps: cell.gaps + ["live_attempt_refused"])
            case .allow:
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .untested,
                             reason: "live_window_open_per_cell_probe_pending",
                             gaps: cell.gaps + ["awaiting_authenticated_cell_evidence"])
            }
        }
    }
}
