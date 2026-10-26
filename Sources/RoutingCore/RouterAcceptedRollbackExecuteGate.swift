import Foundation

/// Production rollback **execute** gate. Requires a sealed fresh preview, explicit UI
/// confirmation, and a post-confirm re-observation. Refuses when a foreign tunnel /
/// refuseOwnTun / requireClear failure is present. Never treats historical digests as
/// new success. Never mutates TUN/routes/PF/你的代理客户端; restore side-effects stay unwired
/// until a clear apply window exists.
public enum RouterAcceptedRollbackExecuteGate {
    public static let policyVersion = 1

    public struct Observation: Equatable, Sendable {
        public let refuseOwnTun: Bool?
        public let requireClearWouldPass: Bool?
        public let systemPhase: String?
        public let observedAt: Date
        public let fingerprint: String?

        public init(refuseOwnTun: Bool?, requireClearWouldPass: Bool?,
                    systemPhase: String?, observedAt: Date = Date(),
                    fingerprint: String? = nil) {
            self.refuseOwnTun = refuseOwnTun
            self.requireClearWouldPass = requireClearWouldPass
            self.systemPhase = systemPhase
            self.observedAt = observedAt
            self.fingerprint = fingerprint
        }

        public var foreignTunnelLikely: Bool {
            refuseOwnTun == true || requireClearWouldPass == false
        }
    }

    /// Explicit in-product UI confirmation bound to one preview id.
    public struct Confirmation: Equatable, Sendable {
        public let previewID: UUID
        public let confirmedAt: Date
        public let explicitUIConfirm: Bool

        public init(previewID: UUID, confirmedAt: Date = Date(), explicitUIConfirm: Bool) {
            self.previewID = previewID
            self.confirmedAt = confirmedAt
            self.explicitUIConfirm = explicitUIConfirm
        }
    }

    public enum Decision: Equatable, Sendable {
        case allow
        case refuse(String)
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let previewID: UUID
        public let decision: Decision
        public let executed: Bool
        public let networkModified: Bool
        public let journalMutated: Bool
        public let historicalDigestTreatedAsNewSuccess: Bool
        public let dimensions: [RouterAcceptedRollback.Dimension]
        public let reason: String
        public let summary: String
    }

    public static func decide(preview: RouterAcceptedRollback.Preview,
                              arming: RouterAcceptedRollback.ExecuteArming?,
                              confirmation: Confirmation?,
                              before: Observation,
                              after: Observation,
                              now: Date = Date()) -> Decision {
        guard preview.isFresh(now: now) else {
            return .refuse("stale_preview")
        }
        guard !preview.historicalSuccessTransfersToNewInstance else {
            return .refuse("historical_digest_reuse_forbidden")
        }
        guard let arming, arming.isValid(now: now), arming.previewID == preview.id else {
            return .refuse("execute_disarmed")
        }
        guard arming.kind == .productionGuardedExecute else {
            return .refuse("arming_kind_not_guarded_execute")
        }
        guard let confirmation, confirmation.explicitUIConfirm,
              confirmation.previewID == preview.id,
              confirmation.confirmedAt >= preview.issuedAt,
              confirmation.confirmedAt <= now else {
            return .refuse("explicit_ui_confirm_required")
        }
        // Re-observation must follow confirmation.
        guard after.observedAt >= confirmation.confirmedAt else {
            return .refuse("reobservation_before_confirm")
        }
        if before.foreignTunnelLikely || after.foreignTunnelLikely {
            return .refuse("foreign_tunnel_or_refuseOwnTun")
        }
        if before.requireClearWouldPass == false || after.requireClearWouldPass == false {
            return .refuse("requireClear_would_fail")
        }
        if before.refuseOwnTun == true || after.refuseOwnTun == true {
            return .refuse("refuseOwnTun_blocks_rollback_execute")
        }
        // Fingerprints, when both present, must match across the confirm window.
        if let a = before.fingerprint, let b = after.fingerprint, a != b {
            return .refuse("reobservation_fingerprint_changed")
        }
        // Clear path still required for any future mutation; nil means unknown → refuse mutation path.
        guard after.requireClearWouldPass == true, after.refuseOwnTun != true else {
            return .refuse("clear_window_not_proven")
        }
        return .allow
    }

    /// Production execute entry. On refuse or allow: never modifies the network.
    /// Allow only means the gate passed; restore side-effects remain unwired.
    public static func execute(preview: RouterAcceptedRollback.Preview,
                               arming: RouterAcceptedRollback.ExecuteArming?,
                               confirmation: Confirmation?,
                               before: Observation,
                               after: Observation,
                               now: Date = Date()) throws -> Report {
        try RouterAcceptedRollback.requireFresh(preview, now: now)
        let decision = decide(preview: preview, arming: arming, confirmation: confirmation,
                              before: before, after: after, now: now)
        switch decision {
        case .refuse(let reason):
            let dimensions = preview.dimensions.map {
                RouterAcceptedRollback.Dimension(
                    name: $0.name, status: "refused",
                    detail: "\($0.detail) · gate=\(reason)")
            }
            return .init(policyVersion: policyVersion, previewID: preview.id, decision: decision,
                         executed: false, networkModified: false, journalMutated: false,
                         historicalDigestTreatedAsNewSuccess: false, dimensions: dimensions,
                         reason: reason,
                         summary: "回退执行拒绝（\(reason)）。未改网络、未写 journal/accepted；旧 digest ≠ 新成功。")
        case .allow:
            let dimensions = [
                RouterAcceptedRollback.Dimension(
                    name: "configurationRestore", status: "gate_passed_unwired",
                    detail: "门禁通过；配置恢复副作用未接线，未写 stage/journal。"),
                RouterAcceptedRollback.Dimension(
                    name: "processRestore", status: "gate_passed_unwired",
                    detail: "门禁通过；进程恢复未执行。"),
                RouterAcceptedRollback.Dimension(
                    name: "networkCleanup", status: "gate_passed_no_mutation",
                    detail: "门禁通过且 requireClear 显示可通过；本路径仍不改 TUN/路由/PF/你的代理客户端。"),
                RouterAcceptedRollback.Dimension(
                    name: "trafficReacceptance", status: "required",
                    detail: "历史 evidence 不转移；须新流量验收后才能谈 accepted。")
            ]
            return .init(policyVersion: policyVersion, previewID: preview.id, decision: .allow,
                         executed: false, networkModified: false, journalMutated: false,
                         historicalDigestTreatedAsNewSuccess: false, dimensions: dimensions,
                         reason: "gates_passed_restore_effects_unwired",
                         summary: "回退执行门禁已通过（密封预览+显式确认+复验+清场）。恢复副作用未接线；networkModified=false；旧 digest ≠ 新成功。")
        }
    }
}
