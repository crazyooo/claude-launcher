import Foundation

/// TUN / network restore side-effects behind `RouterAcceptedRollbackExecuteGate`.
///
/// Production path requires **all** of:
/// 1. ExecuteGate allow (sealed preview + confirm + reobservation)
/// 2. Source is our sealed `previousAccepted` (not a foreign digest)
/// 3. Conversation clear window `tun-apply-clear-window-v1` granted
/// 4. `requireClear` proven / no foreign tunnel / refuseOwnTun != true
/// 5. Explicit `userConfirmedNetworkRestore`
///
/// When (1)–(5) hold and `SideEffects.restoreOwnTun` is injected, effects run and
/// `tunEffectsWired=true` with `networkModified` from the outcome. Without effects,
/// the path stays structured-ready / unwired. Historical digests never become a
/// new success or accepted write.
public enum RouterAcceptedRollbackRestore {
    public static let policyVersion = 3
    public static let clearWindowID = RouterTunApplyExecuteGate.clearWindowID

    public struct SideEffects: Sendable {
        public struct Outcome: Equatable, Sendable {
            public let networkModified: Bool
            public let detail: String
            public init(networkModified: Bool, detail: String) {
                self.networkModified = networkModified
                self.detail = detail
            }
        }

        public var restoreOwnTun: (@Sendable (Intent) throws -> Outcome)?

        public init(restoreOwnTun: (@Sendable (Intent) throws -> Outcome)? = nil) {
            self.restoreOwnTun = restoreOwnTun
        }

        public static let unwired = SideEffects(restoreOwnTun: nil)
    }

    public struct Intent: Equatable, Sendable {
        public let previewID: UUID
        public let source: RouterAcceptedRollback.SourceKind
        public let historicalConfigurationDigest: String
        public let historicalEvidenceDigest: String
        public let userConfirmedNetworkRestore: Bool
        public let clearWindow: RouterTunApplyExecuteGate.ClearWindowGrant

        public init(preview: RouterAcceptedRollback.Preview,
                    userConfirmedNetworkRestore: Bool = false,
                    clearWindow: RouterTunApplyExecuteGate.ClearWindowGrant = .none) {
            previewID = preview.id
            source = preview.source
            historicalConfigurationDigest = preview.historicalConfigurationDigest
            historicalEvidenceDigest = preview.historicalEvidenceDigest
            self.userConfirmedNetworkRestore = userConfirmedNetworkRestore
            self.clearWindow = clearWindow
        }

        /// Our sealed previousAccepted pointer — not a foreign or current-only digest.
        public var previousAcceptedIsOurs: Bool {
            source == .previousAccepted
        }
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let previewID: UUID
        public let gateReason: String
        public let gateAllowed: Bool
        public let executed: Bool
        public let networkModified: Bool
        public let tunEffectsWired: Bool
        public let canAttemptTunRestore: Bool
        public let previousAcceptedIsOurs: Bool
        public let clearWindowGranted: Bool
        public let journalMutated: Bool
        public let historicalDigestTreatedAsNewSuccess: Bool
        public let dimensions: [RouterAcceptedRollback.Dimension]
        public let reason: String
        public let summary: String
    }

    /// Apply restore planning / refuse behind a gate report. Safe by default: no mutation.
    public static func apply(gate: RouterAcceptedRollbackExecuteGate.Report,
                             preview: RouterAcceptedRollback.Preview,
                             intent: Intent,
                             observation: RouterAcceptedRollbackExecuteGate.Observation,
                             sideEffects: SideEffects = .unwired) -> Report {
        guard intent.previewID == preview.id, intent.previewID == gate.previewID else {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "preview_identity_mismatch", observation: observation)
        }
        guard intent.historicalConfigurationDigest == preview.historicalConfigurationDigest,
              intent.historicalEvidenceDigest == preview.historicalEvidenceDigest,
              intent.source == preview.source else {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "historical_digest_mismatch", observation: observation)
        }
        if preview.historicalSuccessTransfersToNewInstance {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "historical_digest_reuse_forbidden", observation: observation)
        }

        switch gate.decision {
        case .refuse(let reason):
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: reason, observation: observation)
        case .allow:
            break
        }

        if !intent.previousAcceptedIsOurs {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "previousAccepted_not_ours", observation: observation)
        }

        if intent.clearWindow.windowID != clearWindowID
            || !intent.clearWindow.grantedInConversation {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "clear_window_not_confirmed_in_conversation",
                           observation: observation)
        }

        if observation.foreignTunnelLikely || observation.refuseOwnTun == true
            || observation.requireClearWouldPass != true {
            return refused(preview: preview, gate: gate, intent: intent,
                           reason: "foreign_tunnel_or_clear_not_met_for_restore",
                           observation: observation)
        }

        let canAttempt = intent.userConfirmedNetworkRestore

        let config = RouterAcceptedRollback.Dimension(
            name: "configurationRestore",
            status: "candidate_validated_not_staged",
            detail: "自有 previousAccepted 配置 \(preview.historicalConfigurationDigest.prefix(12))… 已对照预览；未写 stage/journal。")
        let process = RouterAcceptedRollback.Dimension(
            name: "processRestore",
            status: "requires_new_instance_not_started",
            detail: "历史进程身份不转移；未启动/停止任何内核。")
        let network: RouterAcceptedRollback.Dimension
        let tun: RouterAcceptedRollback.Dimension
        let reason: String
        let networkModified: Bool
        let tunEffectsWired: Bool
        let executed: Bool

        if !canAttempt {
            network = .init(
                name: "networkCleanup",
                status: "clear_proven_awaiting_user_network_confirm",
                detail: "清场窗口已授予且 requireClear 可通过；未获 userConfirmedNetworkRestore；不改网络。")
            tun = .init(
                name: "tunRestore",
                status: "awaiting_userConfirmedNetworkRestore",
                detail: "TUN 恢复副作用未触发；须显式网络恢复确认后才可谈接线。")
            reason = "restore_planned_awaiting_network_confirm"
            networkModified = false
            tunEffectsWired = false
            executed = false
        } else if let restore = sideEffects.restoreOwnTun {
            do {
                let outcome = try restore(intent)
                network = .init(
                    name: "networkCleanup",
                    status: outcome.networkModified ? "effects_reported_network_modified" : "effects_ran_no_network_claim",
                    detail: outcome.detail)
                tun = .init(
                    name: "tunRestore",
                    status: "effects_invoked",
                    detail: "restoreOwnTun 已调用；tunEffectsWired=true；旧 digest ≠ 新成功。")
                reason = "restore_tun_effects_invoked"
                networkModified = outcome.networkModified
                tunEffectsWired = true
                executed = true
            } catch {
                network = .init(
                    name: "networkCleanup", status: "effects_failed",
                    detail: "restoreOwnTun 抛错：\(error)；按未改网记账。")
                tun = .init(
                    name: "tunRestore", status: "effects_failed",
                    detail: "副作用失败；tunEffectsWired=true（已尝试）；networkModified=false。")
                reason = "restore_tun_effects_failed"
                networkModified = false
                tunEffectsWired = true
                executed = false
            }
        } else {
            network = .init(
                name: "networkCleanup",
                status: "preconditions_met_effects_unwired",
                detail: "清场+\(clearWindowID)+userConfirmedNetworkRestore 均满足；未注入 restoreOwnTun；networkModified=false。")
            tun = .init(
                name: "tunRestore",
                status: "structured_ready_effects_unwired",
                detail: "TUN 恢复路径已结构化；tunEffectsWired=false；不得声称恢复完成。")
            reason = "restore_structured_ready_tun_effects_unwired"
            networkModified = false
            tunEffectsWired = false
            executed = false
        }
        let traffic = RouterAcceptedRollback.Dimension(
            name: "trafficReacceptance",
            status: "required_not_started",
            detail: "旧 evidence \(preview.historicalEvidenceDigest.prefix(12))… 不是新成功；须新流量验收。")

        return .init(
            policyVersion: policyVersion, previewID: preview.id,
            gateReason: gate.reason, gateAllowed: true, executed: executed,
            networkModified: networkModified, tunEffectsWired: tunEffectsWired,
            canAttemptTunRestore: canAttempt, previousAcceptedIsOurs: true,
            clearWindowGranted: true, journalMutated: false,
            historicalDigestTreatedAsNewSuccess: false,
            dimensions: [config, process, network, tun, traffic],
            reason: reason,
            summary: tunEffectsWired
                ? "回退 TUN 恢复副作用已调用（tunEffectsWired=true · networkModified=\(networkModified) · executed=\(executed)）；旧 digest ≠ 新成功；未写 accepted。"
                : (canAttempt
                    ? "回退 TUN 恢复路径已结构化（自有 previousAccepted+清场+确认）；tunEffectsWired=false · networkModified=false；旧 digest ≠ 新成功；未写 accepted。"
                    : "回退恢复已分项规划（配置候选/进程未启/TUN 待确认/流量待验）。清场已授予；networkModified=false；旧 digest ≠ 新成功。"))
    }

    private static func refused(preview: RouterAcceptedRollback.Preview,
                                gate: RouterAcceptedRollbackExecuteGate.Report,
                                intent: Intent,
                                reason: String,
                                observation: RouterAcceptedRollbackExecuteGate.Observation) -> Report {
        let dimensions = [
            RouterAcceptedRollback.Dimension(
                name: "configurationRestore", status: "refused",
                detail: "未校验配置候选 · \(reason)"),
            RouterAcceptedRollback.Dimension(
                name: "processRestore", status: "refused",
                detail: "未触碰进程 · \(reason)"),
            RouterAcceptedRollback.Dimension(
                name: "networkCleanup", status: "refused",
                detail: "未改网络（refuseOwnTun=\(observation.refuseOwnTun.map(String.init(describing:)) ?? "nil") clearGrant=\(intent.clearWindow.grantedInConversation)）· \(reason)"),
            RouterAcceptedRollback.Dimension(
                name: "tunRestore", status: "refused",
                detail: "TUN 恢复未执行 · \(reason)；window=\(clearWindowID)"),
            RouterAcceptedRollback.Dimension(
                name: "trafficReacceptance", status: "refused",
                detail: "未开始流量复验 · \(reason)")
        ]
        return .init(
            policyVersion: policyVersion, previewID: preview.id,
            gateReason: gate.reason, gateAllowed: false, executed: false,
            networkModified: false, tunEffectsWired: false,
            canAttemptTunRestore: false,
            previousAcceptedIsOurs: intent.previousAcceptedIsOurs,
            clearWindowGranted: intent.clearWindow.grantedInConversation,
            journalMutated: false, historicalDigestTreatedAsNewSuccess: false,
            dimensions: dimensions, reason: reason,
            summary: "回退 TUN 恢复拒绝（\(reason)）。未改网络、未写 journal/accepted；tunEffectsWired=false；旧 digest ≠ 新成功。")
    }
}
