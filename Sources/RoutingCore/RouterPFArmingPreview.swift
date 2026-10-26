import Foundation

/// Packet-filter fail-closed arming **preview** and confirmation protocol.
/// Does not install PF, change anchors, routes, IPv6, or touch 你的代理客户端/小火箭.
/// Execute always refuses until an explicit user confirmation token from a live
/// conversation is presented — that token has not been issued in this product session.
public enum RouterPFArmingPreview {
    public static let policyVersion = 1
    /// Placeholder policy id. Real arming requires a user-issued confirmation matching this window.
    public static let confirmationWindowID = "pf-arming-user-confirm-v1"

    public struct Preview: Equatable, Sendable {
        public let policyVersion: Int
        public let designedLayer: RouterCoreExitFailClosed.SystemLayerKind
        public let subjectCount: Int
        public let wouldMutateNetwork: Bool
        public let armed: Bool
        public let confirmationWindowID: String
        public let requiredConfirmations: [String]
        public let summary: String
    }

    public struct ExecuteResult: Equatable, Sendable {
        public let armed: Bool
        public let networkMutated: Bool
        public let reason: String
        public let summary: String
    }

    public static func preview(plan: RouterPlan) -> Preview {
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        return .init(
            policyVersion: policyVersion,
            designedLayer: recipe.designedLayer,
            subjectCount: recipe.subjects.count,
            wouldMutateNetwork: true,
            armed: false,
            confirmationWindowID: confirmationWindowID,
            requiredConfirmations: [
                "explicit_user_confirm_pf_arming_in_this_conversation",
                "acknowledge_independent_anchor_default_deny_mutation",
                "acknowledge_no_auto_stop_of_longmaoyun_or_shadowrocket",
                "post_exit_traffic_block_reobservation_required"
            ],
            summary: "PF 断流武装仅有预览：设计层 \(recipe.designedLayer.rawValue)，subjects=\(recipe.subjects.count)。armed=false；执行会改系统 packet-filter，须你在本对话明确确认 \(confirmationWindowID)。未确认前不安装 PF。")
    }

    /// Legacy preview execute. Accepts only the sealed conversation window id after
    /// `RouterConversationPFArming` grant; still never loads PF rules (effects unwired).
    public static func execute(plan: RouterPlan, confirmationToken: String?) -> ExecuteResult {
        let preview = preview(plan: plan)
        guard let confirmationToken, !confirmationToken.isEmpty else {
            return .init(armed: false, networkMutated: false,
                         reason: "pf_arming_confirmation_missing",
                         summary: "PF 武装拒绝：缺少确认令牌。未改网络。窗口 \(preview.confirmationWindowID)。")
        }
        guard RouterConversationPFArming.isGranted,
              confirmationToken == preview.confirmationWindowID else {
            return .init(armed: false, networkMutated: false,
                         reason: "pf_arming_not_confirmed_in_conversation",
                         summary: "PF 武装拒绝：本对话尚未授予 \(preview.confirmationWindowID) 或令牌不匹配；未安装 PF、未改网络。")
        }
        return .init(armed: false, networkMutated: false,
                     reason: "gates_passed_pf_effects_unwired",
                     summary: "本对话已授予 \(preview.confirmationWindowID)；legacy 预览令牌匹配。PF 副作用未接线：armed=false · networkMutated=false；未写 accepted。")
    }
}
