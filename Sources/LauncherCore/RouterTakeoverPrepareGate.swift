import Foundation

/// UI-side gate before requesting system prepare. Does not replace server-side requireClear.
public enum RouterTakeoverPrepareGate {
    public struct Decision: Equatable, Sendable {
        public let allowed: Bool
        public let message: String
        public init(allowed: Bool, message: String) {
            self.allowed = allowed; self.message = message
        }
    }

    public static func decide(sessionCanPrepare: Bool, editorBusy: Bool,
                              brief: RouterCoexistenceBrief.Report?) -> Decision {
        if editorBusy {
            return .init(allowed: false, message: "规划仍在读写；稍后再生成变更预览。")
        }
        if !sessionCanPrepare {
            return .init(allowed: false, message: "系统组件状态尚不允许生成预览；请先查询状态并保存有效规划。")
        }
        guard let brief else {
            return .init(allowed: false, message: "请先点「检查现有网络」。生成预览前须只读核对隧道、系统代理与当前走线；这不会改网络。")
        }
        if brief.refuseOwnTun {
            let head = brief.reasons.first ?? "当前条件会拒绝启用本工具 TUN。"
            return .init(allowed: false,
                         message: "不会发送接管预览请求。" + head + " 不会自动停止你的代理客户端；可用路径对照测线路，或你自行让开外部隧道后再检查。")
        }
        return .init(allowed: true,
                     message: "只读观察未看到已知 requireClear 阻挡项；仍须系统组件正式预览，且不表示已接管或 accepted。")
    }
}
