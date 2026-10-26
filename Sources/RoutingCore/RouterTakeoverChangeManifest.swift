import Foundation

/// Exact, user-facing description of what a prepared system apply would change.
/// Does not authorize apply, does not promote accepted, and does not stop foreign tunnels.
public enum RouterTakeoverChangeManifest {
    public struct Report: Equatable, Sendable {
        public let digest: String
        public let bullets: [String]
        public let confirmationSummary: String
        public let requiresExplicitUserConfirm: Bool
        public let requiresClearNetwork: Bool
        public let routingVerified: Bool
        public let accepted: Bool
        public init(digest: String, bullets: [String], confirmationSummary: String,
                    requiresExplicitUserConfirm: Bool = true, requiresClearNetwork: Bool = true,
                    routingVerified: Bool = false, accepted: Bool = false) {
            self.digest = digest
            self.bullets = bullets
            self.confirmationSummary = confirmationSummary
            self.requiresExplicitUserConfirm = true
            self.requiresClearNetwork = true
            self.routingVerified = false
            self.accepted = false
            _ = requiresExplicitUserConfirm
            _ = requiresClearNetwork
            _ = routingVerified
            _ = accepted
        }
    }

    public static func make(plan: RouterPlan, profile: RouterSystemProfile, digest: String) -> Report {
        let credentials = plan.proxies.compactMap(\.credentialReference).count
        let defaultName: String
        switch plan.defaultDestination.kind {
        case .direct: defaultName = "直连"
        case .block: defaultName = "阻断"
        case .proxy:
            if let id = plan.defaultDestination.proxyID,
               let proxy = plan.proxies.first(where: { $0.id == id }) {
                defaultName = "线路「\(proxy.name)」"
            } else {
                defaultName = "代理（引用待核）"
            }
        }
        var bullets: [String] = [
            "仅在你确认「应用配置」后才会改动本机网络；生成预览本身不创建 TUN。",
            "将为本工具创建自有 TUN（含 IPv6 \(RouterSystemCompiler.tunIPv6)）、相关路由，以及对 TCP/UDP 53 的 DNS 拦截。",
            "DNS 使用 \(profile.resolver.rawValue)，enhanced-mode fake-ip：\(RouterSystemCompiler.fakeIPv4) / \(RouterSystemCompiler.fakeIPv6)。",
            "将按已保存规划加载 \(plan.proxies.count) 条线路、\(plan.rules.count) 条规则；其他连接默认去向：\(defaultName)。",
            "将解析 \(credentials) 个钥匙串凭据引用写入私有运行配置；凭据不会进入 journal 或页面原文。",
            "配置摘要 \(digest.prefix(16))… · 策略版本 \(RouterSystemCompiler.policyVersion) · 固定核心 \(RouterCoreRelease.version)。",
            "应用瞬间仍会再次执行 requireClear：外部隧道转发、系统应用/自动代理、已连接 VPN 或自有内核未知时会拒绝，不会静默覆盖你的代理客户端/小火箭。",
            "不会自动停止其他代理；已有连接、浏览器 helper、实际出口命中仍待验收。",
            "journal 的 accepted / previousAccepted 仅在证据门禁放行后写入；无证据或假摘要仍拒绝。本清单不能提升 routing_verified 或 accepted。",
            "内核退出后的严格断流：\(RouterCoreExitFailClosed.productionGap(for: plan).summary)",
            (try? RouterTrafficMatrix.report(plan: plan, profile: profile).summary)
                ?? "流量矩阵：规划校验失败，无法枚举必需用例。",
            "回退：若存在 sealed previousAccepted，须重新预览；配置/进程/网络/流量分项报告；旧 digest ≠ 新成功；生产执行不改网。"
        ]
        if RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) {
            bullets.insert("当前规划仍有校验错误；系统 prepare 应拒绝。请先修正规划。", at: 0)
        }
        let confirmation = bullets.prefix(6).joined(separator: "\n")
            + "\n\n确认即请求 apply。这不是分流验收通过，也不会写入 accepted。"
        return .init(digest: digest, bullets: bullets, confirmationSummary: confirmation)
    }
}
