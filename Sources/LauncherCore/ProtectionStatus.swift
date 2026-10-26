import Foundation

/// A successful network probe is not authorization to start an unprotected client.
public enum StrictProtection {
    public static let verified = false
    public static let reason = "严格启动已锁定：实际代理链未验证，防火墙与断流守卫尚未完成。"
    public static let launchCommands: Set<String> = ["run", "desktop", "wrap", "official-desktop", "preflight-wrap"]

    public static func requireVerified() throws {
        throw LauncherError.message(reason)
    }
}

public struct ProtectionLayer: Identifiable {
    public let id: String
    public let title: String
    public let status: String
    public let detail: String
}

/// Presentation of the last sample, never an independent source of launch permission.
public struct ProtectionStatus {
    public let entrance: String
    public let observedExit: String
    public let checkedAt: Date?
    public let networkPassed: Bool
    public let networkStatus: String
    public let explanation: String
    /// Display only: end of the 30 s preflight window when this sample currently passes.
    public let validUntil: Date?
    /// Display only: how the topology/detail panel colours this sample. Never read by launch decisions.
    public let display: DisplayState
    public let layers: [ProtectionLayer]

    public init(report: PreflightReport?, settings: PreflightSettings,
                context: String?, checking: Bool, now: Date = Date(), firewall: PFObservation? = nil) {
        checkedAt = report?.completedAt
        entrance = report?.checks.first { $0.id == "transport" }?.detail ?? "尚未取得"
        let exits = Set(report?.observations.compactMap(\.ip) ?? []).sorted()
        observedExit = exits.isEmpty ? "尚未取得" : exits.joined(separator: " / ")
        let valid = report.map { $0.permits(context: context ?? "", now: now) && context != nil } ?? false
        networkPassed = valid && !checking
        validUntil = networkPassed ? report.map { $0.startedAt.addingTimeInterval(30) } : nil
        if checking {
            networkStatus = "检测中"
            display = .checking
            explanation = "正在重新检测；下面显示的是上一次的结果，不作为当前状态。"
        } else if let report {
            if now < report.startedAt || now.timeIntervalSince(report.startedAt) > 30 || report.completedAt > now {
                networkStatus = "已过期（超过 30 秒）"
                display = .expired
                explanation = "这次预检已超过 30 秒有效期或时间异常，结果作废。下一步：点“重新检测”。"
            } else if context == nil || context != report.context {
                networkStatus = "已过期（网络环境变化）"
                display = .expired
                explanation = "网络环境变化或尚未确认，旧结果作废。下一步：等待自动重新检测，或点“重新检测”。"
            } else if valid {
                networkStatus = "出口探测匹配（仅本轮）"
                display = .observed
                explanation = "仅表示本轮预检请求的出口与确认出口一致，30 秒内有效；不代表 Claude 的全部连接都受控，受保护启动仍锁定。"
            } else {
                networkStatus = "未通过"
                display = .failed
                explanation = (report.failures.first?.detail ?? "检查结果缺失或无效。") + " 下一步：在你的代理客户端客户端确认网络可用后点“重新检测”。"
            }
        } else {
            networkStatus = "未验证（尚未检测）"
            display = .unverified
            explanation = "尚未取得当前入口的检测结果。"
        }
        let matchingExits = networkPassed && report.map { r in
            r.observations.count == r.target.hosts.count &&
            Set(r.observations.map(\.host)) == Set(r.target.hosts) &&
            r.observations.allSatisfy { $0.check.result == .passed && $0.ip.map(settings.matches) == true }
        } == true
        let observedLayers = firewall?.layers(at: now) ?? PFObservation.unavailableLayers
        layers = [
            .init(id: "route", title: "① 路由与代理链", status: "未验证",
                  detail: "保持现有代理设置；入口可达不证明内部规则和实际会话链路。"),
            observedLayers[0], observedLayers[1],
            .init(id: "preflight", title: "④ 启动前检查", status: networkStatus,
                  detail: explanation),
            .init(id: "identity", title: "⑤ 出口身份", status: matchingExits ? "仅探测匹配" : "未验证",
                  detail: "目标域名采样与实际会话需分别验收；住宅属性、DNS／IPv6 旁路未验证。")
        ]
    }
}
