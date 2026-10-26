import Foundation

public enum EnvironmentTarget: String, Codable, CaseIterable, Identifiable {
    case desktop, cli, diagnostic
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .desktop: return "桌面聊天"
        case .cli: return "独立 CLI"
        case .diagnostic: return "指定代理诊断"
        }
    }
    public var hosts: [String] {
        self == .desktop ? ["claude.ai", "platform.claude.com"] : ["claude.ai", "api.anthropic.com", "platform.claude.com"]
    }
    var serviceHost: String { self == .desktop ? "claude.ai" : "api.anthropic.com" }
}

public enum EnvironmentRouteSource: String, Codable {
    case systemProxySelection, terminalConfiguration, explicitDiagnosticProxy
    case systemNetworkRoute, noProxyBypass, unresolved
    public var title: String {
        switch self {
        case .systemProxySelection: return "系统为此域名选择的代理"
        case .terminalConfiguration: return "本次终端配置"
        case .explicitDiagnosticProxy: return "指定诊断入口"
        case .systemNetworkRoute: return "系统网络路由（可能经过 VPN/TUN）"
        case .noProxyBypass: return "此域名命中 NO_PROXY"
        case .unresolved: return "路径尚未确定"
        }
    }
}

public struct EnvironmentCheck: Codable, Identifiable {
    public let id: String
    public let title: String
    public let result: CheckResult
    public let required: Bool
    public let code: String
    public let detail: String

    public init(_ id: String, _ title: String, _ result: CheckResult, required: Bool = true,
                code: String, _ detail: String) {
        self.id = id; self.title = title; self.result = result
        self.required = required; self.code = code; self.detail = detail
    }
}

public struct EnvironmentObservation: Codable, Identifiable {
    public var id: String { host }
    public let host: String
    public let ip: String?
    public let country: String?
    public let transport: String
    public let source: EnvironmentRouteSource
    public let milliseconds: Int

    public init(host: String, ip: String?, country: String?, transport: String,
                source: EnvironmentRouteSource, milliseconds: Int) {
        self.host = host; self.ip = ip; self.country = country
        self.transport = transport; self.source = source; self.milliseconds = milliseconds
    }
}

public enum EnvironmentRecommendation: String, Codable {
    case ready, attention, unknown, stale
    public var title: String {
        switch self {
        case .ready: return "检查通过"
        case .attention: return "发现问题"
        case .unknown, .stale: return "尚未测全"
        }
    }
    public var detail: String {
        switch self {
        case .ready: return "本轮网络检测通过，可自行尝试使用；这不是账号、业务可用性或 Claude 实际流量路径的证明。"
        case .attention: return "检测发现明确异常。请按错误提示自行处理，再重新检测。"
        case .unknown: return "部分必要证据尚未取得。请查看未确认项目；没有启动或修改任何客户端。"
        case .stale: return "检测结果已过期或环境已变化。请重新检测，历史记录不能代表现在。"
        }
    }
}

/// A snapshot of diagnostic requests, with no launch or network-control capability.
public struct EnvironmentReport: Codable, Identifiable {
    public let version: Int
    public let id: UUID
    public let target: EnvironmentTarget
    public let startedAt: Date
    public let completedAt: Date
    public let networkFingerprint: String
    public let configurationFingerprint: String
    public let context: String
    public let checks: [EnvironmentCheck]
    public let observations: [EnvironmentObservation]
    public static let lifetime: TimeInterval = 300

    public init(id: UUID = UUID(), target: EnvironmentTarget, startedAt: Date, completedAt: Date,
                networkFingerprint: String, configurationFingerprint: String, context: String,
                checks: [EnvironmentCheck], observations: [EnvironmentObservation]) {
        version = 1; self.id = id; self.target = target
        self.startedAt = startedAt; self.completedAt = completedAt
        self.networkFingerprint = networkFingerprint; self.configurationFingerprint = configurationFingerprint
        self.context = context; self.checks = checks; self.observations = observations
    }

    public func recommendation(settings: EnvironmentSettings, currentNetwork: String,
                               now: Date = Date()) -> EnvironmentRecommendation {
        guard now.timeIntervalSince1970.isFinite, startedAt.timeIntervalSince1970.isFinite,
              completedAt.timeIntervalSince1970.isFinite, now >= completedAt, completedAt >= startedAt,
              now.timeIntervalSince(startedAt) <= Self.lifetime,
              networkFingerprint == currentNetwork,
              configurationFingerprint == EnvironmentInspector.configurationFingerprint(settings: settings) else { return .stale }
        guard validEvidenceShape else { return .unknown }
        if checks.contains(where: { $0.required && $0.result == .failed }) { return .attention }
        if checks.contains(where: { $0.required && $0.result != .passed }) { return .unknown }
        return .ready
    }

    var validEvidenceShape: Bool {
        let mandatory = Set(["configuration", "baseline", "network-configuration", "context-stable", "network:" + target.serviceHost] +
                            target.hosts.flatMap { ["route:" + $0, "exit:" + $0] })
        let ids = checks.map(\.id)
        return version == 1 && Self.validDigest(networkFingerprint) && Self.validDigest(configurationFingerprint) &&
            Self.validDigest(context) && Set(ids).count == ids.count && mandatory.isSubset(of: Set(ids)) &&
            mandatory.allSatisfy { id in checks.contains { $0.id == id && $0.required } } &&
            observations.count == target.hosts.count && Set(observations.map(\.host)) == Set(target.hosts) &&
            observations.allSatisfy { $0.milliseconds >= 0 && $0.milliseconds <= 60_000 }
    }

    static func validDigest(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

/// Fixed presentation for probe outcome codes, shared by the first screen and
/// exports; persisted codes never map to invented success.
public enum EnvironmentProbeFailure {
    /// Probe died before producing exit evidence; rows show a failure label
    /// instead of an exit IP.
    public static let transportCodes: Set<String> = [
        "dns_failed", "connect_failed", "probe_timeout", "tls_failed",
        "tls_reset", "tls_timeout", "tls_certificate", "transport_failed",
    ]

    public static func isTransport(_ code: String) -> Bool { transportCodes.contains(code) }

    /// One short phrase per failure class; nil leaves the row to its result tone.
    public static func shortLabel(for code: String) -> String? {
        switch code {
        case "tls_reset": return "TLS 被中断"
        case "tls_timeout": return "TLS 超时"
        case "tls_certificate": return "证书异常"
        case "tls_failed": return "TLS 失败"
        case "connect_failed": return "入口拒绝"
        case "probe_timeout": return "连接超时"
        case "dns_failed": return "解析失败"
        case "transport_failed": return "探测失败"
        case "exit_mismatch": return "出口不符"
        case "exit_unavailable": return "未取得出口"
        case "service_rate_limited": return "被限流"
        case "service_unavailable": return "服务异常"
        case "route_unresolved", "proxy_invalid", "diagnostic_proxy_missing": return "路径未确认"
        case "baseline_missing", "baseline_invalid": return "未设基准"
        default: return nil
        }
    }
}

public enum EnvironmentGuidance {
    /// Fixed advice, safe to use with persisted error codes or diagnostic exports.
    public static func advice(for code: String) -> String {
        switch code {
        case "baseline_missing", "baseline_invalid": return "填写已确认的固定出口 IP 后重新检测。"
        case "exit_mismatch": return "在现有代理客户端核对节点与域名规则，确认后重新检测。"
        case "cli_context_missing": return "在实际使用 Claude 的终端和项目目录执行 inspect cli。"
        case "cli_configuration_ambiguous", "cli_custom_configuration", "no_proxy_unresolved": return "核对终端及项目的代理、绕过或自定义设置；本工具不会自动改写。"
        case "route_unresolved": return "核对系统代理或 PAC；也可另做指定代理诊断，但两种结果不能互相替代。"
        case "diagnostic_proxy_missing", "proxy_invalid": return "填写明确的代理协议、地址和端口，不要把密码放进地址。"
        case "dns_failed", "connect_failed", "probe_timeout", "transport_failed": return "确认当前代理客户端连接正常，再重新检测。"
        case "tls_reset": return "代理隧道已建立，但 TLS 握手被对端中断；常见于线路对该域名的阻断或丢弃。换节点或线路后重新检测，不要关闭 TLS 校验。"
        case "tls_timeout": return "TLS 握手长时间无响应；多为线路对该域名丢包或限速。稍后重试或换线路，不要关闭 TLS 校验。"
        case "tls_certificate": return "证书校验未通过；核对系统时间与代理是否注入证书，不要关闭 TLS 校验。"
        case "tls_failed": return "TLS 握手失败；检查系统时间、证书或代理配置，不要关闭 TLS 校验。"
        case "service_rate_limited", "service_unavailable": return "稍后重试，并查看服务状态或客户端中的实际错误。"
        case "exit_unavailable", "service_access_unconfirmed": return "此项证据尚未取得；可查看人工网站补充，不能据此确认账号可用。"
        case "context_changed": return "网络或配置在检测期间变化，请重新检测。"
        case "configuration_unreadable", "cli_configuration_unreadable": return "检查配置文件是否可读且格式正确；原文件已保留。"
        default: return "结合该项的来源与检查时间判断；需要时重新检测。"
        }
    }
}
