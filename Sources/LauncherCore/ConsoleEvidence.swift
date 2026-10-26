import Foundation

public enum EvidenceLevel: String { case observed, failed, unknown, stale }

/// Display vocabulary only. Derived from evidence; never an input to any decision.
/// "已观测" always means "observed within the stated scope", never "protected".
public enum DisplayState: String, CaseIterable {
    case observed, checking, expired, unverified, failed
    public init(_ level: EvidenceLevel) {
        switch level {
        case .observed: self = .observed
        case .failed: self = .failed
        case .stale: self = .expired
        case .unknown: self = .unverified
        }
    }
    public var label: String {
        switch self {
        case .observed: return "已观测"
        case .checking: return "检测中"
        case .expired: return "已过期"
        case .unverified: return "未验证"
        case .failed: return "异常"
        }
    }
    public var symbol: String {
        switch self {
        case .observed: return "eye.circle.fill"
        case .checking: return "arrow.triangle.2.circlepath"
        case .expired: return "clock"
        case .unverified: return "questionmark.circle"
        case .failed: return "exclamationmark.triangle.fill"
        }
    }
    public var meaning: String {
        switch self {
        case .observed: return "有当前证据且在有效期内；只覆盖该项写明的范围。"
        case .checking: return "正在采样；旧结果不作为当前状态。"
        case .expired: return "曾有证据，但已超过有效期；旧结果不能沿用。"
        case .unverified: return "没有证据、未接入数据源，或尚无验收方法。"
        case .failed: return "检查明确未通过，或后台锁存了故障。"
        }
    }
    /// Legend order, worst first.
    public static let legend: [DisplayState] = [.failed, .expired, .unverified, .checking, .observed]
}

public struct ConsoleEvidence: Identifiable {
    public let id: String
    public let title: String
    public let level: EvidenceLevel
    public let source: String
    public let detail: String
    public var state: DisplayState { .init(level) }
}
public struct ConsoleGate: Identifiable {
    public let id: String
    public let title: String
    public let symbol: String
    public let evidence: [ConsoleEvidence]
    public var level: EvidenceLevel {
        if evidence.contains(where: { $0.level == .failed }) { return .failed }
        if evidence.contains(where: { $0.level == .stale }) { return .stale }
        if evidence.contains(where: { $0.level == .unknown }) { return .unknown }
        return .observed
    }
    public var state: DisplayState { .init(level) }
    public func count(_ state: DisplayState) -> Int { evidence.filter { $0.state == state }.count }
    /// Plain counts, worst first, e.g. "1 项异常 · 2 项未验证 · 1 项已观测".
    public var summary: String { Self.tally(evidence.map(\.state)) }
    public static func tally(_ states: [DisplayState]) -> String {
        let parts = DisplayState.legend.compactMap { state -> String? in
            let n = states.filter { $0 == state }.count
            return n == 0 ? nil : "\(n) 项\(state.label)"
        }
        return parts.isEmpty ? "没有检查项" : parts.joined(separator: " · ")
    }
    /// Overview tally across all gates; never collapses into a single "pass".
    public static func overall(_ gates: [ConsoleGate]) -> String {
        tally(gates.flatMap { $0.evidence.map(\.state) })
    }
}

/// A view of evidence with explicit scope. This model cannot issue launch permission.
public enum ConsoleProjection {
    public static func gates(report: PreflightReport?, settings: PreflightSettings,
                             target: CheckTarget, checking: Bool, now: Date,
                             firewall: PFObservation?, controller: ControllerSnapshot?,
                             endpoint: String, connector: ConnectorSnapshot? = nil) -> [ConsoleGate] {
        let bound = report?.target == target ? report : nil
        let status = ProtectionStatus(report: bound, settings: settings, context: bound?.context,
                                      checking: checking, now: now, firewall: firewall)
        let stable = bound?.checks.filter { $0.id == "unchanged" } ?? []
        let fresh = bound.map { now >= $0.startedAt && now.timeIntervalSince($0.startedAt) <= 30 && $0.completedAt >= $0.startedAt && $0.completedAt <= now } == true && !checking &&
            stable.count == 1 && stable[0].required && stable[0].result == .passed
        let pf = firewall.flatMap { $0.isCurrent(at: now) ? $0 : nil }
        let live = controller.flatMap { $0.isCurrent(endpoint: endpoint, now: now) ? $0 : nil }
        func item(_ id: String, _ title: String, _ level: EvidenceLevel, _ source: String, _ detail: String) -> ConsoleEvidence {
            .init(id: id, title: title, level: level, source: source, detail: detail)
        }
        func diagnostic(_ id: String, _ title: String) -> ConsoleEvidence {
            let check = bound?.checks.first { $0.id == id }
            return item(id, title, !fresh ? .stale : check?.result == .failed ? .failed : .unknown,
                        "本机配置诊断", check?.detail ?? "尚未取得当前入口的诊断。")
        }
        let owned = connector.flatMap { $0.isCurrent(at: now) ? $0 : nil }
        let observations = bound?.observations ?? []
        let expected = Set(target.hosts)
        let complete = observations.count == expected.count && Set(observations.map(\.host)) == expected
        let matching = complete && observations.allSatisfy { $0.check.result == .passed && $0.ip.map(settings.matches) == true }
        let exitLevel: EvidenceLevel = !fresh ? .stale : matching ? .observed : observations.isEmpty ? .unknown : .failed
        return [
            .init(id: "exit", title: "住宅出口", symbol: "house", evidence: [
                item("probe-exit", "目标站点探测出口", exitLevel, "HTTPS trace · \(target.title)", status.observedExit),
                item("residence", "住宅属性与实际会话出口", .unknown, "缺少独立证据", "固定 IP 匹配不能证明住宅属性，也不能代替实际业务会话的出口。")]),
            .init(id: "block", title: "断网保护", symbol: "lock.shield", evidence: [
                item("pf", "PF 目的地址规则", pf == nil ? .stale : pf!.rules_observed ? .observed : .failed,
                     "root 后台 · 限定目的地址", pf?.rules_observed == true ? "规则已观测；仅覆盖批准的目的地址。" : "未取得新鲜、完整的规则观测。"),
                item("connector-block", "自有连接器转发", owned == nil ? .stale : .observed, "本机 Unix 管理接口", owned?.explanation ?? "没有新鲜的连接器状态。"),
                item("disconnect", "真实会话故障断流", .unknown, "尚未验收", "需要验证代理退出、TUN 消失、已有连接和新建连接；当前不提供完整断流保证。")]),
            .init(id: "protocols", title: "IPv6 / UDP", symbol: "arrow.triangle.branch", evidence: [
                diagnostic("ipv6", "本机 IPv6 配置"),
                item("udp", "IPv6 / UDP 旁路", .unknown, "尚未实测", "接口存在与否、单个 IPv6 阻断命中，都不能证明全路径无旁路。")]),
            .init(id: "routing", title: "DNS 与分流", symbol: "network", evidence: [
                diagnostic("dns", "DNS 配置"),
                item("owned-connections", "自有连接器连接", owned == nil ? .stale : .observed, "连接器实际转发计数", owned.map { "当前 \($0.connectionCount) 条；连接器只连接已配置上游，不回退直连。" } ?? "尚未连接自有管理接口。"),
                item("connections", "代理内核连接与命中规则", live == nil ? .unknown : .observed,
                     "可选 Mihomo API · 非原子采样", live.map { "内核报告 \($0.totalConnections) 条活跃连接；进程归属和实际出口仍需独立确认。" } ?? "未接入已确认的控制接口。HTTP 代理入口不等于控制接口。"),
                item("bypass", "完整 DNS 与分流覆盖", .unknown, "尚未验收", "控制接口看不到完全绕过内核的连接；空连接表不能证明无泄漏。")]),
            .init(id: "startup", title: "启动安检", symbol: "play.shield", evidence: [
                item("preflight", target.title, !fresh ? .stale : status.networkPassed ? .observed : .failed,
                     "当前入口预检", status.explanation),
                item("permission", "严格启动许可", .unknown, "所有启动入口统一门禁", StrictProtection.reason)]),
            .init(id: "background", title: "后台巡检", symbol: "waveform.path.ecg", evidence: [
                item("observer", "规则与网络证据后台", pf == nil ? .stale : pf!.manual_recheck_required ? .failed : pf!.evidence_fresh ? .observed : .unknown,
                     "root 后台报告", pf?.diagnosticDescription ?? "后台报告缺失或已过期。"),
                item("connector-heartbeat", "连接器心跳", owned == nil ? .stale : .observed, "守卫 ACK 与网关状态", owned == nil ? "没有新鲜心跳证据。" : "守卫持续核对心跳；网关失联 3 秒关闭转发。"),
                item("session-guard", "会话级守卫", .unknown, "尚未验收", "连接观测不等于持续强制隔离；自动修复不授予启动许可。")])
        ]
    }
}

public struct EnvironmentReading {
    public let timezone: String
    public let languages: [String]
    public let region: String
    public let system: String
    public let cores: Int
    public static func read() -> Self {
        .init(timezone: TimeZone.current.identifier, languages: Locale.preferredLanguages,
              region: Locale.current.region?.identifier ?? "未知",
              system: ProcessInfo.processInfo.operatingSystemVersionString,
              cores: ProcessInfo.processInfo.processorCount)
    }
}
