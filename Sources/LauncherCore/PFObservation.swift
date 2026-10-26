import Foundation
import Darwin

/// Root-published observation. Recovery checks may consume it; never a launch authorization.
public struct PFObservation: Decodable {
    public let version: Int
    public let plan_id: String
    public let checked_at: Double
    public let service_running: Bool
    public let rules_observed: Bool
    public let evidence_fresh: Bool
    public let manual_recheck_required: Bool
    public let status: String
    public let reason: String
    public let fault_detail: String?
    public let evidence_expires_at: Double?
    public let protection_verified: Bool
    public let launch_authorized: Bool
    public let fault_diagnostic: PFTimingDiagnostic?
    public let sampling_diagnostic: PFSamplingDiagnostic?
    public let recovery: PFRecoveryReceipt?
    private let recoveryCurrent: Bool
    private let controlContext: PFControlContext?
    private let recoveryWasInvalid: Bool

    private enum CodingKeys: String, CodingKey {
        case version, plan_id, checked_at, service_running, rules_observed, evidence_fresh
        case manual_recheck_required, status, reason, fault_detail, evidence_expires_at
        case protection_verified, launch_authorized, fault_diagnostic, sampling_diagnostic
        case recovery, recovery_current, control_context
    }

    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        version = try fields.decode(Int.self, forKey: .version)
        plan_id = try fields.decode(String.self, forKey: .plan_id)
        checked_at = try fields.decode(Double.self, forKey: .checked_at)
        service_running = try fields.decode(Bool.self, forKey: .service_running)
        rules_observed = try fields.decode(Bool.self, forKey: .rules_observed)
        evidence_fresh = try fields.decode(Bool.self, forKey: .evidence_fresh)
        manual_recheck_required = try fields.decode(Bool.self, forKey: .manual_recheck_required)
        status = try fields.decode(String.self, forKey: .status)
        reason = try fields.decode(String.self, forKey: .reason)
        fault_detail = try fields.decodeIfPresent(String.self, forKey: .fault_detail)
        evidence_expires_at = try fields.decodeIfPresent(Double.self, forKey: .evidence_expires_at)
        protection_verified = try fields.decode(Bool.self, forKey: .protection_verified)
        launch_authorized = try fields.decode(Bool.self, forKey: .launch_authorized)
        // Optional explanations may be absent or malformed in another runtime version.
        // Only these fields are tolerant; the original report remains strictly decoded.
        fault_diagnostic = try? fields.decodeIfPresent(PFTimingDiagnostic.self, forKey: .fault_diagnostic)
        sampling_diagnostic = try? fields.decodeIfPresent(PFSamplingDiagnostic.self, forKey: .sampling_diagnostic)
        recovery = try? fields.decodeIfPresent(PFRecoveryReceipt.self, forKey: .recovery)
        recoveryCurrent = (try? fields.decode(Bool.self, forKey: .recovery_current)) == true
        controlContext = try? fields.decodeIfPresent(PFControlContext.self, forKey: .control_context)
        recoveryWasInvalid = fields.contains(.recovery) &&
            (try? fields.decodeNil(forKey: .recovery)) != true && recovery == nil
    }

    public func availableControlContext(at now: Date) -> PFControlContext? {
        guard isCurrent(at: now), service_running, !recoveryWasInvalid,
              let context = controlContext, context.plan_id == plan_id,
              context.receipt_revision == (recovery?.revision ?? 0),
              recovery == nil || recovery!.matches(planID: plan_id, reportTime: checked_at) else { return nil }
        return context
    }

    public func canBeginRecovery(at now: Date) -> Bool {
        guard let context = availableControlContext(at: now),
              context.receipt_revision < PFControlContext.maximumRevision else { return false }
        return recovery?.active != true
    }

    func connectorExpiry(matching binding: ConnectorPFBinding, at now: Date) -> Double? {
        guard isCurrent(at: now), recoveryCurrent, status == "observed", service_running,
              rules_observed, evidence_fresh, !manual_recheck_required,
              let context = availableControlContext(at: now), context.plan_id == binding.planID,
              context.plan_sha256 == binding.planSHA256, context.runtime_sha256 == binding.runtimeSHA256,
              context.service_instance == binding.serviceInstance,
              let receiptExpiry = recovery?.connectorExpiry(matching: binding, at: now),
              let reportExpiry = evidence_expires_at else { return nil }
        return min(receiptExpiry, reportExpiry)
    }

    public func recoveryLines(at now: Date) -> [String] {
        guard isCurrent(at: now) else {
            return ["后台报告缺失或过期，暂不展示复检结果。"]
        }
        guard let receipt = recovery, receipt.matches(planID: plan_id, reportTime: checked_at) else {
            return ["后台未提供有效的关联复检记录；可能是旧版本或记录格式不支持。"]
        }
        let current = recoveryCurrent && status == "observed" && service_running &&
            evidence_fresh && !manual_recheck_required
        return receipt.lines(at: now, current: current)
    }

    public func diagnosticLines(at now: Date) -> [String] {
        guard isCurrent(at: now) else { return [] }
        if manual_recheck_required {
            guard let record = fault_diagnostic else { return [] }
            return ["故障锁存时的记录，数值不是当前重新测量："] + record.lines +
                ["阶段说明在哪一步检查到证据失效，不单凭此判断上游原因或地址是否一致。"]
        }
        guard status == "observed", let sample = sampling_diagnostic else { return [] }
        if let prior = sample.priorExpiry {
            return ["本轮 DNS 采样 2 次；第一次 DNS 采样的过期记录："] + prior.lines +
                ["本轮有效证据来自第二次采样；采样次数不代表实际会话受保护。"]
        }
        return ["本轮 DNS 采样 1 次；未进行再次采样。采样次数不代表实际会话受保护。"]
    }

    public func isCurrent(at now: Date) -> Bool {
        let timestamp = now.timeIntervalSince1970
        guard version == 1 && plan_id.range(of: "^[a-f0-9]{32}$", options: .regularExpression) != nil &&
            checked_at.isFinite && timestamp >= checked_at && timestamp - checked_at <= 10 &&
            !protection_verified && !launch_authorized else { return false }
        switch status {
        case "observed":
            return service_running && rules_observed && evidence_fresh && !manual_recheck_required &&
                evidence_expires_at.map { $0.isFinite && $0 > timestamp } == true
        case "checking": return service_running && !evidence_fresh && !manual_recheck_required
        case "fault": return !evidence_fresh && manual_recheck_required
        case "stopped": return !service_running && !rules_observed && !evidence_fresh && manual_recheck_required
        default: return false
        }
    }

    public func layers(at now: Date) -> [ProtectionLayer] {
        guard isCurrent(at: now) else { return Self.unavailableLayers }
        let fresh = evidence_fresh && evidence_expires_at.map { $0.isFinite && $0 > now.timeIntervalSince1970 } == true
        return [
            .init(id: "firewall", title: "② 防火墙", status: rules_observed ? "规则已观测" : "规则待核验",
                  detail: rules_observed ? "后台核对目的地址规则存在；完整防旁路尚未验收。" : "本轮未确认规则完整；不会据此允许启动。"),
            .init(id: "guard", title: "③ 后台检查", status: !service_running ? "已停止" : manual_recheck_required ? "需手动复检" : fresh ? "检查运行中" : "地址复核中",
                  detail: manual_recheck_required ? faultDescription : "按目标约 3 秒核对规则、约 30 秒复核地址与探测出口；尚未实现实际会话链审计。")
        ]
    }

    public var diagnosticDescription: String {
        if !manual_recheck_required { return evidence_fresh ? "规则与网络证据已观测；完整断流尚未验收。" : "正在等待新的网络证据。" }
        return faultDescription
    }
    private var faultDescription: String {
        if let detail = fault_detail, let description = Self.dnsDetails[detail] {
            return "\(description)（\(detail)）；故障保留，需手动复检。"
        }
        switch reason {
        case "dns_refresh_failed": return "DNS 刷新失败（dns_refresh_failed）；旧版后台未保留具体子原因，不能直接断定代理或防火墙失效。故障需手动复检。"
        case "evidence_expired": return "DNS 或出口证据已过期（evidence_expired）；故障保留，需手动复检。"
        case "network_check_timeout": return "后台网络采样超时；故障保留，需手动复检。"
        case "proxy_probe_failed": return "目标站点出口探测失败；故障保留，需手动复检。"
        case "address_or_proxy_policy_changed": return "目标地址或代理基准变化，保留旧规则，等待确认新策略。"
        case "proxy_exit_mismatch": return "探测出口不匹配，故障已保留；需要管理员重新检查。"
        case "service_restarted", "service_stopped": return "后台曾停止或重启，需要管理员重新检查。"
        case "rules_missing_or_changed", "pf_check_failed": return "PF 规则或状态异常；即使补回规则也需要重新检查。"
        default: return "网络或证据检查未通过；故障已保留，需要管理员重新检查。"
        }
    }

    static let dnsDetails = [
        "proxy_doh_failed": "经代理的 DNS 查询失败，未取得更细原因",
        "dns_question_or_status_invalid": "DNS 问题或响应状态不匹配",
        "dns_answers_invalid": "DNS 回答结构无效",
        "dns_cname_loop": "DNS 别名形成循环",
        "dns_owner_ambiguous": "DNS 地址与别名记录冲突",
        "dns_address_invalid": "DNS 地址格式无效",
        "dns_family_mismatch": "DNS 地址族不匹配",
        "dns_cname_invalid": "DNS 别名格式无效",
        "dns_cname_too_deep": "DNS 别名链超过限制",
        "destination_evidence_expired": "目标地址证据已过期",
        "incomplete_query_evidence": "DNS 查询证据不完整",
        "query_answer_count_mismatch": "DNS 回答数量与证据不符",
        "unexpected_dns_source": "DNS 证据来源不符合预期",
        "renewal_requires_host_addresses": "DNS 续期证据不是单个主机地址",
        "proxy_doh_timeout": "经代理的 DNS 查询超时",
        "proxy_doh_connect_failed": "无法建立经代理的 DNS 查询连接",
        "proxy_doh_tls_failed": "DNS 查询 TLS 验证或握手失败",
        "proxy_doh_http_failed": "DNS 查询服务返回 HTTP 错误",
        "proxy_doh_too_large": "DNS 响应超过大小限制",
        "proxy_doh_json_invalid": "DNS 响应格式无法解析",
        "proxy_doh_exec_failed": "无法执行 DNS 查询组件",
        "proxy_doh_headers_invalid": "DNS 响应头格式无效",
        "proxy_doh_age_invalid": "DNS 响应的 HTTP 缓存年龄无效",
        "proxy_doh_cleanup_failed": "DNS 查询进程结束或回收未得到确认",
        "dns_ttl_invalid": "DNS 返回了无效的有效期",
        "query_evidence_expired_or_invalid": "DNS 查询证据已过期或时间无效",
        "proxy_evidence_stale": "出口探测证据已过期"
    ]

    // MARK: Display-only guidance. Never changes trust checks, freshness or launch permission.

    public var checkedAtDate: Date { Date(timeIntervalSince1970: checked_at) }
    /// Present only while the report says evidence is fresh; nil otherwise.
    public var evidenceExpiresDate: Date? {
        guard evidence_fresh, let value = evidence_expires_at, value.isFinite else { return nil }
        return Date(timeIntervalSince1970: value)
    }

    public var guide: FaultGuide {
        if status == "stopped" || !service_running { return Self.guide(reason: "service_stopped", detail: nil) }
        if manual_recheck_required { return Self.guide(reason: reason, detail: fault_detail) }
        if status == "observed" && evidence_fresh { return Self.guide(reason: "same_addresses_observed", detail: nil) }
        return Self.guide(reason: "waiting_for_network_evidence", detail: nil)
    }

    static let recheckStep = "在你自己的终端执行安装时输出并保存的 recheck_command（需要管理员密码，只在终端输入），然后回到这里看结果。命令返回 recheck_requested 只表示请求已收下。"

    /// Reason codes the root observer can publish (tools/pf_service.py FAULTS + healthy states).
    public static let knownReasons = [
        "same_addresses_observed", "waiting_for_network_evidence", "address_or_proxy_policy_changed",
        "proxy_exit_mismatch", "proxy_probe_failed", "dns_refresh_failed", "network_check_timeout",
        "pf_check_failed", "rules_missing_or_changed", "evidence_expired", "service_stopped",
        "service_restarted", "waiting_for_plan", "service_state_invalid"
    ]

    public static func guide(reason: String, detail: String?) -> FaultGuide {
        let technical = detail.flatMap { dnsDetails[$0].map { d in "\(d)（\(detail!)）" } }
        func g(_ title: String, _ text: String, _ next: String) -> FaultGuide {
            .init(code: detail.map { "\(reason) / \($0)" } ?? reason, title: title, explanation: text, nextStep: next, technical: technical)
        }
        if detail == "dns_ttl_shorter_than_sample" {
            return g("旧记录报告 DNS 证据有效期不足",
                     "这条旧原因码没有说明过期发生在哪个阶段，不能判断是请求、排队、检查耗时还是上游有效期导致，也不能确认地址是否保持一致。故障继续锁存。",
                     "先核对后台诊断记录中的阶段耗时；缺少记录时先补采诊断，处理原因后再复检。重复复检不能替代原因诊断。")
        }
        if reason == "dns_refresh_failed", detail == "proxy_doh_cleanup_failed" {
            return g("DNS 查询进程回收未确认",
                     "后台未能确认查询子进程已结束并回收，不能据此判断代理连接或 DNS 响应是否成功。",
                     "先检查后台与查询子进程状态，处理回收问题后再复检；重复复检不能代替处理。")
        }
        if reason == "dns_refresh_failed", detail == "proxy_doh_exec_failed" {
            return g("DNS 查询组件执行失败",
                     "后台无法完成查询组件的执行或本机输入输出；这个原因码不能单独证明代理失效。",
                     "先核对后台运行环境和查询组件，修复后再复检。")
        }
        if reason == "dns_refresh_failed", let detail, detail.hasPrefix("proxy_doh_") {
            return g("经代理查询 DNS 失败",
                     "通过 127.0.0.1:1082 查询 dns.google 没有成功（超时、连不上、TLS 或 HTTP 错误等）。",
                     "先在你的代理客户端客户端确认网络可用，再" + recheckStep)
        }
        switch reason {
        case "same_addresses_observed":
            return g("地址证据有效（限定范围）",
                     "后台刚核对过：Claude 相关域名仍解析到已批准的地址，探测出口也一致。只覆盖这几个已批准地址，不覆盖新地址、UDP、TUN 或 Claude 的全部连接。",
                     "不需要操作。证据到期前后台会自动续采；受保护启动仍锁定。")
        case "waiting_for_network_evidence":
            return g("等待后台证据",
                     "后台在运行，但还没有当前有效的地址证据（刚启动，或正在续采）。",
                     "等待约 30 秒；长时间不变请看诊断工作台。")
        case "evidence_expired":
            return g("证据已过期",
                     "上一份地址或出口证据超过了有效期，新证据没能及时接上。后台已锁存故障，不会自动恢复。",
                     recheckStep)
        case "dns_refresh_failed":
            return g("DNS 刷新失败",
                     detail == nil ? "后台没有记录具体子原因（可能是旧版后台），不能据此判断代理或防火墙哪里坏了。" : "后台核对 DNS 时未通过。",
                     recheckStep)
        case "address_or_proxy_policy_changed":
            return g("地址或代理基准变了",
                     "域名解析到了未批准的新地址，或代理端口、出口基准变了。旧规则仍保留，但新地址没有被拦截。",
                     "不要只做复检：需要重新审阅并准备新计划（prepare → 审阅 → apply），按 docs/pf-background-observer.md 操作。")
        case "proxy_exit_mismatch":
            return g("出口不一致",
                     "探测到的出口 IP 与你确认的固定出口不同。界面不会自动接受新 IP。",
                     "在你的代理客户端客户端确认节点；确认无误后再" + recheckStep)
        case "proxy_probe_failed":
            return g("出口探测失败",
                     "通过代理访问 claude.ai / api.anthropic.com 的探测没有成功。",
                     "确认代理可用后，" + recheckStep)
        case "network_check_timeout":
            return g("后台核对超时",
                     "一轮网络核对超过 45 秒没有完成。",
                     "检查网络是否卡顿，然后" + recheckStep)
        case "rules_missing_or_changed", "pf_check_failed":
            return g("防火墙规则异常",
                     "PF 规则缺失、被改动或无法读取。即使后台补回了规则，也需要人工确认。",
                     recheckStep + " 仍异常时按文档检查 PF，不要重复 apply。")
        case "service_restarted", "service_stopped":
            return g("后台曾停止或重启",
                     "后台中断过，期间的状态未知。",
                     "确认后台在运行，然后" + recheckStep)
        case "waiting_for_plan":
            return g("后台没有可用计划",
                     "没有找到已应用的 PF 计划（例如系统重启后计划丢失）。",
                     "按 docs/pf-background-observer.md 重新 prepare、审阅并 apply；不要复用旧命令。")
        case "service_state_invalid":
            return g("后台状态无效",
                     "后台记录无法通过校验，已停止判断。",
                     "按 docs/pf-background-observer.md 检查后台安装；不要手动改 root 文件。")
        default:
            return g("网络或证据检查未通过", "后台报告了未识别的原因码。", recheckStep)
        }
    }

    /// Shown when no fresh, trusted report exists.
    public static let unavailableGuide = FaultGuide(
        code: "report_unavailable", title: "后台报告不可用",
        explanation: "没有读到新鲜、可信的后台报告（未安装、已停止，或报告超过 10 秒）。界面不会沿用旧状态。",
        nextStep: "确认 PF 后台已安装并在运行（见 docs/pf-background-observer.md）。", technical: nil)

    /// One-line PF status for sidebar / menu bar. Display only.
    public static func statusLine(_ value: PFObservation?, now: Date) -> String {
        guard let value, value.isCurrent(at: now) else { return "后台报告不可用" }
        if !value.service_running { return "后台已停止 · 需手动复检" }
        if value.manual_recheck_required { return "需手动复检 · " + value.guide.title }
        if let expiry = value.evidenceExpiresDate, value.evidence_fresh {
            let left = max(0, Int(expiry.timeIntervalSince(now)))
            return "地址证据有效至 \(clock(expiry))（剩 \(left) 秒）· 仅限批准地址"
        }
        return "等待后台证据"
    }

    public static func clock(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "zh_CN"); formatter.timeZone = .current
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }

    public static let unavailableLayers: [ProtectionLayer] = [
        .init(id: "firewall", title: "② 防火墙", status: "当前未核验",
              detail: "目的地址阻断已完成基础实测；没有新鲜的管理员后台报告。"),
        .init(id: "guard", title: "③ 后台检查", status: "未连接",
              detail: "后台未安装、已停止或报告已过期；界面不会沿用旧的正常状态。")
    ]

    public static func load() -> PFObservation? {
        // Open every component relative to a verified directory descriptor. A
        // symlink or writable ancestor must not turn user data into a root report.
        var descriptor = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { return nil }
        defer { close(descriptor) }
        for name in ["Library", "Application Support", "Claude Launcher PF"] {
            let next = openat(descriptor, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard next >= 0 else { return nil }
            close(descriptor); descriptor = next
            var info = stat()
            guard fstat(descriptor, &info) == 0, info.st_uid == 0, (info.st_mode & 0o022) == 0 else { return nil }
        }
        let file = openat(descriptor, "status.json", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { return nil }
        defer { close(file) }
        var info = stat()
        guard fstat(file, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG,
              info.st_uid == 0, (info.st_mode & 0o022) == 0, info.st_nlink == 1,
              info.st_size >= 0, info.st_size <= 16384 else { return nil }
        var bytes = [UInt8](repeating: 0, count: 16385)
        let count = bytes.withUnsafeMutableBytes { read(file, $0.baseAddress, $0.count) }
        guard count > 0, count <= 16384 else { return nil }
        return try? JSONDecoder().decode(PFObservation.self, from: Data(bytes.prefix(count)))
    }
}

/// Plain-language fault explanation with a concrete next step. Display only.
public struct FaultGuide: Equatable {
    public let code: String
    public let title: String
    public let explanation: String
    public let nextStep: String
    public let technical: String?
}
