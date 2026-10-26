import Foundation

/// Correlated result of one PF check. Selectors are not standalone forwarding or launch permission.
public struct PFRecoveryReceipt: Decodable {
    private struct Record: Decodable {
        let version: Int
        let revision: Int64
        let plan_id, plan_sha256, runtime_sha256, service_instance: String
        let request_id, status, reason: String
        let generation: String?
        let received_at, updated_at, request_deadline: Double
        let started_at, checked_at, finished_at: Double?
        let checks: [String: Bool]?
        let evidence_expires_at: Double?
    }

    private struct Field: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    private let record: Record
    private static let fields: Set<String> = [
        "version", "revision", "plan_id", "plan_sha256", "runtime_sha256", "service_instance",
        "request_id", "status", "reason", "generation", "received_at", "updated_at",
        "request_deadline", "started_at", "checked_at", "finished_at", "checks", "evidence_expires_at"
    ]
    private static let checks: Set<String> = [
        "installed", "pf_enabled", "root_matches", "destinations_match", "evidence_fresh"
    ]
    private static let reasons: [String: Set<String>] = [
        "received": ["request_received"], "checking": ["checks_in_progress"], "passed": ["checks_passed"],
        "failed": ["dns_refresh_failed", "network_check_timeout", "proxy_probe_failed", "proxy_exit_mismatch",
            "address_or_proxy_policy_changed", "pf_check_failed", "rules_missing_or_changed",
            "evidence_expired", "request_expired", "check_failed"],
        "interrupted": ["service_restarted", "service_stopped", "runtime_changed",
            "configuration_changed", "manual_cancelled"]
    ]

    public init(from decoder: Decoder) throws {
        let invalid = DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                       debugDescription: "Invalid PF recovery receipt"))
        func require(_ condition: Bool) throws { if !condition { throw invalid } }
        func hex(_ text: String, length: Int) -> Bool {
            text.utf8.count == length && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
        }
        func time(_ number: Double) -> Bool {
            number.isFinite && (0...253_402_300_799).contains(number)
        }

        let keys = try decoder.container(keyedBy: Field.self)
        try require(Set(keys.allKeys.map(\.stringValue)) == Self.fields)
        let value = try Record(from: decoder)
        try require(value.version == 1 && (1...9_007_199_254_740_991).contains(value.revision))
        try require(hex(value.plan_id, length: 32) && hex(value.service_instance, length: 32) &&
            hex(value.request_id, length: 32) && hex(value.plan_sha256, length: 64) && hex(value.runtime_sha256, length: 64))
        try require(Self.reasons[value.status]?.contains(value.reason) == true)
        try require(time(value.received_at) && time(value.updated_at) && time(value.request_deadline) &&
            value.received_at <= value.updated_at && value.request_deadline > value.received_at &&
            value.request_deadline - value.received_at <= 120)
        try require((value.started_at == nil) == (value.generation == nil))
        if let generation = value.generation { try require(hex(generation, length: 32)) }
        if let started = value.started_at {
            try require(time(started) && value.received_at <= started && started <= value.updated_at &&
                started < value.request_deadline)
        }
        switch value.status {
        case "received":
            try require(value.started_at == nil && value.checked_at == nil && value.finished_at == nil &&
                value.updated_at == value.received_at)
        case "checking":
            try require(value.started_at != nil && value.updated_at == value.started_at &&
                value.checked_at == nil && value.finished_at == nil)
        default:
            guard let finished = value.finished_at else { throw invalid }
            try require(time(finished) && finished == value.updated_at)
            if value.status == "passed" {
                guard let started = value.started_at, let checked = value.checked_at,
                      let expires = value.evidence_expires_at, let checks = value.checks else { throw invalid }
                try require(time(checked) && started <= checked && checked <= finished && finished < value.request_deadline &&
                    time(expires) && finished < expires && expires <= checked + 45 &&
                    Set(checks.keys) == Self.checks && checks.values.allSatisfy { $0 })
            } else {
                try require(value.checked_at == nil)
                if value.reason == "request_expired" { try require(finished >= value.request_deadline) }
            }
        }
        if value.status != "passed" { try require(value.checks == nil && value.evidence_expires_at == nil) }
        record = value
    }

    func matches(planID: String, reportTime: Double) -> Bool {
        record.plan_id == planID && record.updated_at <= reportTime
    }

    var revision: Int64 { record.revision }
    var active: Bool { record.status == "received" || record.status == "checking" }
    var updatedAt: Double { record.updated_at }
    var requestDeadline: Double { record.request_deadline }

    func connectorBinding(for request: PFRecoveryRequest) -> ConnectorPFBinding? {
        guard correlatedStatus(for: request) == "passed", let generation = record.generation else { return nil }
        return .init(requestID: request.id, expectedRevision: request.context.receipt_revision,
                     planID: record.plan_id, planSHA256: record.plan_sha256, runtimeSHA256: record.runtime_sha256,
                     serviceInstance: record.service_instance, generation: generation,
                     receivedNotBefore: request.createdAt.timeIntervalSince1970)
    }

    func connectorExpiry(matching binding: ConnectorPFBinding, at now: Date) -> Double? {
        guard binding.valid, record.status == "passed", record.revision == binding.expectedRevision + 1,
              record.request_id == binding.requestID, record.plan_id == binding.planID,
              record.plan_sha256 == binding.planSHA256, record.runtime_sha256 == binding.runtimeSHA256,
              record.service_instance == binding.serviceInstance, record.generation == binding.generation,
              record.received_at >= binding.receivedNotBefore,
              let expiry = record.evidence_expires_at, now.timeIntervalSince1970 < expiry else { return nil }
        return expiry
    }

    func correlatedStatus(for request: PFRecoveryRequest) -> String? {
        let expected = request.context
        guard expected.receipt_revision < PFControlContext.maximumRevision,
              record.revision == expected.receipt_revision + 1, record.request_id == request.id,
              record.plan_id == expected.plan_id, record.plan_sha256 == expected.plan_sha256,
              record.runtime_sha256 == expected.runtime_sha256, record.service_instance == expected.service_instance,
              record.received_at >= request.createdAt.timeIntervalSince1970 else { return nil }
        return record.status
    }

    /// `current` is a trusted root declaration, not independent client verification
    /// of the runtime/instance/generation; local expiry is checked again here.
    func lines(at now: Date, current: Bool) -> [String] {
        let titles = ["received": "请求已收到", "checking": "正在复检", "passed": "本次复检当时通过",
                      "failed": "本次复检未通过", "interrupted": "本次复检已中断"]
        func date(_ timestamp: Double) -> String {
            Date(timeIntervalSince1970: timestamp).formatted(date: .abbreviated, time: .standard)
        }
        var result = [titles[record.status] ?? "复检记录不可用", "收到请求：" + date(record.received_at)]
        if let started = record.started_at { result.append("开始检查：" + date(started)) }
        if let finished = record.finished_at { result.append("完成记录：" + date(finished)) }
        switch record.status {
        case "received", "checking":
            if now.timeIntervalSince1970 >= record.request_deadline {
                result.append("请求期限已过，等待后台确认最终结果。")
            }
        case "passed":
            let fresh = current && record.evidence_expires_at.map { now.timeIntervalSince1970 < $0 } == true
            result.append(fresh ? "后台报告本次复检证据当前有效；仅限已批准地址。" : "这是历史通过记录，不表示当前网络检查通过。")
        case "failed":
            switch record.reason {
            case "request_expired": result.append("本次请求超过完成期限。")
            case "check_failed": result.append("本次检查未完成全部核验。")
            default: result.append(PFObservation.guide(reason: record.reason, detail: nil).title)
            }
        case "interrupted":
            let reasons = ["service_restarted": "后台已重启", "service_stopped": "后台已停止",
                           "runtime_changed": "后台版本已变化", "configuration_changed": "配置已变化",
                           "manual_cancelled": "请求已取消"]
            result.append(reasons[record.reason] ?? "检查中断")
        default: break
        }
        result.append("复检结果只说明这次检查；受保护启动仍锁定。")
        return result
    }
}
