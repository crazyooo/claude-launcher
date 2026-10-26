import Foundation

/// Bounded display data from the root observer. Never used to grant permission.
public struct PFTimingDiagnostic: Decodable {
    public let phase: String
    public let evidenceKind: String
    public let host: String?
    public let recordType: Int?
    public let values: [String: Double]

    private enum Keys: String, CodingKey {
        case phase, evidence_kind, host, record_type, lifetime_seconds, request_seconds
        case remaining_seconds, age_seconds, checked_at, http_age_seconds
    }
    private static let phases = [
        "query_return": "单次 DNS 查询返回", "dns_batch": "整批 DNS 查询完成",
        "exit_wait": "等待出口探测完成", "worker_queue": "后台读取采样结果",
        "pf_check": "防火墙规则检查", "active_evidence": "已有证据有效期检查",
        "publication": "报告发布前检查"
    ]
    private static let hosts: Set<String> = [
        "claude.ai", "api.anthropic.com", "platform.claude.com",
        "console.anthropic.com", "files.claudeusercontent.com"
    ]

    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: Keys.self)
        phase = try fields.decode(String.self, forKey: .phase)
        evidenceKind = try fields.decode(String.self, forKey: .evidence_kind)
        guard Self.phases[phase] != nil, ["dns", "proxy"].contains(evidenceKind) else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                    debugDescription: "Invalid diagnostic labels"))
        }
        let reportedHost = try? fields.decode(String.self, forKey: .host)
        let reportedType = try? fields.decode(Int.self, forKey: .record_type)
        if evidenceKind == "dns", let reportedHost, Self.hosts.contains(reportedHost),
           let reportedType, [1, 28].contains(reportedType) {
            host = reportedHost; recordType = reportedType
        } else {
            host = nil; recordType = nil
        }
        var numbers: [String: Double] = [:]
        let keys: [Keys] = [.lifetime_seconds, .request_seconds, .remaining_seconds, .age_seconds, .checked_at]
        for key in keys {
            let bound = key == .checked_at ? 100_000_000_000.0 : 86_400.0
            if let value = try? fields.decode(Double.self, forKey: key),
               value.isFinite, abs(value) <= bound { numbers[key.rawValue] = value }
        }
        if let age = try? fields.decode(Int.self, forKey: .http_age_seconds),
           (0...2_147_483_648).contains(age) { numbers["http_age_seconds"] = Double(age) }
        values = numbers
    }

    public var lines: [String] {
        var result = ["阶段：\(Self.phases[phase] ?? phase)（\(phase)）",
                      "证据类型：" + (evidenceKind == "dns" ? "DNS 地址" : "出口探测")]
        if let host, let recordType { result.append("查询：\(host) · \(recordType == 1 ? "A" : "AAAA")") }
        for (key, label) in [("lifetime_seconds", "证据有效期预算"), ("request_seconds", "请求耗时"),
                             ("age_seconds", "检查时证据年龄"), ("remaining_seconds", "检查时剩余有效期"),
                             ("http_age_seconds", "HTTP 缓存年龄")] {
            if let value = values[key] {
                let seconds = String(format: "%.3f", locale: Locale(identifier: "en_US_POSIX"), value)
                result.append("\(label)：\(seconds) 秒")
            }
        }
        if let timestamp = values["checked_at"] {
            result.append("记录时间：" + Date(timeIntervalSince1970: timestamp).formatted(date: .abbreviated, time: .standard))
        }
        if evidenceKind == "dns" { result.append("有效期预算可能包含本地零回答观察上限，并非都表示权威 DNS TTL。") }
        return result
    }
}

public struct PFSamplingDiagnostic: Decodable {
    public let dnsAttempts: Int
    public let priorExpiry: PFTimingDiagnostic?
    private enum Keys: String, CodingKey { case dns_attempts, prior_expiry }

    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: Keys.self)
        dnsAttempts = try fields.decode(Int.self, forKey: .dns_attempts)
        priorExpiry = try fields.decodeIfPresent(PFTimingDiagnostic.self, forKey: .prior_expiry)
        let valid: Bool
        switch dnsAttempts {
        case 1: valid = priorExpiry == nil
        case 2: valid = priorExpiry.map {
            $0.evidenceKind == "dns" &&
                ["query_return", "dns_batch", "exit_wait", "worker_queue", "pf_check", "publication"].contains($0.phase)
        } ?? false
        default: valid = false
        }
        guard valid else {
            throw DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                    debugDescription: "Invalid sampling diagnostic"))
        }
    }
}
