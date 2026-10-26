import Foundation
import CryptoKit

public enum CheckResult: String, Codable { case passed, failed, unknown, info }
public enum CheckTarget: String, Codable, CaseIterable, Identifiable {
    case desktop, desktopCode, vscode
    public var id: String { rawValue }
    public var title: String {
        switch self { case .desktop: return "Claude 桌面聊天"; case .desktopCode: return "桌面 Code"; case .vscode: return "VS Code 插件" }
    }
    public var hosts: [String] {
        switch self {
        case .desktop: return ["claude.ai", "platform.claude.com"]
        case .desktopCode, .vscode: return ["claude.ai", "api.anthropic.com", "platform.claude.com"]
        }
    }
}
public struct NetworkCheck: Codable, Identifiable {
    public let id: String
    public let title: String
    public let result: CheckResult
    public let required: Bool
    public let detail: String
    public init(_ id: String, _ title: String, _ result: CheckResult, required: Bool = true, _ detail: String) {
        self.id = id; self.title = title; self.result = result; self.required = required; self.detail = detail
    }
}
public struct PreflightSettings: Codable, Equatable {
    public var expectedIP = ""
    // Decode legacy values so they can be explicitly rejected, never silently cleared.
    public var expectedIPv6 = ""
    public var notifications = true
    public init() {}
    public static let url = Paths.root.appendingPathComponent("preflight-settings.json")
    public func validate() throws {
        guard expectedIPv6.isEmpty else {
            throw LauncherError.message("旧设置含 IPv6 出口基准；请明确移除后重新检查。当前仅接受 IPv4 出口。")
        }
        guard normalizedIPv4(expectedIP) != nil else {
            throw LauncherError.message("请填写确认的固定 IPv4 出口。")
        }
    }
    public static func read() throws -> Self { try loadJSON(Self.self, from: url) }
    public static func read(from url: URL) throws -> Self { try loadJSON(Self.self, from: url) }
    /// Only a missing directory entry is a confirmed first run. A path that exists but
    /// cannot be read — dangling symlink, directory, permissions, corrupt JSON — throws.
    public static func readIfPresent(_ url: URL = Self.url) throws -> Self? {
        var info = stat()
        guard lstat(url.path, &info) == 0 else {
            if errno == ENOENT { return nil }
            throw LauncherError.message("无法检查预检配置路径；已保留原状态。")
        }
        return try read(from: url)
    }
    public var fingerprint: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return ManagedAddressPolicy.fingerprint((try? encoder.encode(self)) ?? Data())
    }
    public func matches(_ ip: String) -> Bool {
        guard expectedIPv6.isEmpty, let observed = normalizedIPv4(ip),
              let expected = normalizedIPv4(expectedIP) else { return false }
        return observed == expected
    }
}
public func fingerprintData(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

public struct DomainObservation: Codable, Identifiable {
    public var id: String { host }
    public let host: String
    public let ip: String?
    public let country: String?
    public let transport: String
    public let milliseconds: Int
    public let check: NetworkCheck
}
public struct PreflightReport: Codable {
    public let target: CheckTarget
    public let startedAt: Date
    public let completedAt: Date
    public let context: String
    public let checks: [NetworkCheck]
    public let observations: [DomainObservation]
    public var failures: [NetworkCheck] { checks.filter { $0.required && $0.result != .passed } }
    public func permits(context current: String, now: Date = Date()) -> Bool {
        let age = now.timeIntervalSince(startedAt)
        let mandatory = Set(["baseline", "client", "transport", "unchanged", "service"] + target.hosts.map { "exit:" + $0 } + (target == .vscode ? ["plugin-gate", "code-network", "uniform-proxy"] : []))
        let ids = checks.map(\.id)
        return context == current && age >= 0 && age <= 30 && completedAt >= startedAt && completedAt <= now &&
            Set(ids).count == ids.count && mandatory.isSubset(of: Set(ids)) &&
            mandatory.allSatisfy { id in checks.contains { $0.id == id && $0.required && $0.result == .passed } } && failures.isEmpty
    }
    public var summary: String { failures.first?.detail ?? "启动前探测通过；实际会话路径需运行后观测。" }
}

public enum TraceResponse {
    /// A Cloudflare trace is accepted only from the requested HTTPS origin with a
    /// successful response; redirects, HTML challenge pages and duplicate IPs fail.
    public static func parse(_ body: String, status: Int) -> (ip: String, country: String)? {
        guard status == 200, body.utf8.count <= 16384 else { return nil }
        var fields: [String: String] = [:]
        for line in body.split(separator: "\n") {
            let parts = line.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = String(parts[0]); guard fields[key] == nil else { return nil }
            fields[key] = String(parts[1]).trimmingCharacters(in: .whitespacesAndNewlines)
        }
        guard let ip = fields["ip"].flatMap(normalizedIP), let country = fields["loc"],
              country.count == 2, country.allSatisfy({ $0.isASCII && $0.isUppercase }),
              fields["tls"]?.hasPrefix("TLS") == true else { return nil }
        return (ip, country)
    }
}
