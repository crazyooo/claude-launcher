import Foundation

/// An incomplete, inactive worksheet. Never converted to production configuration automatically.
public struct ShadowrocketDraft: Codable, Equatable {
    public var protocolName = ""
    public var host = ""
    public var port = ""
    public var expectedIP = ""
    public init() {}
    public static var url: URL { Paths.root.appendingPathComponent("shadowrocket-draft.json") }

    public func validated() throws -> Self {
        var value = self
        value.protocolName = protocolName.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        value.host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        value.port = port.trimmingCharacters(in: .whitespacesAndNewlines)
        value.expectedIP = expectedIP.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ["", "http", "socks5"].contains(value.protocolName) else {
            throw LauncherError.message("请选择 HTTP 或 SOCKS5，也可以暂不填写")
        }
        guard ["", "127.0.0.1"].contains(value.host) else {
            throw LauncherError.message("本地代理入口仅接受 IPv4 回环地址 127.0.0.1")
        }
        if !value.port.isEmpty {
            guard value.port.utf8.allSatisfy({ (48...57).contains($0) }),
                  let number = Int(value.port), (1...65535).contains(number) else {
                throw LauncherError.message("端口应为 1–65535，也可以暂不填写")
            }
            value.port = String(number)
        }
        if !value.expectedIP.isEmpty {
            guard value.expectedIP.utf8.allSatisfy({ "0123456789abcdefABCDEF:.".utf8.contains($0) }),
                  let ip = normalizedIPv4(value.expectedIP) else {
                throw LauncherError.message("预期出口应为有效的 IPv4 地址")
            }
            value.expectedIP = ip
        }
        return value
    }

    public var endpointDescription: String {
        guard !protocolName.isEmpty, !host.isEmpty, !port.isEmpty else { return "待填写" }
        return "\(protocolName.uppercased()) \(host == "::1" ? "[::1]" : host):\(port) · 草稿"
    }

    public func save() throws {
        let value = try validated()
        try FileManager.default.createDirectory(at: Paths.root, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: 0o700])
        try saveJSON(value, to: Self.url)
    }
}

public enum ShadowrocketVPNState: String, Codable {
    case connected, disconnected, connecting, disconnecting, reasserting, invalid, unknown
    public static func parse(_ output: String) -> Self {
        guard let first = output.split(whereSeparator: \.isNewline).first else { return .unknown }
        return Self(rawValue: first.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) ?? .unknown
    }
    public var title: String {
        switch self {
        case .connected: return "已连接 · 未验证保护"
        case .disconnected: return "未连接"
        case .connecting: return "连接中"
        case .disconnecting: return "断开中"
        case .reasserting: return "重新连接中"
        case .invalid: return "VPN 配置不可用"
        case .unknown: return "状态未知"
        }
    }
}

public struct ShadowrocketLocalStatus: Codable {
    public var installed = false
    public var version: String?
    public var vpn: ShadowrocketVPNState = .unknown
    public var detail = "尚未读取本机状态"
    public var checkedAt: Date?
    public init() {}
}

public enum ShadowrocketLocal {
    public static let bundleID = "com.liguangming.Shadowrocket"

    public static func serviceIDs(in listing: String) -> [String] {
        let pattern = #"^\s*\*?\s*\([^)]+\)\s+([0-9A-Fa-f-]{36})\s+VPN\s+\(com\.liguangming\.Shadowrocket\)(?:\s|$)"#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
        let matches = listing.components(separatedBy: .newlines).compactMap { line -> String? in
            guard let match = expression.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  let range = Range(match.range(at: 1), in: line),
                  let identifier = UUID(uuidString: String(line[range])) else { return nil }
            return identifier.uuidString
        }
        return Array(Set(matches)).sorted()
    }

    /// These are exclusively read operations; never start the app, connect VPN, or probe the Internet.
    public static func read() -> ShadowrocketLocalStatus {
        var result = ShadowrocketLocalStatus()
        result.checkedAt = Date()
        let applications = [URL(fileURLWithPath: "/Applications/Shadowrocket.app"),
                            FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/Shadowrocket.app")]
        if let bundle = applications.compactMap({ Bundle(url: $0) }).first(where: { $0.bundleIdentifier == bundleID }) {
            result.installed = true
            result.version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        }
        do {
            let list = try Subprocess.capture("/usr/sbin/scutil", ["--nc", "list"], timeout: 3)
            guard list.0 == 0 else { result.detail = "无法读取系统 VPN 列表"; return result }
            let ids = serviceIDs(in: list.1)
            guard ids.count == 1 else {
                result.detail = ids.isEmpty ? "未找到小火箭 VPN 配置" : "存在多个小火箭 VPN 配置，需人工确认"
                return result
            }
            let state = try Subprocess.capture("/usr/sbin/scutil", ["--nc", "status", ids[0]], timeout: 3)
            guard state.0 == 0 else { result.detail = "无法读取小火箭 VPN 状态"; return result }
            result.vpn = ShadowrocketVPNState.parse(state.1)
            result.detail = "仅读取系统状态；入口、出口和断流能力未验证"
        } catch {
            result.detail = "本机状态读取失败，请稍后刷新"
        }
        return result
    }
}
