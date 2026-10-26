import Foundation
import CryptoKit
import Security
import Darwin

/// Local proxy policy; domain resolution inside the upstream remains external.
public enum ManagedAddressPolicy {
    public static let revision = "managed-ipv4-only-v1"
    static func fingerprint(_ encoded: Data) -> String {
        fingerprintData(Data((revision + "\n").utf8) + encoded)
    }
}

/// Reject mapped IPv6, abbreviated numbers and embedded NUL before C parsing.
public func normalizedIPv4(_ value: String) -> String? {
    let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !clean.isEmpty, clean.utf8.allSatisfy({ (48...57).contains($0) || $0 == 46 }) else { return nil }
    var address = in_addr()
    guard inet_pton(AF_INET, clean, &address) == 1 else { return nil }
    var bytes = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
    guard inet_ntop(AF_INET, &address, &bytes, socklen_t(bytes.count)) != nil else { return nil }
    return String(cString: bytes)
}

public enum LauncherError: Error, LocalizedError {
    case message(String)
    public var errorDescription: String? { if case .message(let s) = self { return s }; return nil }
}
public enum Paths {
    public static let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ClaudeLauncher")
    public static let config = root.appendingPathComponent("config.json")
    public static let status = root.appendingPathComponent("status.json")
    public static let socket = root.appendingPathComponent("control.sock").path
    public static let wrapper = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/claude-process-wrapper").path
    public static let cli = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".local/bin/claude").path
    public static let desktop = "/Applications/Claude.app/Contents/MacOS/Claude"
    public static func prepare() throws {
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try FileManager.default.createDirectory(at: root.appendingPathComponent("sessions"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    }
}
public func saveJSON<T: Encodable>(_ value: T, to url: URL) throws {
    let data = try JSONEncoder().encode(value)
    try data.write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
}
public func loadJSON<T: Decodable>(_ type: T.Type, from url: URL) throws -> T {
    try JSONDecoder().decode(type, from: Data(contentsOf: url))
}
public struct Configuration: Codable, Equatable {
    public var officialDesktopConsent: OfficialDesktopConsent?
    public var protocolName = "http"
    public var host = "127.0.0.1"
    public var port = 1082
    public var gatewayPort = 18761
    public var probePort = 18762
    public var expectedIP = ""
    public var confirmed = false
    public var authentication = false
    public init() {}
    public var digest: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return ManagedAddressPolicy.fingerprint((try? encoder.encode(self)) ?? Data())
    }
    public func validate() throws {
        // Upstream is deliberately local: preserve the existing chain and avoid DNS here.
        guard ["http", "socks5"].contains(protocolName), host == "127.0.0.1",
              (1024...65535).contains(gatewayPort), (1024...65535).contains(probePort),
              (1...65535).contains(port), Set([port, gatewayPort, probePort]).count == 3,
              confirmed, normalizedIPv4(expectedIP) != nil else {
            throw LauncherError.message("请确认 127.0.0.1 代理入口及固定 IPv4 出口；三个端口必须不同")
        }
    }
}
public func normalizedIP(_ value: String) -> String? {
    var v4 = in_addr(); var v6 = in6_addr()
    let clean = value.trimmingCharacters(in: .whitespacesAndNewlines)
    var bytes = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
    if inet_pton(AF_INET, clean, &v4) == 1 { inet_ntop(AF_INET, &v4, &bytes, socklen_t(bytes.count)) }
    else if inet_pton(AF_INET6, clean, &v6) == 1 { inet_ntop(AF_INET6, &v6, &bytes, socklen_t(bytes.count)) }
    else { return nil }
    return String(cString: bytes)
}
public struct Credential: Codable { public var username: String; public var password: String
    public init(username: String, password: String) { self.username = username; self.password = password }
}
public enum Vault {
    private static let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: "local.claude-launcher.upstream", kSecAttrAccount as String: "proxy"]
    public static func read() throws -> Credential {
        var q = query; q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?; let result = SecItemCopyMatching(q as CFDictionary, &item)
        guard result == errSecSuccess, let data = item as? Data else { throw LauncherError.message("无法读取代理钥匙串认证信息") }
        return try JSONDecoder().decode(Credential.self, from: data)
    }
    public static func write(_ credential: Credential) throws {
        let data = try JSONEncoder().encode(credential)
        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if status == errSecItemNotFound {
            var q = query; q[kSecValueData as String] = data; q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            guard SecItemAdd(q as CFDictionary, nil) == errSecSuccess else { throw LauncherError.message("钥匙串保存失败") }
        } else if status != errSecSuccess { throw LauncherError.message("钥匙串更新失败") }
    }
}
public struct Event: Codable, Identifiable { public var id = UUID(); public var time = Date(); public var message: String }
public struct Snapshot: Codable {
    public var proxyCheck: ProxyCheckEvidence?
    public var desktopMode: String?
    public var configDigest: String?
    public var state = "unconfigured"
    public var reason = "请完成首次配置"
    public var updated = Date()
    public var lastExitCheck: Date?
    public var observedIP: String?
    public var faultTime: Date?
    public var gatewayReady = false
    public var networkAllowed = false
    public var cliCompatible = false
    public var desktopCompatible = false
    public var sessions = 0
    public var events: [Event] = []
    public init() {}
    public var fresh: Bool { Date().timeIntervalSince(updated) >= -1 && Date().timeIntervalSince(updated) < 3 }
    public var title: String { ["connection-ready":"代理出口已核对", "unconfigured":"未配置", "checking":"检查中", "ready":"可以启动", "running":"运行中", "proxy":"代理不可达", "exit":"出口不匹配", "guard":"守卫故障", "port":"端口冲突", "incompatible":"客户端不兼容", "unmanaged":"发现未受管理的 Claude", "blocked":"网络已阻断"][state] ?? "网络已阻断" }
}
public enum Isolation {
    public static func profile(port: Int) -> String {
        // Strict baseline. GUI Mach exceptions require a new profile and new acceptance.
        "(version 1)\n(allow default)\n(deny network*)\n(deny mach-lookup)\n(allow network-outbound (remote tcp \"localhost:\(port)\"))\n"
    }
    public static func environment(_ original: [String:String], port: Int) -> [String:String] {
        var result = original
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"] { result[key] = "http://127.0.0.1:\(port)" }
        result["NO_PROXY"] = ""; result["no_proxy"] = ""
        result["CLAUDE_CODE_PROCESS_WRAPPER"] = Paths.wrapper
        return result
    }
}
public struct Acceptance: Codable {
    public var fingerprint: String
    public var checks: Set<String>
    public static let required: Set<String> = ["ipv4", "ipv6", "dns", "descendants", "brokers", "streaming", "reconnect", "background", "restart", "update", "window-preservation"]
    public func permits(_ current: String) -> Bool { fingerprint == current && Self.required.isSubset(of: checks) }
}
public func sha256(_ url: URL) throws -> String {
    let handle = try FileHandle(forReadingFrom: url); defer { try? handle.close() }
    var hash = SHA256()
    while let chunk = try handle.read(upToCount: 1024 * 1024), !chunk.isEmpty { hash.update(data: chunk) }
    return hash.finalize().map { String(format: "%02x", $0) }.joined()
}
public enum Compatibility {
    public static func fingerprint(kind: String, port: Int, tool: URL) throws -> String {
        let binary = URL(fileURLWithPath: kind == "cli" ? Paths.cli : Paths.desktop).resolvingSymlinksInPath()
        var components = [ProcessInfo.processInfo.operatingSystemVersionString, try sha256(binary), try sha256(tool), Isolation.profile(port: port)]
        if kind == "desktop" {
            // Include nested helpers/resources, not just the primary executable.
            let base = URL(fileURLWithPath: "/Applications/Claude.app")
            let files = FileManager.default.enumerator(at: base, includingPropertiesForKeys: [.isRegularFileKey])!
            for case let url as URL in files { if (try url.resourceValues(forKeys: [.isRegularFileKey])).isRegularFile == true { components.append(url.path + (try sha256(url))) } }
        }
        return SHA256.hash(data: Data(components.sorted().joined(separator:"\n").utf8)).map { String(format:"%02x",$0) }.joined()
    }
    public static func permits(kind: String, config: Configuration, tool: URL) -> Bool {
        guard let evidence = try? loadJSON(Acceptance.self, from: Paths.root.appendingPathComponent("acceptance-\(kind).json")),
              let current = try? fingerprint(kind: kind, port: config.gatewayPort, tool: tool) else { return false }
        return evidence.permits(current)
    }
}
