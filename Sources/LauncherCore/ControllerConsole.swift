import Foundation
import Security

public struct ControllerConfiguration: Codable {
    public var endpoint: String
    public init(endpoint: String = "") { self.endpoint = endpoint }
    public static let url = Paths.root.appendingPathComponent("console-controller.json")
    public static func canonicalEndpoint(_ value: String) throws -> String {
        guard value.range(of: #"^http://(127\.0\.0\.1|\[::1\]):[0-9]{1,5}/?$"#, options: .regularExpression) != nil,
              let u = URLComponents(string: value), let port = u.port, (1...65535).contains(port) else {
            throw LauncherError.message("只接受 http://127.0.0.1:端口 或 http://[::1]:端口。请填写控制接口，不是 HTTP 代理入口。")
        }
        return "http://\(value.contains("[::1]") ? "[::1]" : "127.0.0.1"):\(port)"
    }
    public static func validateToken(_ token: String) throws {
        guard !token.isEmpty, token.utf8.count <= 4096,
              token.unicodeScalars.allSatisfy({ (33...126).contains($0.value) }) else {
            throw LauncherError.message("请填写控制接口的 Secret；只接受 1–4096 个可打印 ASCII 字符（不含空格）。")
        }
    }
    public static func read() throws -> Self {
        guard FileManager.default.fileExists(atPath: url.path) else { return .init() }
        var value = try loadJSON(Self.self, from: url)
        if !value.endpoint.isEmpty { value.endpoint = try canonicalEndpoint(value.endpoint) }
        return value
    }
    public func save() throws {
        let value = Self(endpoint: endpoint.isEmpty ? "" : try Self.canonicalEndpoint(endpoint))
        try Paths.prepare(); try saveJSON(value, to: Self.url)
    }
}

public enum ControllerCredentials {
    private static func query(_ endpoint: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "local.claude-launcher.controller",
         kSecAttrAccount as String: fingerprintData(Data(endpoint.utf8))]
    }
    public static func read(endpoint: String) throws -> String {
        var request = query(try ControllerConfiguration.canonicalEndpoint(endpoint)); request[kSecReturnData as String] = true
        request[kSecMatchLimit as String] = kSecMatchLimitOne
        var value: CFTypeRef?
        guard SecItemCopyMatching(request as CFDictionary, &value) == errSecSuccess,
              let data = value as? Data, let token = String(data: data, encoding: .utf8) else {
            throw LauncherError.message("钥匙串中没有可读取的 Secret，请在接入设置中重新填写。")
        }
        try ControllerConfiguration.validateToken(token); return token
    }
    public static func save(_ token: String, endpoint: String) throws {
        try ControllerConfiguration.validateToken(token)
        let request = query(try ControllerConfiguration.canonicalEndpoint(endpoint)), data = Data(token.utf8)
        var result = SecItemUpdate(request as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if result == errSecItemNotFound {
            var item = request; item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            result = SecItemAdd(item as CFDictionary, nil)
        }
        guard result == errSecSuccess else { throw LauncherError.message("无法保存控制接口 Secret 到钥匙串。") }
    }
}

public struct ControllerConnection: Decodable, Identifiable {
    public let id: String
    public let process: String
    public let host: String
    public let port: String
    public let network: String
    public let chains: [String]
    public let rule: String
    public let upload: Int64
    public let download: Int64
}
public struct ControllerSnapshot: Decodable {
    public let endpoint: String
    public let startedAt: Double
    public let completedAt: Double
    public let version: String
    public let mode: String
    public let tun: Bool?
    public let ipv6: Bool?
    public let ruleCount: Int
    public let proxyCount: Int
    public let totalConnections: Int
    public let upload: Int64
    public let download: Int64
    public let connections: [ControllerConnection]
    public func isCurrent(endpoint: String, now: Date = Date()) -> Bool {
        let time = now.timeIntervalSince1970
        return self.endpoint == endpoint && startedAt.isFinite && completedAt.isFinite &&
            startedAt <= completedAt && completedAt <= time && time - startedAt <= 20
    }
}

public enum ControllerProbe {
    public static func read(endpoint: String, helper: URL) throws -> ControllerSnapshot {
        let address = try ControllerConfiguration.canonicalEndpoint(endpoint)
        let token = try ControllerCredentials.read(endpoint: address)
        let input = try JSONSerialization.data(withJSONObject: ["endpoint": address, "token": token])
        guard input.count <= 16384 else { throw LauncherError.message("控制接口凭据封套超过长度上限。") }
        let result = ReadCommand.run("/usr/bin/python3", ["-I", "-B", helper.path], timeout: 14,
                                     environment: ["PATH": "/usr/bin:/bin"], input: input)
        if result.code == 0, let data = result.text.data(using: .utf8),
           let snapshot = try? JSONDecoder().decode(ControllerSnapshot.self, from: data),
           snapshot.isCurrent(endpoint: address) { return snapshot }
        // Never display arbitrary helper/remote output, including reflected credentials.
        throw LauncherError.message("控制接口读取失败：请核对地址、Secret 和客户端状态；拒绝重定向、不完整或过期数据。")
    }
}
