import Foundation
import CryptoKit
import Security

public struct RouterRuntimeSummary: Codable, Equatable {
    public let mode: String
    public let coreVersion: String
    public let planDigest: String
    public let controllerPort: UInt16
    public let proxyCount: Int
    public let ruleCount: Int
    public let tunEnabled: Bool
    public let routingVerified: Bool
    public let networkSettingsModified: Bool
}

/// Sensitive representation. Only the runtime writer can persist this; never return it in reports.
public struct RouterRuntimeConfiguration {
    let privateJSON: Data
    public let summary: RouterRuntimeSummary
}

public enum RouterRuntimeCompiler {
    public static func randomSecret() throws -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw RouterRuntimeError.invalidController
        }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func compile(_ plan: RouterPlan, controllerPort: UInt16, secret: String,
                               resolve: (UUID) throws -> RouterCredential = RouterCredentialVault.read) throws -> RouterRuntimeConfiguration {
        guard controllerPort > 1024, secret.count == 64,
              secret.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw RouterRuntimeError.invalidController
        }
        let routing = try RouterCompiledRouting.compile(plan, resolve: resolve)
        let data = try routing.document(controllerPort: controllerPort, secret: secret,
            tun: ["enable": false, "auto-route": false, "dns-hijack": []], dns: ["enable": false])
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let digest = SHA256.hash(data: try encoder.encode(plan)).map { String(format: "%02x", $0) }.joined()
        // Mihomo parses YAML; its parser rejects JSON's optional \/ escaping.
        return .init(privateJSON: data,
                     summary: .init(mode: "controlOnly", coreVersion: RouterCoreRelease.version, planDigest: digest,
                                    controllerPort: controllerPort, proxyCount: routing.proxies.count, ruleCount: routing.rules.count,
                                    tunEnabled: false, routingVerified: false, networkSettingsModified: false))
    }
}
