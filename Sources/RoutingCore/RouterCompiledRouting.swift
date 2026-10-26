import Foundation

/// Shared private output for both runtime modes. Never encode it in a public report.
struct RouterCompiledRouting {
    let proxies: [[String: Any]]
    let rules: [String]

    static func compile(_ plan: RouterPlan, resolve: (UUID) throws -> RouterCredential) throws -> Self {
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else {
            throw RouterRuntimeError.invalidPlan
        }
        var publicPlan = plan
        for index in publicPlan.proxies.indices { publicPlan.proxies[index].credentialReference = nil }
        guard let fragment = try MihomoRoutingCompiler.preview(publicPlan).fragment else { throw RouterRuntimeError.invalidPlan }
        let proxies = try fragment.proxies.enumerated().map { index, proxy -> [String: Any] in
            var result: [String: Any] = ["name": proxy.name, "type": proxy.type, "server": proxy.server,
                                         "port": proxy.port, "udp": proxy.udp]
            if let reference = plan.proxies[index].credentialReference {
                do {
                    let value = try resolve(reference)
                    try value.validate()
                    result["username"] = value.username; result["password"] = value.password
                } catch { throw RouterRuntimeError.credentialUnavailable }
            }
            return result
        }
        return .init(proxies: proxies, rules: fragment.rules)
    }

    func document(controllerPort: UInt16, secret: String, ipv6: Bool? = nil,
                  tun: [String: Any], dns: [String: Any]) throws -> Data {
        guard controllerPort > 1024, secret.count == 64,
              secret.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else { throw RouterRuntimeError.invalidController }
        var result: [String: Any] = [
            "mode": "rule", "find-process-mode": "strict", "allow-lan": false, "bind-address": "127.0.0.1",
            "port": 0, "socks-port": 0, "mixed-port": 0, "redir-port": 0, "tproxy-port": 0,
            "external-controller": "127.0.0.1:\(controllerPort)",
            "external-controller-cors": ["allow-origins": [], "allow-private-network": false],
            "secret": secret, "log-level": "silent", "geo-auto-update": false,
            "ntp": ["enable": false, "write-to-system": false],
            "profile": ["store-selected": false, "store-fake-ip": false],
            "tun": tun, "dns": dns, "proxies": proxies, "rules": rules
        ]
        if let ipv6 { result["ipv6"] = ipv6 }
        return try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys, .withoutEscapingSlashes])
    }
}
