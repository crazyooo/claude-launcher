import Foundation
import CryptoKit

public struct MihomoRoutingFragment: Encodable {
    public struct Proxy: Encodable {
        public let name: String
        public let type: String
        public let server: String
        public let port: Int
        public let udp: Bool
    }
    public let proxies: [Proxy]
    public let rules: [String]
}

/// A fragment is NOT a runtime configuration. This type has no apply/start API.
public struct MihomoRoutingPreview: Encodable {
    public let mode = "offline_preview"
    public let networkModified = false
    public let deployable = false
    public let runtimeVerified = false
    public let schemaVersion = 1
    public let planDigest: String
    public let issues: [RouterIssue]
    public let fragment: MihomoRoutingFragment?
    public let pendingRequirements = [
        "pinned_core_version_and_core_validation", "keychain_runtime_secret_resolution",
        "dns_and_process_attribution", "tun_ownership_and_system_permissions",
        "ipv6_and_udp_traffic_acceptance", "transactional_apply_and_rollback",
        "core_exit_blocking_acceptance"
    ]
}

public enum MihomoRoutingCompiler {
    public static func preview(_ plan: RouterPlan) throws -> MihomoRoutingPreview {
        var issues = RouterValidation.issues(in: plan)
        for (index, proxy) in plan.proxies.enumerated() where proxy.credentialReference != nil {
            issues.append(.init("proxies[\(index)].credentialReference", "credential_resolution_not_implemented"))
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let digest = SHA256.hash(data: try encoder.encode(plan)).map { String(format: "%02x", $0) }.joined()
        guard !issues.contains(where: { $0.severity == .error }) else {
            return .init(planDigest: digest, issues: issues, fragment: nil)
        }
        let proxies = Dictionary(uniqueKeysWithValues: plan.proxies.map { ($0.id, $0) })
        var rules: [String] = []
        for rule in plan.rules {
            var predicates: [String] = []
            if let process = rule.selector.processPath { predicates.append("PROCESS-PATH," + process) }
            if let domain = rule.selector.domain {
                predicates.append((domain.kind == .exact ? "DOMAIN," : "DOMAIN-SUFFIX,") + domain.value.lowercased())
            }
            if blocksUDP(rule.destination, proxies: proxies) {
                rules.append(expression(predicates + ["NETWORK,UDP"], destination: "REJECT"))
            }
            rules.append(expression(predicates, destination: try name(rule.destination, proxies: proxies)))
        }
        if blocksUDP(plan.defaultDestination, proxies: proxies) { rules.append("NETWORK,UDP,REJECT") }
        rules.append("MATCH," + (try name(plan.defaultDestination, proxies: proxies)))
        let fragment = MihomoRoutingFragment(proxies: plan.proxies.map {
            .init(name: $0.coreName, type: $0.kind.rawValue, server: $0.host, port: $0.port, udp: $0.supportsUDP)
        }, rules: rules)
        return .init(planDigest: digest, issues: issues, fragment: fragment)
    }

    static func blocksUDP(_ destination: RouterDestination, proxies: [UUID: RouterProxy]) -> Bool {
        guard destination.kind == .proxy, let id = destination.proxyID, let proxy = proxies[id] else { return false }
        return !proxy.supportsUDP
    }
    private static func name(_ destination: RouterDestination, proxies: [UUID: RouterProxy]) throws -> String {
        switch destination.kind {
        case .direct: return "DIRECT"
        case .block: return "REJECT"
        case .proxy:
            guard let id = destination.proxyID, let proxy = proxies[id] else { throw RouterInputError("missing_proxy") }
            return proxy.coreName
        }
    }
    private static func expression(_ predicates: [String], destination: String) -> String {
        if predicates.count == 1 { return predicates[0] + "," + destination }
        return "AND,(" + predicates.map { "(" + $0 + ")" }.joined(separator: ",") + ")," + destination
    }
}
