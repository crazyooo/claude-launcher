import Foundation

public struct RouterSystemConfigurationSummary: Encodable {
    public let mode = "systemTUN"
    public let coreVersion = RouterCoreRelease.version
    public let planDigest: String
    public let profile: RouterSystemProfile
    public let resolverDomain: String
    public let bootstrapResolvers: [String]
    public let resolverRoute: String
    // Pinned Mihomo parses these resolver lists outside respect-rules.
    // They are explicit control-plane exceptions, not evidence of observed traffic.
    public let bootstrapRoute = "direct_control_plane_planned"
    public let proxyHostnameResolverRoute = "direct_control_plane_planned"
    public let controllerPort: UInt16
    public let fakeIPv4Range: String
    public let fakeIPv6Range: String
    public let proxyCount: Int
    public let ruleCount: Int
    public let routingVerified = false
    public let networkSettingsModified = false
}

/// A distinct type prevents passing a TUN document to the control-only launcher.
public struct RouterSystemConfiguration {
    let privateJSON: Data
    public let summary: RouterSystemConfigurationSummary
}

public enum RouterSystemCompiler {
    public static let policyVersion = 2
    public static let controllerPort: UInt16 = 19492
    public static let fakeIPv4 = "198.18.0.1/16"
    public static let fakeIPv6 = "fdfe:dcba:9876::/48"
    public static let tunIPv6 = "fdfe:dcba:9876::1/126"

    /// Shared profile facts for emitted configuration and offline acceptance coverage.
    /// `servers` holds the exact `nameserver`/`proxy-server-nameserver` entries. DoH
    /// archetypes resolve their hostname through `bootstrap` literals; the plain
    /// archetype is UDP-literal-only with no hostname and therefore no bootstrap hop.
    struct Resolver {
        let domain: String
        let bootstrap: [String]
        let servers: [String]
        init(_ selection: RouterSystemProfile.Resolver) {
            switch selection {
            case .cloudflare:
                domain = "cloudflare-dns.com"; bootstrap = ["1.1.1.1", "1.0.0.1"]
                servers = ["https://cloudflare-dns.com/dns-query"]
            case .quad9:
                domain = "dns.quad9.net"; bootstrap = ["9.9.9.9", "149.112.112.112"]
                servers = ["https://dns.quad9.net/dns-query"]
            case .plain:
                // UDP-literal resolvers for networks where foreign DoH and its bootstrap
                // literals are unreachable: a dead upstream inside a fake-ip takeover
                // silently blackholes every hostname on the host (live evidence
                // 2026-10-25 matrix window, Cloudflare DoH unreachable on this LAN).
                domain = "223.5.5.5"; bootstrap = ["223.5.5.5", "119.29.29.29"]
                servers = ["223.5.5.5", "119.29.29.29"]
            }
        }
    }

    static func resolverExplanation(plan: RouterPlan, profile: RouterSystemProfile) throws -> RouterExplanation {
        // Pinned DNSDialer uses INNER metadata without process lookup. This is only
        // a diagnostic projection; compile still emits every original routing rule.
        var projection = plan
        projection.rules.removeAll { $0.selector.processPath != nil }
        if profile.resolver == .plain {
            // The plain archetype's resolver endpoints are IP literals: plan rules
            // cannot express an IP selector (validDomain rejects literals) and inner
            // DNS carries no process identity, so every domain rule misses and the
            // resolver route is always the plan's default destination.
            return .init(status: "planned", ruleID: nil, destination: plan.defaultDestination,
                         reason: "explicit_default")
        }
        return try RouterExplainer.explain(projection,
            flow: .init(domain: Resolver(profile.resolver).domain, transport: .tcp))
    }

    public static func digest(plan: RouterPlan, profile: RouterSystemProfile) throws -> String {
        struct Binding: Encodable {
            let policyVersion: Int
            let coreVersion: String
            let plan: RouterPlan
            let profile: RouterSystemProfile
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return RouterSystemObservation.hash(try encoder.encode(Binding(policyVersion: policyVersion,
            coreVersion: RouterCoreRelease.version, plan: plan, profile: profile)))
    }

    public static func compile(plan: RouterPlan, profile: RouterSystemProfile, secret: String,
                               credentials: [UUID: RouterCredential]) throws -> RouterSystemConfiguration {
        guard Set(credentials.keys) == Set(plan.proxies.compactMap(\.credentialReference)) else { throw RouterSystemError.invalidCredentials }
        for value in credentials.values {
            do { try value.validate() } catch { throw RouterSystemError.invalidCredentials }
        }
        let routing = try RouterCompiledRouting.compile(plan) { reference in
            guard let value = credentials[reference] else { throw RouterSystemError.invalidCredentials }
            return value
        }
        let resolver = Resolver(profile.resolver)
        let explanation = try resolverExplanation(plan: plan, profile: profile)
        let resolverRoute: String
        if explanation.status == "undetermined" { resolverRoute = "resolver_route_undetermined" }
        else if explanation.destination == .block { resolverRoute = "resolver_route_blocked" }
        else { resolverRoute = "resolver_route_planned_not_verified" }
        let data = try routing.document(controllerPort: controllerPort, secret: secret, ipv6: true,
            tun: ["enable": true, "stack": "mixed", "auto-route": true, "auto-detect-interface": true,
                  "auto-redirect": false, "inet6-address": [tunIPv6], "dns-hijack": ["any:53", "tcp://any:53"]],
            dns: ["enable": true, "ipv6": true, "enhanced-mode": "fake-ip", "fake-ip-range": fakeIPv4,
                  "fake-ip-range6": fakeIPv6, "respect-rules": true, "prefer-h3": false,
                  "default-nameserver": resolver.bootstrap, "nameserver": resolver.servers,
                  "proxy-server-nameserver": resolver.servers])
        return .init(privateJSON: data, summary: .init(planDigest: try digest(plan: plan, profile: profile),
            profile: profile, resolverDomain: resolver.domain, bootstrapResolvers: resolver.bootstrap,
            resolverRoute: resolverRoute, controllerPort: controllerPort, fakeIPv4Range: fakeIPv4,
            fakeIPv6Range: fakeIPv6, proxyCount: routing.proxies.count, ruleCount: routing.rules.count))
    }
}
