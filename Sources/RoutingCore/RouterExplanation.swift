import Foundation

public struct RouterFlow: Codable {
    public enum Transport: String, Codable { case tcp, udp }
    public var processPath: String?
    public var domain: String?
    public var transport: Transport
    public init(processPath: String? = nil, domain: String? = nil, transport: Transport) {
        self.processPath = processPath; self.domain = domain; self.transport = transport
    }
}

public struct RouterExplanation: Encodable {
    public let mode = "offline_explanation"
    public let networkModified = false
    public let runtimeVerified = false
    public let status: String
    public let ruleID: UUID?
    public let destination: RouterDestination?
    public let reason: String
}

public enum RouterExplainer {
    private enum Match { case yes, no, unknown }

    public static func explain(_ plan: RouterPlan, flow: RouterFlow) throws -> RouterExplanation {
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else {
            throw RouterInputError("invalid_plan")
        }
        if let process = flow.processPath, !RouterValidation.validProcessPath(process) { throw RouterInputError("invalid_flow_process") }
        if let domain = flow.domain, !RouterValidation.validDomain(domain) { throw RouterInputError("invalid_flow_domain") }
        let proxies = Dictionary(uniqueKeysWithValues: plan.proxies.map { ($0.id, $0) })
        func decision(_ destination: RouterDestination, ruleID: UUID?) -> RouterExplanation {
            let blocked = flow.transport == .udp && MihomoRoutingCompiler.blocksUDP(destination, proxies: proxies)
            return .init(status: "planned", ruleID: ruleID, destination: blocked ? .block : destination,
                         reason: blocked ? "proxy_udp_not_supported" : (ruleID == nil ? "explicit_default" : "first_matching_rule"))
        }
        for rule in plan.rules {
            switch match(rule.selector, flow) {
            case .no: continue
            case .unknown:
                // A later/default rule cannot resolve an earlier unknown identity.
                return .init(status: "undetermined", ruleID: rule.id, destination: nil,
                             reason: "earlier_rule_needs_missing_identity")
            case .yes: return decision(rule.destination, ruleID: rule.id)
            }
        }
        return decision(plan.defaultDestination, ruleID: nil)
    }

    private static func match(_ selector: RouterSelector, _ flow: RouterFlow) -> Match {
        var unknown = false
        if let expected = selector.processPath {
            if let actual = flow.processPath {
                // Mihomo PROCESS-PATH performs case-insensitive matching.
                if actual.lowercased() != expected.lowercased() { return .no }
            } else { unknown = true }
        }
        if let expected = selector.domain {
            if let actual = flow.domain {
                if !RouterValidation.domainMatches(expected, actual) { return .no }
            } else { unknown = true }
        }
        return unknown ? .unknown : .yes
    }
}
