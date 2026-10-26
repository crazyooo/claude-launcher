import Foundation

enum RouterControlPlaneRole: String, Encodable, Hashable {
    case mainResolver, bootstrapResolver, proxyHostnameResolver
}

enum RouterControlPlaneQuery: String, Encodable, CaseIterable, Hashable {
    case a = "A", aaaa = "AAAA"
}

struct RouterControlPlaneCase: Encodable, Hashable {
    let role: RouterControlPlaneRole
    let proxyID: UUID?
    let bootstrapAddress: String?
    let transport: RouterTrafficTransport
    /// Family of this DNS/HTTPS hop, independent of the DNS question/answer family.
    let family: RouterTrafficFamily
    let query: RouterControlPlaneQuery
}

/// Private, derived assessment only. A recipe is neither an observation nor a
/// capability to collect traffic; no caller-supplied recipe can grant acceptance.
struct RouterControlPlaneRequirement: Encodable {
    enum RouteBasis: String, Encodable {
        case innerProcessSelectorsExcluded, bootstrapDirectException, proxyHostnameDirectException
    }
    enum ResponseRequirement: String, Encodable {
        case controlledQueryRecipeMissing, matchingQuestionAndUpstreamAnswerRequired
    }

    let id: RouterControlPlaneCase
    let resolverHost: String
    let resolverAddress: String?
    let port: UInt16
    let httpsPath: String?
    let questionName: String?
    let queryClass: UInt16 = 1
    let expectedDestination: RouterDestination?
    let projectedRuleID: UUID?
    let routeBasis: RouteBasis
    let responseRequirement: ResponseRequirement
    let gaps: [RouterTrafficGap]
    let collectorAuthenticated = false
    let canPromoteAccepted = false
}

enum RouterControlPlaneCoverage {
    // Separate from immutable receipt v1, application coverage v1 and compiler v2.
    static let version = 1
    static let maximumCases = 1024

    static func requirements(plan: RouterPlan, profile: RouterSystemProfile) throws -> [RouterControlPlaneRequirement] {
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else {
            throw RouterTrafficEvidenceError.invalidPlan
        }
        let resolver = RouterSystemCompiler.Resolver(profile.resolver)
        let mainRoute = try RouterSystemCompiler.resolverExplanation(plan: plan, profile: profile)
        var required: [RouterControlPlaneRequirement] = []

        func appendDoH(role: RouterControlPlaneRole, proxyID: UUID? = nil, question: String?,
                       destination: RouterDestination?, rule: UUID? = nil,
                       basis: RouterControlPlaneRequirement.RouteBasis) {
            var gaps: [RouterTrafficGap] = [.notRun, .liveCollectorUnavailable, .endpointUnavailable]
            if question == nil { gaps.append(.controlPlaneRecipeMissing) }
            if destination == nil { gaps.append(.ruleUncorrelated) }
            for family in [RouterTrafficFamily.ipv4, .ipv6] {
                for query in RouterControlPlaneQuery.allCases {
                    required.append(.init(
                        id: .init(role: role, proxyID: proxyID, bootstrapAddress: nil,
                                  transport: .tcp, family: family, query: query),
                        resolverHost: resolver.domain, resolverAddress: nil, port: 443,
                        httpsPath: "/dns-query", questionName: question,
                        expectedDestination: destination, projectedRuleID: rule, routeBasis: basis,
                        responseRequirement: question == nil ? .controlledQueryRecipeMissing :
                            .matchingQuestionAndUpstreamAnswerRequired,
                        gaps: gaps.sorted { $0.rawValue < $1.rawValue }))
                }
            }
        }

        func appendPlain(role: RouterControlPlaneRole, proxyID: UUID? = nil, question: String?,
                         destination: RouterDestination?, rule: UUID? = nil,
                         basis: RouterControlPlaneRequirement.RouteBasis) throws {
            // UDP-literal archetype: each configured server is one direct udp/53 hop.
            // There is no DoH hostname, no https endpoint and no separate bootstrap
            // stage; the ID reuses bootstrapAddress to carry the literal endpoint.
            var gaps: [RouterTrafficGap] = [.notRun, .liveCollectorUnavailable, .endpointUnavailable]
            if question == nil { gaps.append(.controlPlaneRecipeMissing) }
            if destination == nil { gaps.append(.ruleUncorrelated) }
            for address in resolver.servers {
                guard RouterTrafficAddress.bytes(address)?.count == 4 else {
                    throw RouterTrafficEvidenceError.invalidPlan
                }
                for query in RouterControlPlaneQuery.allCases {
                    required.append(.init(
                        id: .init(role: role, proxyID: proxyID, bootstrapAddress: address,
                                  transport: .udp, family: .ipv4, query: query),
                        resolverHost: address, resolverAddress: address, port: 53,
                        httpsPath: nil, questionName: question,
                        expectedDestination: destination, projectedRuleID: rule, routeBasis: basis,
                        responseRequirement: question == nil ? .controlledQueryRecipeMissing :
                            .matchingQuestionAndUpstreamAnswerRequired,
                        gaps: gaps.sorted { $0.rawValue < $1.rawValue }))
                }
            }
        }

        if profile.resolver == .plain {
            try appendPlain(role: .mainResolver, question: nil, destination: mainRoute.destination,
                            rule: mainRoute.ruleID, basis: .innerProcessSelectorsExcluded)
        } else {
            appendDoH(role: .mainResolver, question: nil, destination: mainRoute.destination,
                      rule: mainRoute.ruleID, basis: .innerProcessSelectorsExcluded)

            for address in resolver.bootstrap {
                // Both supported profiles specify IPv4 literals. Do not silently omit
                // coverage if a future profile introduces a different kind of endpoint.
                guard RouterTrafficAddress.bytes(address)?.count == 4 else {
                    throw RouterTrafficEvidenceError.invalidPlan
                }
                for transport in [RouterTrafficTransport.udp, .tcp] {
                    for query in RouterControlPlaneQuery.allCases {
                        required.append(.init(
                            id: .init(role: .bootstrapResolver, proxyID: nil, bootstrapAddress: address,
                                      transport: transport, family: .ipv4, query: query),
                            resolverHost: address, resolverAddress: address, port: 53,
                            httpsPath: nil, questionName: resolver.domain, expectedDestination: .direct,
                            projectedRuleID: nil, routeBasis: .bootstrapDirectException,
                            responseRequirement: .matchingQuestionAndUpstreamAnswerRequired,
                            gaps: [.liveCollectorUnavailable, .notRun]))
                    }
                }
            }
        }

        // Keep each proxy's obligation, even for unused proxies or shared hosts.
        // Literals do not require hostname resolution; canonicalization is DNS-only.
        for proxy in plan.proxies where !RouterValidation.isIP(proxy.host) {
            if profile.resolver == .plain {
                try appendPlain(role: .proxyHostnameResolver, proxyID: proxy.id,
                                question: proxy.host.lowercased(), destination: .direct,
                                basis: .proxyHostnameDirectException)
            } else {
                appendDoH(role: .proxyHostnameResolver, proxyID: proxy.id,
                          question: proxy.host.lowercased(), destination: .direct,
                          basis: .proxyHostnameDirectException)
            }
        }
        guard required.count <= maximumCases, Set(required.map(\.id)).count == required.count else {
            throw RouterTrafficEvidenceError.limitExceeded
        }
        return required
    }
}
