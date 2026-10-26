import XCTest
@testable import RoutingCore

final class RouterControlPlaneCoverageTests: XCTestCase {
    private let profile = RouterSystemProfile(resolver: .quad9)
    private let emptyPlan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    private let proxyID = UUID(uuidString: "00000000-0000-4000-8000-000000000001")!
    private let reference = UUID(uuidString: "00000000-0000-4000-8000-000000000002")!
    private let ruleID = UUID(uuidString: "00000000-0000-4000-8000-000000000003")!
    private let processPath = "/Applications/Fixture.app/Contents/MacOS/Fixture"

    private var compilerFixture: RouterPlan {
        .init(proxies: [.init(id: proxyID, name: "Fixture", kind: .socks5,
                             host: "Proxy.Example.com", port: 1080, udp: true, credentialReference: reference)],
              rules: [.init(id: ruleID, selector: .init(processPath: processPath), destination: .block)],
              defaultDestination: .proxy(proxyID))
    }

    func testCompilerBytesAndBindingRemainAtPreRefactorBaseline() throws {
        // Captured from the unchanged c1269e6 compiler BEFORE this refactor.
        let baselines: [(RouterSystemProfile.Resolver, String, String)] = [
            (.cloudflare, "38679bf88b0b17b5b8b5facc7f8d6bd73e22f5841530763a4b6dc214bd55ffac",
             "188292060cf4c7c34696d1178dad1254c5eaf55ecc74d0427a5da83d352f7ed6"),
            (.quad9, "f59c68e2888e0e16059ca8c66a9ea09910dd0f5bd7e5a8d74f009fbe7d1f0b04",
             "521fea93e6e42a1c0cbc87d7c31f801dc0f90245b3bdb1d8ba5f4c5908b6693f")
        ]
        for (choice, bytesDigest, planDigest) in baselines {
            let config = try RouterSystemCompiler.compile(plan: compilerFixture,
                profile: .init(resolver: choice), secret: String(repeating: "d", count: 64),
                credentials: [reference: .init(username: "fixture-user", password: "fixture-pass")])
            XCTAssertEqual(RouterSystemObservation.hash(config.privateJSON), bytesDigest)
            XCTAssertEqual(config.summary.planDigest, planDigest)
        }
        XCTAssertEqual(RouterSystemCompiler.policyVersion, 2)
        XCTAssertEqual(RouterTrafficCoveragePolicy.version, 1)
        XCTAssertEqual(RouterControlPlaneCoverage.version, 1)
    }

    func testBothProfilesRequireExactMainAndBootstrapMatrix() throws {
        for (choice, host, addresses) in [
            (RouterSystemProfile.Resolver.cloudflare, "cloudflare-dns.com", ["1.1.1.1", "1.0.0.1"]),
            (.quad9, "dns.quad9.net", ["9.9.9.9", "149.112.112.112"])
        ] {
            let required = try RouterControlPlaneCoverage.requirements(plan: emptyPlan, profile: .init(resolver: choice))
            XCTAssertEqual(required.count, 12)
            XCTAssertEqual(Set(required.map(\.id)).count, 12)
            for family in [RouterTrafficFamily.ipv4, .ipv6] {
                for query in RouterControlPlaneQuery.allCases {
                    let main = try XCTUnwrap(required.first { $0.id == .init(role: .mainResolver, proxyID: nil,
                        bootstrapAddress: nil, transport: .tcp, family: family, query: query) })
                    XCTAssertEqual(main.resolverHost, host)
                    XCTAssertEqual(main.port, 443)
                    XCTAssertEqual(main.httpsPath, "/dns-query")
                    XCTAssertNil(main.resolverAddress)
                    XCTAssertNil(main.questionName)
                    XCTAssertEqual(main.responseRequirement, .controlledQueryRecipeMissing)
                    XCTAssertEqual(Set(main.gaps), [.notRun, .liveCollectorUnavailable,
                                                    .endpointUnavailable, .controlPlaneRecipeMissing])
                }
            }
            for address in addresses {
                for transport in [RouterTrafficTransport.udp, .tcp] {
                    for query in RouterControlPlaneQuery.allCases {
                        let bootstrap = try XCTUnwrap(required.first { $0.id == .init(role: .bootstrapResolver,
                            proxyID: nil, bootstrapAddress: address, transport: transport, family: .ipv4, query: query) })
                        XCTAssertEqual(bootstrap.resolverAddress, address)
                        XCTAssertEqual(bootstrap.questionName, host)
                        XCTAssertEqual(bootstrap.port, 53)
                        XCTAssertEqual(bootstrap.queryClass, 1)
                        XCTAssertNil(bootstrap.httpsPath)
                        XCTAssertEqual(bootstrap.expectedDestination, .direct)
                        XCTAssertEqual(bootstrap.routeBasis, .bootstrapDirectException)
                        XCTAssertEqual(Set(bootstrap.gaps), [.notRun, .liveCollectorUnavailable])
                    }
                }
            }
        }
    }

    func testProxyObligationsIncludeUnusedAndSharedHostsButNotLiterals() throws {
        var plan = emptyPlan
        plan.proxies = ["192.0.2.1", "2001:db8::1", "Proxy.Example.com", "proxy.example.com", "unused.example.com"]
            .map { .init(id: UUID(), name: "Fixture", kind: .socks5, host: $0, port: 1080) }
        let required = try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile)
        XCTAssertEqual(required.count, 24)
        for (index, proxy) in plan.proxies.enumerated() {
            let cases = required.filter { $0.id.proxyID == proxy.id }
            XCTAssertEqual(cases.count, index < 2 ? 0 : 4)
            XCTAssertTrue(cases.allSatisfy {
                $0.questionName == proxy.host.lowercased() && $0.id.role == .proxyHostnameResolver &&
                $0.expectedDestination == .direct && $0.routeBasis == .proxyHostnameDirectException &&
                $0.resolverAddress == nil && $0.gaps.contains(.endpointUnavailable)
            })
        }
        let before = try RouterTrafficCodec.encode(required)
        plan.proxies[2].host = plan.proxies[2].host.lowercased()
        XCTAssertEqual(try RouterTrafficCodec.encode(
            RouterControlPlaneCoverage.requirements(plan: plan, profile: profile)), before)
    }

    func testINNERProjectionPreservesDomainOrderAndDirectExceptions() throws {
        for selector in [RouterSelector(processPath: processPath),
                         .init(processPath: processPath, domain: .init(kind: .exact, value: "dns.quad9.net"))] {
            var plan = compilerFixture
            plan.defaultDestination = .block
            plan.rules = [
                .init(id: UUID(), selector: selector, destination: .block),
                .init(id: ruleID, selector: .init(domain: .init(kind: .exact, value: "dns.quad9.net")),
                      destination: .proxy(proxyID)),
                .init(id: UUID(), selector: .init(domain: .init(kind: .suffix, value: "quad9.net")),
                      destination: .direct)
            ]
            for destination in [RouterDestination.proxy(proxyID), .block, .direct] {
                plan.rules[1].destination = destination
                let required = try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile)
                XCTAssertTrue(required.filter { $0.id.role == .mainResolver }.allSatisfy {
                    $0.expectedDestination == destination && $0.projectedRuleID == ruleID &&
                    $0.routeBasis == .innerProcessSelectorsExcluded && $0.gaps.contains(.notRun)
                })
                XCTAssertTrue(required.filter { $0.id.role != .mainResolver }.allSatisfy {
                    $0.expectedDestination == .direct && $0.projectedRuleID == nil
                })
                XCTAssertEqual(try RouterExplainer.explain(plan, flow: .init(domain: "dns.quad9.net", transport: .tcp)).status,
                               "undetermined")
            }
            // Selecting another profile restores the explicit fallback, not the Quad9 rule.
            let cloudflare = try RouterControlPlaneCoverage.requirements(plan: plan, profile: .init(resolver: .cloudflare))
            XCTAssertTrue(cloudflare.filter { $0.id.role == .mainResolver }.allSatisfy {
                $0.expectedDestination == .block && $0.projectedRuleID == nil
            })
        }
    }

    func testAssessmentAlwaysDerivesControlPlaneWithoutChangingReceiptOrApplicationMatrix() throws {
        for populated in [false, true] {
            let plan = compilerFixture
            let receipt = try receipt(plan: plan, populated: populated)
            let oldBytes = try RouterTrafficCodec.encode(receipt)
            let decoded = try RouterTrafficCodec.decode(oldBytes, plan: plan, profile: profile)
            let assessment = try decoded.assess(plan: plan, profile: profile)
            XCTAssertEqual(assessment.cases.map(\.id), try RouterTrafficCoveragePolicy.requirements(plan))
            XCTAssertEqual(assessment.controlPlane.count, 16)
            XCTAssertEqual(assessment.status, "incomplete")
            XCTAssertFalse(assessment.canPromoteAccepted)
            XCTAssertEqual(assessment.blockers, [.controlPlaneRecipeMissing, .liveCollectorUnavailable])
            XCTAssertEqual(try RouterTrafficCodec.encode(decoded), oldBytes)
            XCTAssertEqual(decoded.version, 1)
            XCTAssertThrowsError(try decoded.assess(plan: plan, profile: .init(resolver: .cloudflare)))
        }
    }

    func testReportedApplicationFailureSurvivesAdditionalRequirements() throws {
        let receipt = try receipt(plan: compilerFixture, populated: true, failed: true)
        let assessment = try receipt.assess(plan: compilerFixture, profile: profile)
        XCTAssertEqual(assessment.status, "reported_failure")
        XCTAssertTrue(assessment.cases.allSatisfy(\.reportedFailure))
        XCTAssertEqual(assessment.controlPlane.count, 16)
        XCTAssertFalse(assessment.canPromoteAccepted)
    }

    func testInvalidAndOversizedPlansCannotShrinkCoverage() throws {
        var plan = compilerFixture
        plan.proxies.append(plan.proxies[0])
        XCTAssertThrowsError(try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile))
        plan = compilerFixture; plan.proxies[0].host = "https://user:password@example.com"
        XCTAssertThrowsError(try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile))
        plan = compilerFixture; plan.rules.append(plan.rules[0])
        XCTAssertThrowsError(try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile))
        plan = emptyPlan
        plan.proxies = (0..<128).map {
            .init(id: UUID(), name: "Fixture", kind: .http, host: "p\($0).example.com", port: 8080)
        }
        let required = try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile)
        XCTAssertEqual(required.count, 524)
        XCTAssertLessThanOrEqual(required.count, RouterControlPlaneCoverage.maximumCases)
        XCTAssertEqual(Set(required.map(\.id)).count, required.count)
        plan.proxies.append(.init(id: UUID(), name: "Too many", kind: .http, host: "extra.example.com", port: 8080))
        XCTAssertThrowsError(try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile))
    }

    func testDerivedExportShowsMissingEvidenceWithoutCredentialsOrProcessPaths() throws {
        let assessment = try receipt(plan: compilerFixture, populated: true)
            .assess(plan: compilerFixture, profile: profile)
        let bytes = try RouterTrafficCodec.encode(assessment)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        XCTAssertEqual(object["controlPlaneCoveragePolicy"] as? Int, 1)
        let cases = try XCTUnwrap(object["controlPlane"] as? [[String: Any]])
        XCTAssertEqual(cases.count, 16)
        for item in cases {
            XCTAssertEqual(item["collectorAuthenticated"] as? Bool, false)
            XCTAssertEqual(item["canPromoteAccepted"] as? Bool, false)
            XCTAssertTrue((item["gaps"] as? [String])?.contains("notRun") == true)
            XCTAssertNil(item["httpMethod"])
        }
        let text = String(decoding: bytes, as: UTF8.self)
        for sensitive in [processPath, reference.uuidString, "credentialReference", "fixture-user", "fixture-pass", "rawPacket"] {
            XCTAssertFalse(text.contains(sensitive))
        }
    }

    private func receipt(plan: RouterPlan, populated: Bool, failed: Bool = false) throws -> RouterTrafficReceipt {
        let boot = UUID(), sampleDigest = String(repeating: "a", count: 64)
        let binding = RouterTrafficBinding(phase: .active,
            installation: .init(id: UUID(), ownerUID: 501), instance: UUID(), revision: UUID(),
            work: .init(bootID: boot, pid: 999, birthSeconds: 1000, birthMicroseconds: 0),
            planDigest: try RouterSystemCompiler.digest(plan: plan, profile: profile),
            configurationDigest: sampleDigest, stageReceiptDigest: sampleDigest, baselineID: UUID(),
            baselineDigest: sampleDigest, networkFingerprint: sampleDigest,
            coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
            compilerPolicy: RouterSystemCompiler.policyVersion)
        let interval = RouterTrafficInterval(
            start: .init(bootID: boot, uptime: 100, date: Date(timeIntervalSince1970: 2000)),
            end: .init(bootID: boot, uptime: 120, date: Date(timeIntervalSince1970: 2020)))
        let session = UUID()
        let records = try (populated ? RouterTrafficCoveragePolicy.requirements(plan) : []).map { id in
            RouterTrafficCaseRecord(id: id, attempt: UUID(), session: session, bindingDigest: try binding.digest(),
                interval: interval, transcript: .init(outcome: failed ? .failed : .incomplete, requestNonce: UUID(),
                    endpointDigest: nil, expectedEgress: nil, reply: nil, rejectControlBefore: nil,
                    rejectControlAfter: nil, gaps: []))
        }
        return .init(version: 1, coveragePolicy: 1, session: session, before: binding, after: binding,
                     interval: interval, records: records)
    }
}
