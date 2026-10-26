import XCTest
@testable import RoutingCore

final class RouterCoreExitFailClosedTests: XCTestCase {
    func testDirectOnlyPlanHasNoProtectedSubjects() {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        XCTAssertFalse(recipe.requiresIndependentLayer)
        XCTAssertTrue(recipe.subjects.isEmpty)
        XCTAssertFalse(recipe.allowFailoverOnFault)
        let assessment = RouterCoreExitFailClosed.assess(recipe: recipe, claim: .productionGap)
        XCTAssertFalse(assessment.verified)
        XCTAssertTrue(assessment.capabilityGap)
        XCTAssertTrue(assessment.rejectRulesAreNotProof)
        XCTAssertTrue(assessment.blockers.contains("no_protected_subjects_fail_closed_not_applicable"))
    }

    func testProxyAndBlockSubjectsRequireIndependentLayer() throws {
        let proxy = UUID()
        let domainRule = UUID()
        let processRule = UUID()
        let plan = RouterPlan(
            proxies: [.init(id: proxy, name: "mei", kind: .socks5, host: "127.0.0.1", port: 1080)],
            rules: [
                .init(id: domainRule,
                      selector: .init(domain: .init(kind: .suffix, value: "claude.ai")),
                      destination: .proxy(proxy)),
                .init(id: processRule,
                      selector: .init(processPath: "/Applications/Test.app/Contents/MacOS/Test"),
                      destination: .block)
            ],
            defaultDestination: .block)
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        XCTAssertTrue(recipe.requiresIndependentLayer)
        XCTAssertEqual(recipe.designedLayer, .packetFilterAnchorDefaultDeny)
        XCTAssertTrue(recipe.subjects.contains(where: { $0.kind == .domainSuffix && $0.value == "claude.ai" }))
        XCTAssertTrue(recipe.subjects.contains(where: { $0.kind == .processPath }))
        XCTAssertTrue(recipe.subjects.contains(where: { $0.value == "plan.defaultDestination" }))
        XCTAssertTrue(recipe.notes.contains(where: { $0.contains("REJECT") }))
    }

    func testRejectRulesAndProbesNeverVerifyProductionGap() {
        let proxy = UUID()
        let plan = RouterPlan(
            proxies: [.init(id: proxy, name: "p", kind: .http, host: "127.0.0.1", port: 8080)],
            rules: [.init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                          destination: .proxy(proxy))],
            defaultDestination: .direct)
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        let claim = RouterCoreExitFailClosed.IndependentLayerClaim(
            authentication: .productionUnverified, layerKind: nil, layerArmed: false,
            verifiedAfterCoreExit: false,
            offeredProofs: [.mihomoInternalRejectRules, .compiledRejectRulePresence,
                            .probeOrDetectionSuccess, .routingVerifiedFlag],
            evidenceDigest: String(repeating: "a", count: 64))
        let assessment = RouterCoreExitFailClosed.assess(recipe: recipe, claim: claim)
        XCTAssertFalse(assessment.verified)
        XCTAssertTrue(assessment.capabilityGap)
        XCTAssertEqual(assessment.status, "capability_gap")
        XCTAssertTrue(assessment.rejectRulesAreNotProof)
        XCTAssertTrue(assessment.blockers.contains("reject_rules_are_not_core_exit_proof"))
        XCTAssertTrue(assessment.blockers.contains("insufficient_proof:mihomoInternalRejectRules"))
        XCTAssertTrue(assessment.blockers.contains("production_independent_layer_unimplemented"))
        XCTAssertTrue(assessment.summary.contains("REJECT"))
    }

    func testUnitTestSealedFixtureCanVerifyAssessmentPathOnly() {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .suffix, value: "anthropic.com")),
                  destination: .block)
        ], defaultDestination: .direct)
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        let digest = String(repeating: "b", count: 64)
        let sealed = RouterCoreExitFailClosed.IndependentLayerClaim.unitTestVerified(
            layer: .packetFilterAnchorDefaultDeny, evidenceDigest: digest)
        let assessment = RouterCoreExitFailClosed.assess(recipe: recipe, claim: sealed)
        XCTAssertTrue(assessment.verified)
        XCTAssertFalse(assessment.capabilityGap)
        XCTAssertEqual(assessment.status, "verified_after_core_exit_fixture")
        XCTAssertTrue(assessment.rejectRulesAreNotProof)
        XCTAssertTrue(assessment.summary.contains("不代表本机已武装"))

        let wrongLayer = RouterCoreExitFailClosed.IndependentLayerClaim.unitTestVerified(
            layer: .routeDiscardWithInterfaceHold, evidenceDigest: digest)
        let refused = RouterCoreExitFailClosed.assess(recipe: recipe, claim: wrongLayer)
        XCTAssertFalse(refused.verified)
        XCTAssertTrue(refused.capabilityGap)
    }

    func testProductionGapHelperNeverClaimsVerification() {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "chatgpt.com")),
                  destination: .block)
        ], defaultDestination: .direct)
        let gap = RouterCoreExitFailClosed.productionGap(for: plan)
        XCTAssertFalse(gap.verified)
        XCTAssertTrue(gap.capabilityGap)
        XCTAssertGreaterThan(gap.recipeSubjectCount, 0)
        XCTAssertTrue(gap.blockers.contains("production_independent_layer_unimplemented"))
    }
}
