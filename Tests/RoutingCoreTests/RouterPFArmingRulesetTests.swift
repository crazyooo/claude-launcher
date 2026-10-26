import XCTest
@testable import RoutingCore

final class RouterPFArmingRulesetTests: XCTestCase {
    func testDirectOnlyPlanNotApplicable() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let artifact = try RouterPFArmingRuleset.generate(plan: plan)
        XCTAssertFalse(artifact.applicable)
        XCTAssertFalse(artifact.routingVerified)
        XCTAssertFalse(artifact.accepted)
        XCTAssertTrue(artifact.blockers.contains("no_protected_subjects_fail_closed_not_applicable"))
        XCTAssertEqual(artifact.anchorName, "claude_router_failclosed")
    }

    func testBlockDomainRequiresTableFillBeforeApplySemantics() throws {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .direct)
        let empty = try RouterPFArmingRuleset.generate(plan: plan)
        XCTAssertTrue(empty.blockers.contains("destination_table_empty_fill_required_before_apply"))
        XCTAssertTrue(empty.pfConf.contains("empty — fill"))
        XCTAssertFalse(empty.pfConf.contains("block drop"))

        let filled = try RouterPFArmingRuleset.generate(plan: plan, destinationAddresses: ["1.1.1.1"])
        XCTAssertTrue(filled.applicable)
        XCTAssertTrue(filled.pfConf.contains("1.1.1.1"))
        XCTAssertTrue(filled.pfConf.contains("block drop out quick inet from any to 1.1.1.1"))
        XCTAssertFalse(filled.routingVerified)
        XCTAssertEqual(filled.sourceSHA256.count, 64)
    }

    func testRejectsPrivateDestinationAddresses() throws {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .direct)
        let artifact = try RouterPFArmingRuleset.generate(
            plan: plan, destinationAddresses: ["10.0.0.1", "1.1.1.1"])
        XCTAssertTrue(artifact.blockers.contains(where: { $0.hasPrefix("destination_address_not_public_unicast") }))
        XCTAssertFalse(artifact.applicable)
        XCTAssertFalse(artifact.pfConf.contains("block drop"))
        XCTAssertTrue(artifact.pfConf.contains("NOT applicable"))
    }
}

final class RouterPFArmingRulesetHardeningTests: XCTestCase {
    private func blockPlan(processPath: String? = nil, proxies: [RouterProxy] = [],
                           defaultDestination: RouterDestination = .direct) -> RouterPlan {
        RouterPlan(proxies: proxies, rules: [
            .init(id: UUID(), selector: .init(processPath: processPath,
                                              domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: defaultDestination)
    }

    func testNonGlobalAddressesRejectedIncludingFakeIP() throws {
        for addr in ["198.18.0.5", "100.64.1.1", "::", "ff02::1", "2001:db8::1",
                     "192.0.2.1", "8_8.8.8.8", "1.1.1", "fd00::1", "::ffff:1.1.1.1"] {
            let artifact = try RouterPFArmingRuleset.generate(plan: blockPlan(), destinationAddresses: [addr])
            XCTAssertFalse(artifact.applicable, addr)
            XCTAssertFalse(artifact.pfConf.contains("block drop"), addr)
        }
        let ok = try RouterPFArmingRuleset.generate(
            plan: blockPlan(), destinationAddresses: ["1.1.1.1", "2606:4700:4700::1111"])
        XCTAssertTrue(ok.applicable)
        XCTAssertTrue(ok.pfConf.contains("block drop out quick inet from any to 1.1.1.1"))
        XCTAssertTrue(ok.pfConf.contains("block drop out quick inet6 from any to 2606:4700:4700::1111"))
    }

    func testProcessPathAnywhereMakesRulesetNotApplicable() throws {
        let artifact = try RouterPFArmingRuleset.generate(
            plan: blockPlan(processPath: "/usr/bin/curl"), destinationAddresses: ["1.1.1.1"])
        XCTAssertFalse(artifact.applicable)
        XCTAssertFalse(artifact.pfConf.contains("block drop"))
    }

    func testDestinationOverlappingProxyTransportRejected() throws {
        let proxy = RouterProxy(id: UUID(), name: "p", kind: .socks5, host: "9.9.9.9", port: 1080)
        let artifact = try RouterPFArmingRuleset.generate(
            plan: blockPlan(proxies: [proxy]), destinationAddresses: ["9.9.9.9"])
        XCTAssertFalse(artifact.applicable)
        XCTAssertTrue(artifact.blockers.contains("destination_overlaps_proxy_transport:9.9.9.9"))
    }

    func testGateRefusesNonApplicableRulesetEvenWithWiredEffects() throws {
        let plan = blockPlan(defaultDestination: .block)
        let now = Date(timeIntervalSince1970: 1_900_500_000)
        let preview = try RouterPFArmingExecuteGate.preview(plan: plan, now: now)
        XCTAssertFalse(preview.rulesetApplicable)
        let arming = try RouterPFArmingExecuteGate.arm(preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "active",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp")
        let effects = RouterPFArmingExecuteGate.SideEffects { _ in
            XCTFail("loader must not run for a non-applicable ruleset")
            return .init(networkModified: true, pfRulesLoaded: true, armed: true, detail: "x")
        }
        let report = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm, before: obs, after: obs,
            grant: RouterConversationPFArming.liveGrant, sideEffects: effects,
            now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .refuse("pf_ruleset_not_applicable"))
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.armed)
    }
}

final class RouterPFArmingSideEffectsGateTests: XCTestCase {
    func testInjectedSideEffectsMarkWiredWithoutPromotion() throws {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .direct)
        let now = Date(timeIntervalSince1970: 1_900_400_000)
        let preview = try RouterPFArmingExecuteGate.preview(plan: plan, now: now)
        let arming = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "active",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp")
        let effects = RouterPFArmingExecuteGate.SideEffects { _ in
            .init(networkModified: true, pfRulesLoaded: true, armed: true,
                  detail: "test recorder — not live pfctl")
        }
        let report = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: obs, after: obs,
            grant: RouterConversationPFArming.liveGrant,
            sideEffects: effects,
            now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .allow)
        XCTAssertTrue(report.pfEffectsWired)
        XCTAssertTrue(report.executed)
        XCTAssertTrue(report.armed)
        XCTAssertTrue(report.pfRulesLoaded)
        XCTAssertTrue(report.networkModified)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertEqual(report.reason, "gates_passed_pf_effects_invoked")

        let proof = RouterCoreExitFailClosedProofHarness.evaluate(plan: plan, pfArming: report)
        XCTAssertEqual(proof.outcome, .unverified)
        XCTAssertFalse(proof.canClaimFailClosedProven)
        XCTAssertTrue(proof.blockers.contains("post_exit_reobservation_still_required"))
        XCTAssertFalse(proof.blockers.contains("unexpected_pf_rules_loaded_without_wired_effects"))
    }
}
