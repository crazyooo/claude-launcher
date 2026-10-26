import XCTest
@testable import RoutingCore

final class RouterPFArmingExecuteGateTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [
        .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
              destination: .block)
    ], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func makePreview(now: Date) throws -> RouterPFArmingExecuteGate.Preview {
        try RouterPFArmingExecuteGate.preview(plan: plan, profile: profile, now: now)
    }

    func testUnconfirmedConversationRefusesWithoutLoadingPF() throws {
        let now = Date(timeIntervalSince1970: 1_900_300_000)
        let preview = try makePreview(now: now)
        let arming = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now, fingerprint: "fp-a")
        let after = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let report = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, grant: .none, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .refuse("pf_arming_not_confirmed_in_conversation"))
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.pfRulesLoaded)
        XCTAssertFalse(report.armed)
        XCTAssertFalse(report.foreignComponentsStopped)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertEqual(RouterPFArmingExecuteGate.confirmationWindowID, "pf-arming-user-confirm-v1")
    }

    func testForeignTunnelAndMissingConfirmRefuse() throws {
        let now = Date(timeIntervalSince1970: 1_900_300_000)
        let preview = try makePreview(now: now)
        let previewOnly = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionPreviewOnly, now: now)
        let clear = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle", observedAt: now)
        XCTAssertEqual(
            RouterPFArmingExecuteGate.decide(
                preview: preview, arming: previewOnly, confirmation: nil,
                before: clear, after: clear, now: now),
            .refuse("arming_kind_not_guarded_arm"))

        let guarded = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        XCTAssertEqual(
            RouterPFArmingExecuteGate.decide(
                preview: preview, arming: guarded, confirmation: nil,
                before: clear, after: clear, now: now),
            .refuse("explicit_ui_confirm_required"))

        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let foreign = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: true, foreignTunnelPresent: true, systemPhase: "active",
            observedAt: now.addingTimeInterval(2))
        XCTAssertEqual(
            RouterPFArmingExecuteGate.decide(
                preview: preview, arming: guarded, confirmation: confirm,
                before: foreign, after: foreign, grant: .init(grantedInConversation: true),
                now: now.addingTimeInterval(3)),
            .refuse("foreign_tunnel_or_refuseOwnTun"))
    }

    func testGrantedWindowAllowsGateWithoutPFMutation() throws {
        let now = Date(timeIntervalSince1970: 1_900_300_000)
        let preview = try makePreview(now: now)
        XCTAssertFalse(preview.routingVerified)
        XCTAssertFalse(preview.accepted)
        XCTAssertTrue(preview.wouldMutateNetworkIfArmed)
        let arming = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now, fingerprint: "fp-a")
        let after = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let grant = RouterPFArmingExecuteGate.ConversationGrant(grantedInConversation: true)
        let report = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, grant: grant, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .allow)
        XCTAssertEqual(report.reason, "gates_passed_pf_effects_unwired")
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.pfRulesLoaded)
        XCTAssertFalse(report.armed)
        XCTAssertEqual(report.dimensions.first { $0.name == "pfAnchor" }?.status,
                       "gate_passed_unwired")
    }

    func testLegacyPreviewExecuteAcceptsSealedWindowWithoutLoadingPF() {
        XCTAssertTrue(RouterConversationPFArming.isGranted)
        let missing = RouterPFArmingPreview.execute(plan: plan, confirmationToken: nil)
        XCTAssertFalse(missing.armed)
        XCTAssertFalse(missing.networkMutated)
        let arbitrary = RouterPFArmingPreview.execute(plan: plan, confirmationToken: "please-arm")
        XCTAssertFalse(arbitrary.armed)
        XCTAssertFalse(arbitrary.networkMutated)
        XCTAssertEqual(arbitrary.reason, "pf_arming_not_confirmed_in_conversation")
        let granted = RouterPFArmingPreview.execute(
            plan: plan, confirmationToken: RouterPFArmingPreview.confirmationWindowID)
        XCTAssertFalse(granted.armed)
        XCTAssertFalse(granted.networkMutated)
        XCTAssertEqual(granted.reason, "gates_passed_pf_effects_unwired")
    }
}

final class RouterCoreExitFailClosedProofHarnessTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [
        .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
              destination: .block)
    ], defaultDestination: .direct)

    func testProofRefusedWhenPFGateNotRunOrRefused() throws {
        let none = RouterCoreExitFailClosedProofHarness.evaluate(plan: plan, pfArming: nil)
        XCTAssertEqual(none.outcome, .refused)
        XCTAssertFalse(none.verified)
        XCTAssertFalse(none.pfArmed)
        XCTAssertFalse(none.pfRulesLoaded)
        XCTAssertFalse(none.networkModified)
        XCTAssertFalse(none.canClaimFailClosedProven)
        XCTAssertTrue(none.blockers.contains("independent_pf_layer_not_armed"))

        let now = Date(timeIntervalSince1970: 1_900_300_100)
        let preview = try RouterPFArmingExecuteGate.preview(plan: plan, now: now)
        let arming = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "a")
        let refused = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: obs, after: obs, grant: .none, now: now.addingTimeInterval(3))
        let proof = RouterCoreExitFailClosedProofHarness.evaluate(plan: plan, pfArming: refused)
        XCTAssertEqual(proof.outcome, .refused)
        XCTAssertFalse(proof.verified)
        XCTAssertTrue(proof.blockers.contains(where: { $0.hasPrefix("pf_arming_gate_refused:") }))
        XCTAssertTrue(proof.summary.contains("REJECT") || proof.blockers.contains("reject_rules_are_not_core_exit_proof"))
    }

    func testGateAllowStillLeavesFailClosedUnproven() throws {
        let now = Date(timeIntervalSince1970: 1_900_300_200)
        let preview = try RouterPFArmingExecuteGate.preview(plan: plan, now: now)
        let arming = try RouterPFArmingExecuteGate.arm(
            preview: preview, kind: .productionGuardedArm, now: now)
        let confirm = RouterPFArmingExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterPFArmingExecuteGate.Observation(
            refuseOwnTun: false, foreignTunnelPresent: false, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "a")
        let grant = RouterPFArmingExecuteGate.ConversationGrant(grantedInConversation: true)
        let allowed = try RouterPFArmingExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: obs, after: obs, grant: grant, now: now.addingTimeInterval(3))
        XCTAssertEqual(allowed.decision, .allow)
        XCTAssertFalse(allowed.armed)
        let proof = RouterCoreExitFailClosedProofHarness.evaluate(plan: plan, pfArming: allowed)
        XCTAssertEqual(proof.outcome, .unverified)
        XCTAssertFalse(proof.verified)
        XCTAssertFalse(proof.canClaimFailClosedProven)
        XCTAssertTrue(proof.blockers.contains("pf_arming_gate_passed_but_effects_unwired"))
        XCTAssertTrue(proof.blockers.contains("independent_pf_layer_not_armed"))
    }

    func testLiveDifferentialEvidenceIsUnsealed() {
        let proof = RouterCoreExitFailClosedProofHarness.evaluate(
            plan: plan, pfArming: nil, postExit: .live20261024)
        XCTAssertEqual(proof.outcome, .differentiallyObserved)
        XCTAssertTrue(proof.postExitDifferentiallyObserved)
        XCTAssertFalse(proof.verified)
        XCTAssertFalse(proof.routingVerified)
        XCTAssertFalse(proof.accepted)
        XCTAssertFalse(proof.canClaimFailClosedProven)
        XCTAssertTrue(proof.blockers.contains("post_exit_differential_observed_not_a_product_seal"))
        XCTAssertFalse(proof.blockers.contains("post_exit_reobservation_still_required"))
    }
}
