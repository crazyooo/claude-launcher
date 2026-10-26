import XCTest
@testable import RoutingCore

final class RouterAcceptedRollbackExecuteGateTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func sealedPreview(now: Date) throws -> RouterAcceptedRollback.Preview {
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        return try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: plan, profile: profile,
            configurationDigest: digest, evidenceDigest: evidence, now: now)
    }

    func testForeignTunnelRefusesWithoutMutation() throws {
        let now = Date(timeIntervalSince1970: 1_900_000_000)
        let preview = try sealedPreview(now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, systemPhase: "active",
            observedAt: now)
        let after = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, systemPhase: "active",
            observedAt: now.addingTimeInterval(2))
        let report = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .refuse("foreign_tunnel_or_refuseOwnTun"))
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.journalMutated)
        XCTAssertFalse(report.historicalDigestTreatedAsNewSuccess)
        XCTAssertTrue(report.summary.contains("未改网络") || report.summary.contains("拒绝"))
    }

    func testMissingConfirmAndWrongArmingRefuse() throws {
        let now = Date(timeIntervalSince1970: 1_900_000_000)
        let preview = try sealedPreview(now: now)
        let previewOnly = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionPreviewOnly, now: now)
        let clear = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now)
        XCTAssertEqual(
            RouterAcceptedRollbackExecuteGate.decide(
                preview: preview, arming: previewOnly, confirmation: nil,
                before: clear, after: clear, now: now),
            .refuse("arming_kind_not_guarded_execute"))

        let guarded = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        XCTAssertEqual(
            RouterAcceptedRollbackExecuteGate.decide(
                preview: preview, arming: guarded, confirmation: nil,
                before: clear, after: clear, now: now),
            .refuse("explicit_ui_confirm_required"))
    }

    func testClearWindowGatePassesWithoutNetworkMutation() throws {
        let now = Date(timeIntervalSince1970: 1_900_000_000)
        let preview = try sealedPreview(now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now, fingerprint: "fp-a")
        let after = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let report = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .allow)
        XCTAssertEqual(report.reason, "gates_passed_restore_effects_unwired")
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.journalMutated)
        XCTAssertFalse(report.historicalDigestTreatedAsNewSuccess)
        XCTAssertEqual(report.dimensions.first { $0.name == "networkCleanup" }?.status,
                       "gate_passed_no_mutation")
    }

    func testFingerprintChangeAndReobservationOrderRefuse() throws {
        let now = Date(timeIntervalSince1970: 1_900_000_000)
        let preview = try sealedPreview(now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(5), explicitUIConfirm: true)
        let before = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now, fingerprint: "a")
        let afterEarly = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now.addingTimeInterval(1), fingerprint: "a")
        XCTAssertEqual(
            RouterAcceptedRollbackExecuteGate.decide(
                preview: preview, arming: arming, confirmation: confirm,
                before: before, after: afterEarly, now: now.addingTimeInterval(6)),
            .refuse("reobservation_before_confirm"))

        let afterChanged = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now.addingTimeInterval(6), fingerprint: "b")
        XCTAssertEqual(
            RouterAcceptedRollbackExecuteGate.decide(
                preview: preview, arming: arming, confirmation: confirm,
                before: before, after: afterChanged, now: now.addingTimeInterval(7)),
            .refuse("reobservation_fingerprint_changed"))
    }

    func testLegacyExecuteWithGuardedArmingStillRefusesMutation() throws {
        let now = Date()
        let preview = try sealedPreview(now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let report = try RouterAcceptedRollback.execute(preview: preview, arming: arming, now: now)
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertTrue(report.dimensions.allSatisfy { $0.status == "blocked_pending_execute_gate" })
    }
}
