import XCTest
@testable import RoutingCore

final class RouterTunApplyExecuteGateTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func makePreview(now: Date) throws -> RouterTunApplyExecuteGate.Preview {
        try RouterTunApplyExecuteGate.preview(plan: plan, profile: profile, now: now)
    }

    func testForeignTunnelRefusesWithoutMutationOrForeignStop() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, foreignTunnelPresent: true,
            systemPhase: "idle", observedAt: now)
        let after = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, foreignTunnelPresent: true,
            systemPhase: "idle", observedAt: now.addingTimeInterval(2))
        let report = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: .none, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .refuse("foreign_tunnel_or_refuseOwnTun"))
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.tunEnabled)
        XCTAssertFalse(report.foreignComponentsStopped)
        XCTAssertFalse(report.journalMutated)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertTrue(report.summary.contains("未启用 TUN") || report.summary.contains("拒绝"))
    }

    func testRequireClearUnmetAndMissingConfirmRefuse() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        let previewOnly = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionPreviewOnly, now: now)
        let clearObs = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "prepared",
            observedAt: now)
        XCTAssertEqual(
            RouterTunApplyExecuteGate.decide(
                preview: preview, arming: previewOnly, confirmation: nil,
                before: clearObs, after: clearObs, now: now),
            .refuse("arming_kind_not_guarded_apply"))

        let guarded = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        XCTAssertEqual(
            RouterTunApplyExecuteGate.decide(
                preview: preview, arming: guarded, confirmation: nil,
                before: clearObs, after: clearObs, now: now),
            .refuse("explicit_ui_confirm_required"))

        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let unmet = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: false, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now.addingTimeInterval(2))
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: false, systemPhase: "prepared",
            observedAt: now)
        XCTAssertEqual(
            RouterTunApplyExecuteGate.decide(
                preview: preview, arming: guarded, confirmation: confirm,
                before: before, after: unmet, now: now.addingTimeInterval(3)),
            .refuse("foreign_tunnel_or_refuseOwnTun"))
    }

    func testUnconfirmedClearWindowRefusesEvenWhenLocalClearLooksOpen() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now, fingerprint: "fp-a")
        let after = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let report = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: .none, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .refuse("clear_window_not_confirmed_in_conversation"))
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.tunEnabled)
        XCTAssertFalse(report.foreignComponentsStopped)
        XCTAssertEqual(RouterTunApplyExecuteGate.clearWindowID, "tun-apply-clear-window-v1")
    }

    func testGrantedClearWindowAllowsGateWithoutNetworkMutation() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        XCTAssertFalse(preview.routingVerified)
        XCTAssertFalse(preview.accepted)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now, fingerprint: "fp-a")
        let after = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let report = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: grant, now: now.addingTimeInterval(3))
        XCTAssertEqual(report.decision, .allow)
        XCTAssertEqual(report.reason, "gates_passed_tun_effects_unwired")
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.tunEnabled)
        XCTAssertFalse(report.tunEffectsWired)
        XCTAssertFalse(report.foreignComponentsStopped)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertEqual(report.dimensions.first { $0.name == "tunEnable" }?.status,
                       "gate_passed_unwired")
    }

    func testInjectedSideEffectsRunOnlyAfterAllow() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now, fingerprint: "fp-a")
        let after = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, foreignTunnelPresent: false,
            systemPhase: "prepared", observedAt: now.addingTimeInterval(2), fingerprint: "fp-a")
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        final class Box: @unchecked Sendable { var count = 0 }
        let box = Box()
        let effects = RouterTunApplyExecuteGate.SideEffects(enableOwnTun: { preview in
            box.count += 1
            XCTAssertEqual(preview.planDigest.count, 64)
            return .init(networkModified: true, tunEnabled: true,
                         detail: "test harness simulated own TUN enable")
        })
        let report = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: grant, sideEffects: effects,
            now: now.addingTimeInterval(3))
        XCTAssertEqual(box.count, 1)
        XCTAssertEqual(report.decision, .allow)
        XCTAssertEqual(report.reason, "gates_passed_tun_effects_invoked")
        XCTAssertTrue(report.executed)
        XCTAssertTrue(report.tunEffectsWired)
        XCTAssertTrue(report.networkModified)
        XCTAssertTrue(report.tunEnabled)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canPromoteAccepted)

        // Refuse path must not invoke effects.
        box.count = 0
        let refused = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: .none, sideEffects: effects,
            now: now.addingTimeInterval(3))
        XCTAssertEqual(refused.decision, .refuse("clear_window_not_confirmed_in_conversation"))
        XCTAssertEqual(box.count, 0)
        XCTAssertFalse(refused.tunEffectsWired)
        XCTAssertFalse(refused.networkModified)
    }

    func testFingerprintChangeAndReobservationOrderRefuse() throws {
        let now = Date(timeIntervalSince1970: 1_900_100_000)
        let preview = try makePreview(now: now)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(5), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "prepared",
            observedAt: now, fingerprint: "a")
        let afterEarly = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "prepared",
            observedAt: now.addingTimeInterval(1), fingerprint: "a")
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        XCTAssertEqual(
            RouterTunApplyExecuteGate.decide(
                preview: preview, arming: arming, confirmation: confirm,
                before: before, after: afterEarly, clearWindow: grant, now: now.addingTimeInterval(6)),
            .refuse("reobservation_before_confirm"))

        let afterChanged = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "prepared",
            observedAt: now.addingTimeInterval(6), fingerprint: "b")
        XCTAssertEqual(
            RouterTunApplyExecuteGate.decide(
                preview: preview, arming: arming, confirmation: confirm,
                before: before, after: afterChanged, clearWindow: grant, now: now.addingTimeInterval(7)),
            .refuse("reobservation_fingerprint_changed"))
    }
}
