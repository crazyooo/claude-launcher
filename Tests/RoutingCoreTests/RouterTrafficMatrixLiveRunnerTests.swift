import XCTest
@testable import RoutingCore

final class RouterTrafficMatrixLiveRunnerTests: XCTestCase {
    private func samplePlan() -> RouterPlan {
        let proxy = UUID()
        return RouterPlan(
            proxies: [.init(id: proxy, name: "mei", kind: .socks5, host: "127.0.0.1", port: 1080)],
            rules: [
                .init(id: UUID(),
                      selector: .init(domain: .init(kind: .suffix, value: "claude.ai")),
                      destination: .proxy(proxy))
            ],
            defaultDestination: .direct)
    }

    func testRefuseWithoutActiveInstance() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let report = try RouterTrafficMatrixLiveRunner.run(
            plan: samplePlan(), profile: profile,
            context: .init(systemPhase: "idle", systemInstance: nil, refuseOwnTun: false))
        XCTAssertEqual(report.gate, .refuse("no_active_system_instance"))
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertFalse(report.networkMutated)
        XCTAssertFalse(report.acceptedWritten)
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .applicationTraffic && $0.outcome == .blocked
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed"
        }))
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .coreExitFailClosed && $0.outcome == .capabilityGap
        }))
    }

    func testRefuseOwnTunBlocksAndMarksForeignTunnelBlocked() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let report = try RouterTrafficMatrixLiveRunner.run(
            plan: samplePlan(), profile: profile,
            context: .init(systemPhase: "active", systemInstance: UUID(),
                           refuseOwnTun: true, requireClearWouldPass: false))
        XCTAssertEqual(report.gate, .refuse("refuseOwnTun_blocks_live_matrix"))
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .foreignTunnelCoexistence && $0.outcome == .blocked
        }))
        XCTAssertTrue(report.refusedCount > 0)
        XCTAssertTrue(report.summary.contains("未改网络") || report.summary.contains("未写 accepted"))
    }

    func testActiveWithoutConversationGrantBlocksAppCells() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let instance = UUID()
        let report = try RouterTrafficMatrixLiveRunner.run(
            plan: samplePlan(), profile: profile,
            context: .init(systemPhase: "active", systemInstance: instance,
                           refuseOwnTun: false, requireClearWouldPass: true,
                           clearWindowGrantedInConversation: false))
        XCTAssertEqual(report.gate, .allow(instance: instance))
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertTrue(report.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy { $0.outcome == .blocked
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed" })
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .coreExitFailClosed && $0.outcome == .capabilityGap
                && $0.reason == "pf_arming_not_confirmed"
        }))
    }

    func testGrantedClearWindowLeavesAppCellsUntestedWithoutEvidence() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let instance = UUID()
        let report = try RouterTrafficMatrixLiveRunner.run(
            plan: samplePlan(), profile: profile,
            context: .init(systemPhase: "active", systemInstance: instance,
                           refuseOwnTun: false, requireClearWouldPass: true,
                           clearWindowGrantedInConversation: true))
        XCTAssertEqual(report.gate, .allow(instance: instance))
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertTrue(report.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy { $0.outcome == .untested
                && $0.reason == "app_traffic_untested_awaiting_authenticated_evidence" })
    }

    func testAuthenticatedEvidenceCanCountLivePassButNotComplete() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let plan = samplePlan()
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let target = try XCTUnwrap(inventory.cells.first { $0.kind == .applicationTraffic })
        let evidence = RouterTrafficMatrixLiveRunner.CellEvidence(
            kind: target.kind, label: target.label,
            collectorAuthenticated: true, routingVerified: false)
        let forged = RouterTrafficMatrixLiveRunner.CellEvidence(
            kind: target.kind, label: target.label,
            collectorAuthenticated: true, routingVerified: true)
        let context = RouterTrafficMatrixLiveRunner.Context(
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: false, requireClearWouldPass: true,
            clearWindowGrantedInConversation: true)
        let ok = try RouterTrafficMatrixLiveRunner.run(
            plan: plan, profile: profile, context: context, evidence: [evidence])
        XCTAssertEqual(ok.livePassedCount, 1)
        XCTAssertFalse(ok.canClaimMatrixComplete)

        let bad = try RouterTrafficMatrixLiveRunner.run(
            plan: plan, profile: profile, context: context, evidence: [forged])
        XCTAssertEqual(bad.livePassedCount, 0)
        XCTAssertTrue(bad.cells.contains(where: {
            $0.reason == "routing_verified_is_not_app_traffic_pass"
        }))

        let ungranted = RouterTrafficMatrixLiveRunner.Context(
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: false, requireClearWouldPass: true,
            clearWindowGrantedInConversation: false)
        let blocked = try RouterTrafficMatrixLiveRunner.run(
            plan: plan, profile: profile, context: ungranted, evidence: [evidence])
        XCTAssertEqual(blocked.livePassedCount, 0)
        XCTAssertTrue(blocked.cells.contains(where: {
            $0.label == target.label
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed"
        }))
    }
}

final class RouterPFArmingPreviewTests: XCTestCase {
    func testPreviewNeverArmsAndSealedWindowLeavesEffectsUnwired() {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .block)
        let preview = RouterPFArmingPreview.preview(plan: plan)
        XCTAssertFalse(preview.armed)
        XCTAssertTrue(preview.wouldMutateNetwork)
        XCTAssertEqual(preview.confirmationWindowID, RouterPFArmingPreview.confirmationWindowID)
        XCTAssertTrue(preview.requiredConfirmations.contains("explicit_user_confirm_pf_arming_in_this_conversation"))
        XCTAssertTrue(RouterConversationPFArming.isGranted)

        let missing = RouterPFArmingPreview.execute(plan: plan, confirmationToken: nil)
        XCTAssertFalse(missing.armed)
        XCTAssertFalse(missing.networkMutated)
        XCTAssertEqual(missing.reason, "pf_arming_confirmation_missing")

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
