import XCTest
@testable import RoutingCore

final class RouterAppTrafficMatrixAttestationTests: XCTestCase {
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

    func testProductionDefaultBlocksAppCellsWithClearWindowReason() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let window = RouterAppTrafficMatrixAttestation.ClearWindowState.productionDefault(
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: false, requireClearWouldPass: true)
        XCTAssertFalse(window.grantedInConversation)
        XCTAssertEqual(window.windowID, "tun-apply-clear-window-v1")
        let report = try RouterAppTrafficMatrixAttestation.attest(
            plan: samplePlan(), profile: profile, window: window)
        XCTAssertFalse(report.networkMutated)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertFalse(report.canClaimAppTrafficComplete)
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertGreaterThan(report.applicationCellCount, 0)
        XCTAssertTrue(report.cells.allSatisfy {
            $0.outcome == .blocked
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed"
                && $0.canPromoteAccepted == false
                && $0.gaps.contains(RouterAppTrafficMatrixAttestation.clearWindowID)
        })
        XCTAssertTrue(report.summary.contains("tun-apply-clear-window-v1")
                      || report.summary.contains("未授予"))
    }

    func testRefuseOwnTunAndRequireClearProducePreciseBlockedReasons() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let refuseWindow = RouterAppTrafficMatrixAttestation.ClearWindowState(
            grantedInConversation: true, requireClearWouldPass: false,
            refuseOwnTun: true, foreignTunnelPresent: true,
            systemPhase: "active", systemInstance: UUID())
        let refused = try RouterAppTrafficMatrixAttestation.attest(
            plan: samplePlan(), profile: profile, window: refuseWindow)
        XCTAssertTrue(refused.cells.allSatisfy {
            $0.outcome == .blocked && $0.reason == "app_traffic_blocked_refuseOwnTun"
        })

        let clearFail = RouterAppTrafficMatrixAttestation.ClearWindowState(
            grantedInConversation: true, requireClearWouldPass: false,
            refuseOwnTun: false, foreignTunnelPresent: false,
            systemPhase: "active", systemInstance: UUID())
        let unmet = try RouterAppTrafficMatrixAttestation.attest(
            plan: samplePlan(), profile: profile, window: clearFail)
        XCTAssertTrue(unmet.cells.allSatisfy {
            $0.outcome == .blocked && $0.reason == "app_traffic_blocked_requireClear_unmet"
        })
    }

    func testGrantedClearWindowWithoutEvidenceStaysUntestedNotLivePassed() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let window = RouterAppTrafficMatrixAttestation.ClearWindowState(
            grantedInConversation: true, requireClearWouldPass: true,
            refuseOwnTun: false, foreignTunnelPresent: false,
            systemPhase: "active", systemInstance: UUID())
        XCTAssertTrue(window.clearWindowProvenForAttempt)
        let report = try RouterAppTrafficMatrixAttestation.attest(
            plan: samplePlan(), profile: profile, window: window, evidence: [])
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertTrue(report.cells.allSatisfy {
            $0.outcome == .untested
                && $0.reason == "app_traffic_untested_awaiting_authenticated_evidence"
        })
    }

    func testAuthenticatedEvidenceOnlyCountsWhenClearWindowProven() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let plan = samplePlan()
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let target = try XCTUnwrap(inventory.cells.first { $0.kind == .applicationTraffic })
        let evidence = RouterTrafficMatrixLiveRunner.CellEvidence(
            kind: target.kind, label: target.label, collectorAuthenticated: true)

        let closed = RouterAppTrafficMatrixAttestation.ClearWindowState.productionDefault(
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: false, requireClearWouldPass: true)
        let blocked = try RouterAppTrafficMatrixAttestation.attest(
            plan: plan, profile: profile, window: closed, evidence: [evidence])
        XCTAssertEqual(blocked.livePassedCount, 0)
        XCTAssertTrue(blocked.cells.contains {
            $0.label == target.label && $0.outcome == .blocked
        })

        let open = RouterAppTrafficMatrixAttestation.ClearWindowState(
            grantedInConversation: true, requireClearWouldPass: true,
            refuseOwnTun: false, foreignTunnelPresent: false,
            systemPhase: "active", systemInstance: UUID())
        let passed = try RouterAppTrafficMatrixAttestation.attest(
            plan: plan, profile: profile, window: open, evidence: [evidence])
        XCTAssertEqual(passed.livePassedCount, 1)
        XCTAssertFalse(passed.canPromoteAccepted)
        XCTAssertFalse(passed.canClaimAppTrafficComplete)
        XCTAssertTrue(passed.cells.contains {
            $0.label == target.label && $0.outcome == .livePassed
                && $0.canPromoteAccepted == false
        })

        let forged = RouterTrafficMatrixLiveRunner.CellEvidence(
            kind: target.kind, label: target.label,
            collectorAuthenticated: true, routingVerified: true)
        let ignored = try RouterAppTrafficMatrixAttestation.attest(
            plan: plan, profile: profile, window: open, evidence: [forged])
        XCTAssertEqual(ignored.livePassedCount, 0)
        XCTAssertTrue(ignored.cells.contains {
            $0.label == target.label
                && $0.reason == "routing_verified_is_not_app_traffic_pass"
        })
    }

    func testLiveRunnerUsesScaffoldingReasonsForAppCells() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let report = try RouterTrafficMatrixLiveRunner.run(
            plan: samplePlan(), profile: profile,
            context: .init(systemPhase: "active", systemInstance: UUID(),
                           refuseOwnTun: false, requireClearWouldPass: true,
                           clearWindowGrantedInConversation: false),
            evidence: [])
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertTrue(report.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy { $0.outcome == .blocked
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed" })
        XCTAssertTrue(report.cells.filter { $0.kind == .existingConnectionMigration }
            .allSatisfy { $0.outcome == .blocked
                && $0.reason == "app_traffic_blocked_clear_window_unconfirmed" })
    }
}
