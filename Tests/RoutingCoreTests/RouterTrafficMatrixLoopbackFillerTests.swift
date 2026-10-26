import XCTest
@testable import RoutingCore

final class RouterTrafficMatrixLoopbackFillerTests: XCTestCase {
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

    func testInstanceGateIgnoresRefuseOwnTunButNeedsActive() {
        XCTAssertEqual(
            RouterTrafficMatrixLoopbackFiller.decideInstanceGate(systemPhase: "idle", systemInstance: nil),
            .refuse("no_active_system_instance"))
        let id = UUID()
        XCTAssertEqual(
            RouterTrafficMatrixLoopbackFiller.decideInstanceGate(systemPhase: "active", systemInstance: id),
            .allow(instance: id))
    }

    func testRemoteAppCellsBlockedAndControlPlanePendingWithoutProbe() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let report = try RouterTrafficMatrixLoopbackFiller.run(
            plan: samplePlan(), profile: profile,
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: true, probes: [])
        XCTAssertFalse(report.networkMutated)
        XCTAssertFalse(report.acceptedWritten)
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertTrue(report.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy {
                $0.outcome == .blocked
                    && ($0.reason == "app_traffic_blocked_refuseOwnTun"
                        || $0.reason == "app_traffic_blocked_clear_window_unconfirmed"
                        || $0.reason == "app_traffic_blocked_foreign_tunnel_clear_window")
                    && $0.gaps.contains(RouterAppTrafficMatrixAttestation.clearWindowID)
            })
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .controlPlaneDNS && $0.outcome == .untested
        }))
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .foreignTunnelCoexistence && $0.outcome == .blocked
        }))
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .coreExitFailClosed && $0.outcome == .capabilityGap
        }))
    }

    func testAuthenticatedLoopbackProbeCountsLivePassWithoutCompleting() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let plan = samplePlan()
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let target = try XCTUnwrap(
            RouterTrafficMatrixLoopbackFiller.loopbackCandidates(from: inventory).first)
        let reply = RouterHitCorrelationReply.correlated(
            request: UUID(),
            report: .init(armingID: UUID(), mode: .tcpNumeric, relation: "candidateUnverified",
                          reason: "loopback_ok", connection: nil, compiledOrdinal: 0,
                          collectorAuthenticated: false, canPromoteAccepted: false,
                          journalMutated: false, gaps: [], summary: "test"),
            collectorAuthenticated: true)
        XCTAssertTrue(reply.collectorAuthenticated)
        XCTAssertFalse(reply.canPromoteAccepted)
        let probe = RouterTrafficMatrixLoopbackFiller.Probe(
            cellKind: target.kind, cellLabel: target.label,
            address: "127.0.0.1", port: RouterSystemCompiler.controllerPort, reply: reply)
        let report = try RouterTrafficMatrixLoopbackFiller.run(
            plan: plan, profile: profile,
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: true, probes: [probe])
        XCTAssertEqual(report.livePassedCount, 1)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertTrue(report.cells.contains(where: {
            $0.label == target.label && $0.outcome == .livePassed
                && $0.reason == "loopback_hit_correlation_authenticated"
        }))
        XCTAssertTrue(report.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy { $0.outcome == .blocked })
    }

    func testUnauthenticatedCorrelatedProbeStaysUntested() throws {
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let plan = samplePlan()
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let target = try XCTUnwrap(
            RouterTrafficMatrixLoopbackFiller.loopbackCandidates(from: inventory).first)
        let reply = RouterHitCorrelationReply.correlated(
            request: UUID(),
            report: .init(armingID: UUID(), mode: .tcpNumeric, relation: "candidateUnverified",
                          reason: "loopback_ok", connection: nil, compiledOrdinal: 0,
                          collectorAuthenticated: false, canPromoteAccepted: false,
                          journalMutated: false, gaps: [], summary: "test"),
            collectorAuthenticated: false)
        let probe = RouterTrafficMatrixLoopbackFiller.Probe(
            cellKind: target.kind, cellLabel: target.label,
            address: "127.0.0.1", port: 19492, reply: reply)
        let report = try RouterTrafficMatrixLoopbackFiller.run(
            plan: plan, profile: profile,
            systemPhase: "active", systemInstance: UUID(),
            refuseOwnTun: false, probes: [probe])
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertTrue(report.cells.contains(where: {
            $0.label == target.label
                && $0.reason == "loopback_probe_returned_collector_unauthenticated"
        }))
    }
}
