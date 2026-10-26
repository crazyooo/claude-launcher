import XCTest
@testable import RoutingCore

final class RouterSystemClientLiveTrafficEvidenceTests: XCTestCase {
    func testLiveHitCorrelationAndMatrixAgainstActiveInstance() throws {
        let client = RouterSystemClient()
        let status: RouterSystemStatus
        do {
            status = try client.request(.status(id: nil))
        } catch RouterSystemClientError.unavailable {
            throw XCTSkip("system component unavailable")
        }
        print("STATUS phase=\(status.phase) reason=\(status.reason) instance=\(String(describing: status.instance))")
        guard status.phase == "active", let instance = status.instance else {
            throw XCTSkip("no active instance; run live apply first")
        }
        XCTAssertFalse(status.routingVerified)

        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, ttl: 60)
        switch RouterHitCorrelationGate.decide(
            arming: arming, mode: .tcpNumeric,
            systemPhase: status.phase, systemInstance: instance, refuseOwnTun: false) {
        case .refuse(let reason):
            XCTFail("hit correlation gate refused unexpectedly: \(reason)")
            return
        case .allow(let allowed):
            XCTAssertEqual(allowed, instance)
        }

        let query = RouterHitCorrelationQuery(
            request: UUID(), instance: instance, mode: .tcpNumeric, arming: arming,
            address: "127.0.0.1", port: RouterSystemCompiler.controllerPort, serverName: nil)
        let reply = try client.hitCorrelation(query)
        print("HIT outcome=\(reply.outcome) authenticated=\(reply.collectorAuthenticated) reason=\(reply.reason) relation=\(reply.relation ?? "-") promote=\(reply.canPromoteAccepted)")
        XCTAssertFalse(reply.canPromoteAccepted)

        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let candidates = RouterTrafficMatrixLoopbackFiller.loopbackCandidates(from: inventory)
        let probes: [RouterTrafficMatrixLoopbackFiller.Probe] = candidates.prefix(4).map {
            .init(cellKind: $0.kind, cellLabel: $0.label,
                  address: RouterTrafficMatrixLoopbackFiller.loopbackAddress,
                  port: RouterTrafficMatrixLoopbackFiller.defaultPort,
                  reply: reply)
        }
        let fill = try RouterTrafficMatrixLoopbackFiller.run(
            plan: plan, profile: profile,
            systemPhase: status.phase, systemInstance: instance,
            refuseOwnTun: false, probes: probes)
        print("MATRIX livePassed=\(fill.livePassedCount) blocked=\(fill.blockedCount) refused=\(fill.refusedCount) untested=\(fill.untestedCount) complete=\(fill.canClaimMatrixComplete) summary=\(fill.summary)")
        XCTAssertFalse(fill.canClaimMatrixComplete)
        XCTAssertFalse(fill.acceptedWritten)

        let window = RouterAppTrafficMatrixAttestation.ClearWindowState(
            grantedInConversation: RouterConversationClearWindow.isGranted,
            requireClearWouldPass: true,
            refuseOwnTun: false,
            foreignTunnelPresent: false,
            systemPhase: status.phase,
            systemInstance: instance)
        let app = try RouterAppTrafficMatrixAttestation.attest(
            plan: plan, profile: profile, window: window)
        print("APP_ATTEST blocked=\(app.blockedCount) untested=\(app.untestedCount) livePassed=\(app.livePassedCount) promote=\(app.canPromoteAccepted) summary=\(app.summary)")
        XCTAssertFalse(app.canPromoteAccepted)
        XCTAssertFalse(app.canClaimAppTrafficComplete)

        let faults = RouterFaultAcceptanceHarness.report(
            liveMatrix: fill, appTrafficAttestation: app)
        print("FAULTS verified=\(faults.verifiedCount)/\(faults.faults.count) claimComplete=\(faults.canClaimProductComplete)")
        XCTAssertFalse(faults.canClaimProductComplete)
        XCTAssertFalse(faults.routingVerified)
        XCTAssertFalse(faults.accepted)
    }
}
