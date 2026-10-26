import XCTest
@testable import RoutingCore

final class RouterHitCorrelationGateTests: XCTestCase {
    func testFailClosedWithoutArmingOrActiveInstance() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: nil, mode: .tcpNumeric, systemPhase: "active",
                                            systemInstance: UUID(), refuseOwnTun: false, now: now),
            .refuse("hit_correlation_disarmed"))

        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, now: now, ttl: 60)
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric, systemPhase: "prepared",
                                            systemInstance: UUID(), refuseOwnTun: false, now: now),
            .refuse("no_active_system_instance"))
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric, systemPhase: "active",
                                            systemInstance: nil, refuseOwnTun: false, now: now),
            .refuse("no_active_system_instance"))
    }

    func testRefuseOwnTunBlocksEvenWhenActive() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let instance = UUID()
        let arming = RouterHitCorrelationEntry.arm(mode: .tlsHeld, now: now, ttl: 60)
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tlsHeld, systemPhase: "active",
                                            systemInstance: instance, refuseOwnTun: true, now: now),
            .refuse("refuseOwnTun_blocks_live_hit_correlation"))
    }

    func testAllowOnlyWhenArmedActiveAndClear() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let instance = UUID()
        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, now: now, ttl: 60)
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric, systemPhase: "active",
                                            systemInstance: instance, refuseOwnTun: false, now: now),
            .allow(instance: instance))
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric, systemPhase: "active",
                                            systemInstance: instance, refuseOwnTun: nil, now: now),
            .allow(instance: instance))
    }

    func testExpiredArmingAndModeMismatch() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, now: now, ttl: 30)
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tlsHeld, systemPhase: "active",
                                            systemInstance: UUID(), refuseOwnTun: false, now: now),
            .refuse("hit_correlation_mode_mismatch"))
        XCTAssertEqual(
            RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric, systemPhase: "active",
                                            systemInstance: UUID(), refuseOwnTun: false,
                                            now: now.addingTimeInterval(31)),
            .refuse("hit_correlation_arming_expired"))
    }
}

final class RouterHitCorrelationWireTests: XCTestCase {
    func testRoundTripAndNeverPromotesAccepted() throws {
        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, ttl: 60)
        let query = RouterHitCorrelationQuery(
            request: UUID(), instance: UUID(), mode: .tcpNumeric, arming: arming,
            address: "127.0.0.1", port: RouterSystemCompiler.controllerPort, serverName: nil)
        let encoded = try RouterHitCorrelationWire.encode(query)
        let decoded = try RouterHitCorrelationQuery.decode(encoded)
        XCTAssertEqual(decoded.action, "hitCorrelation")
        XCTAssertEqual(decoded.armingID, arming.id)
        XCTAssertEqual(decoded.reconstructedArming?.mode, .tcpNumeric)

        let refused = RouterHitCorrelationReply.refused(request: query.request, reason: "noActiveInstance")
        XCTAssertEqual(refused.outcome, "refused")
        XCTAssertFalse(refused.canPromoteAccepted)
        XCTAssertFalse(refused.journalMutated)
        XCTAssertFalse(refused.collectorAuthenticated)

        let report = RouterHitCorrelationEntry.Report(
            armingID: arming.id, mode: .tcpNumeric, relation: "candidateUnverified",
            reason: "fixture", connection: nil, compiledOrdinal: nil,
            collectorAuthenticated: false, canPromoteAccepted: false, journalMutated: false,
            gaps: [], summary: "test")
        let correlated = RouterHitCorrelationReply.correlated(request: query.request, report: report)
        XCTAssertEqual(correlated.outcome, "correlated")
        XCTAssertFalse(correlated.canPromoteAccepted)
        XCTAssertFalse(correlated.collectorAuthenticated)
        let attested = RouterHitCorrelationReply.correlated(
            request: query.request, report: report, collectorAuthenticated: true)
        XCTAssertTrue(attested.collectorAuthenticated)
        XCTAssertFalse(attested.canPromoteAccepted)

        let replyBytes = try RouterHitCorrelationWire.response(to: query) {
            .refused(request: query.request, reason: "remote_target_requires_user_clear_window")
        }
        let reply = try RouterHitCorrelationWire.decodeReply(replyBytes, request: query.request)
        XCTAssertEqual(reply.reason, "remote_target_requires_user_clear_window")
        XCTAssertFalse(reply.canPromoteAccepted)
    }

    func testRejectsNonHitCorrelationAction() {
        let bogus = Data(#"{"version":1,"action":"connections","request":"00000000-0000-0000-0000-000000000001"}"#.utf8)
        XCTAssertThrowsError(try RouterHitCorrelationQuery.decode(bogus))
    }
}
