import XCTest
@testable import RoutingCore

final class RouterHitCorrelationEntryTests: XCTestCase {
    func testArmingRequiredAndExpires() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        XCTAssertThrowsError(try RouterHitCorrelationEntry.requireArmed(nil, mode: .tlsHeld, now: now)) { error in
            XCTAssertEqual(error as? RouterHitCorrelationEntry.Failure, .disarmed)
        }
        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric, now: now, ttl: 30)
        XCTAssertTrue(arming.isValid(now: now.addingTimeInterval(10)))
        XCTAssertThrowsError(try RouterHitCorrelationEntry.requireArmed(arming, mode: .tlsHeld, now: now)) { error in
            XCTAssertEqual(error as? RouterHitCorrelationEntry.Failure, .modeMismatch)
        }
        XCTAssertThrowsError(try RouterHitCorrelationEntry.requireArmed(
            arming, mode: .tcpNumeric, now: now.addingTimeInterval(31))) { error in
            XCTAssertEqual(error as? RouterHitCorrelationEntry.Failure, .expired)
        }
        let status = RouterHitCorrelationEntry.status(arming: nil, last: nil, now: now)
        XCTAssertTrue(status.contains("未武装"))
        let armedStatus = RouterHitCorrelationEntry.status(arming: arming, last: nil, now: now)
        XCTAssertTrue(armedStatus.contains("已武装"))
        XCTAssertTrue(armedStatus.contains("不写 accepted") || armedStatus.contains("不自动采样"))
    }

    func testStatusNeverClaimsAcceptedPromotion() {
        let arming = RouterHitCorrelationEntry.arm(mode: .tlsHeld)
        let report = RouterHitCorrelationEntry.Report(
            armingID: arming.id, mode: .tlsHeld, relation: "candidateUnverified",
            reason: "own_tls_candidate_incomplete", connection: nil, compiledOrdinal: 0,
            collectorAuthenticated: false, canPromoteAccepted: false, journalMutated: false,
            gaps: ["ruleUncorrelated", "liveCollectorUnavailable"],
            summary: "受控命中关联（own_tls）· candidateUnverified：own_tls_candidate_incomplete。未写 journal/accepted；collectorAuthenticated=false。")
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertFalse(report.collectorAuthenticated)
        XCTAssertFalse(report.journalMutated)
        let text = RouterHitCorrelationEntry.status(arming: arming, last: report)
        XCTAssertTrue(text.contains("未写 journal/accepted") || text.contains("collectorAuthenticated=false"))
    }
}
