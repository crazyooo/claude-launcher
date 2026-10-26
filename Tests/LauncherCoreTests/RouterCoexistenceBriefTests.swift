import XCTest
@testable import LauncherCore

final class RouterCoexistenceBriefTests: XCTestCase {
    func testTunnelCaptureRefusesOwnTunAndKeepsAcceptanceFalse() {
        let path = CurrentPathPortrait.Snapshot(
            capturedAt: Date(timeIntervalSince1970: 1),
            summary: "s",
            findings: ["经隧道"],
            nextSteps: ["测已保存线路：默认可能失败，用路径对照。"],
            candidates: [],
            proxies: [],
            targets: [
                .init(host: "claude.ai", resolved: "198.18.0.56", routeInterface: "utun8",
                      routeKind: "tunnel", reachability: "reached_403")
            ],
            lines: [
                .init(lineID: UUID(), name: "mei", host: "203.0.113.43", port: 9034,
                      routeInterface: "utun8", routeKind: "tunnel", note: "经隧道")
            ])
        let report = RouterCoexistenceBrief.compose(
            network: .init(complete: true, tunnelCaptureInterfaces: ["utun8"], connectedVPN: false,
                           applicationProxyEnabled: true, automaticProxyEnabled: false,
                           userCoreJobPresent: false),
            path: path)
        XCTAssertTrue(report.refuseOwnTun)
        XCTAssertTrue(report.reasons.contains(where: { $0.contains("utun8") && $0.contains("requireClear") }))
        XCTAssertTrue(report.reasons.contains(where: { $0.contains("系统应用代理") }))
        XCTAssertTrue(report.pathNotes.contains(where: { $0.contains("假地址") }))
        XCTAssertTrue(report.pathNotes.contains(where: { $0.contains("mei") && $0.contains("路径对照") }))
        XCTAssertTrue(report.nextActions.contains(where: { $0.contains("不会替你关你的代理客户端") }))
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        let forced = RouterCoexistenceBrief.Report(
            title: "x", refuseOwnTun: false, reasons: [], pathNotes: [], nextActions: [],
            wouldChangeIfClear: [], routingVerified: true, accepted: true)
        XCTAssertFalse(forced.routingVerified)
        XCTAssertFalse(forced.accepted)
    }

    func testClearObservationStillDoesNotClaimAccepted() {
        let report = RouterCoexistenceBrief.compose(
            network: .init(complete: true, tunnelCaptureInterfaces: [], connectedVPN: false,
                           applicationProxyEnabled: false, automaticProxyEnabled: false,
                           userCoreJobPresent: false),
            path: nil)
        XCTAssertFalse(report.refuseOwnTun)
        XCTAssertTrue(report.title.contains("不表示已接管") || report.nextActions.contains(where: { $0.contains("accepted") }))
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertTrue(report.wouldChangeIfClear.contains(where: { $0.contains("TUN") }))
        XCTAssertTrue(report.wouldChangeIfClear.contains(where: {
            $0.contains("断流尚未验证") || $0.contains("REJECT")
        }))
    }
}
