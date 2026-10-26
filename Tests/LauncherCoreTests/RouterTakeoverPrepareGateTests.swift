import XCTest
@testable import LauncherCore

final class RouterTakeoverPrepareGateTests: XCTestCase {
    func testMissingBriefBlocksPrepare() {
        let decision = RouterTakeoverPrepareGate.decide(sessionCanPrepare: true, editorBusy: false, brief: nil)
        XCTAssertFalse(decision.allowed)
        XCTAssertTrue(decision.message.contains("检查现有网络"))
    }

    func testRefuseOwnTunBlocksWithoutSendingPreview() {
        let brief = RouterCoexistenceBrief.compose(
            network: .init(complete: true, tunnelCaptureInterfaces: ["utun8"], connectedVPN: false,
                           applicationProxyEnabled: false, automaticProxyEnabled: false,
                           userCoreJobPresent: false),
            path: nil)
        XCTAssertTrue(brief.refuseOwnTun)
        let decision = RouterTakeoverPrepareGate.decide(sessionCanPrepare: true, editorBusy: false, brief: brief)
        XCTAssertFalse(decision.allowed)
        XCTAssertTrue(decision.message.contains("不会发送接管预览请求"))
        XCTAssertTrue(decision.message.contains("utun8") || decision.message.contains("隧道"))
        XCTAssertFalse(brief.routingVerified)
        XCTAssertFalse(brief.accepted)
    }

    func testClearBriefAllowsPrepareAttempt() {
        let brief = RouterCoexistenceBrief.compose(
            network: .init(complete: true, tunnelCaptureInterfaces: [], connectedVPN: false,
                           applicationProxyEnabled: false, automaticProxyEnabled: false,
                           userCoreJobPresent: false),
            path: nil)
        XCTAssertFalse(brief.refuseOwnTun)
        let decision = RouterTakeoverPrepareGate.decide(sessionCanPrepare: true, editorBusy: false, brief: brief)
        XCTAssertTrue(decision.allowed)
        XCTAssertTrue(decision.message.contains("不表示已接管") || decision.message.contains("accepted"))
    }
}
