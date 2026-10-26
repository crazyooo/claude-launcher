import XCTest
@testable import LauncherApp
import LauncherCore

final class DetectorPresentationTests: XCTestCase {
    func testOverviewDoesNotCoverMissingCLIWithSuccessfulProxy() {
        XCTAssertEqual(DetectorPresentation.overall([.ready, .unknown, .ready]), .unknown)
        XCTAssertEqual(DetectorPresentation.overall([.ready, .stale, .ready]), .unknown)
        XCTAssertEqual(DetectorPresentation.overall([.ready, .attention, .unknown]), .attention)
        XCTAssertEqual(DetectorPresentation.overall([.ready, .ready, .ready]), .ready)
        XCTAssertEqual(DetectorPresentation.overall([]), .unknown)
    }

    func testHistoricalIPNeverMakesDestinationGreen() {
        let report = fixture(route: .passed, exit: .passed)
        XCTAssertEqual(DetectorPresentation.hostState(report: report, host: "claude.ai", recommendation: .stale), .unknown)
        XCTAssertEqual(DetectorPresentation.hostState(report: report, host: "claude.ai", recommendation: .unknown), .unknown)
        XCTAssertEqual(DetectorPresentation.hostState(report: nil, host: "claude.ai", recommendation: .ready), .unknown)
    }

    func testDestinationRequiresRouteAndExitEvidenceNotJustAnIP() {
        XCTAssertEqual(DetectorPresentation.hostState(report: fixture(route: .unknown, exit: .passed), host: "claude.ai", recommendation: .attention), .unknown)
        XCTAssertEqual(DetectorPresentation.hostState(report: fixture(route: .passed, exit: .failed), host: "claude.ai", recommendation: .attention), .attention)
        XCTAssertEqual(DetectorPresentation.hostState(report: fixture(route: .passed, exit: .passed), host: "claude.ai", recommendation: .attention), .ready)
        XCTAssertEqual(DetectorPresentation.hostState(report: fixture(route: .passed, exit: .passed), host: "api.anthropic.com", recommendation: .attention), .unknown)
    }

    private func fixture(route: CheckResult, exit: CheckResult) -> EnvironmentReport {
        .init(target: .desktop, startedAt: Date(), completedAt: Date(), networkFingerprint: "fixture",
              configurationFingerprint: "fixture", context: "fixture", checks: [
                .init("route:claude.ai", "route", route, code: "fixture", "fixture"),
                .init("exit:claude.ai", "exit", exit, code: "fixture", "fixture")
              ], observations: [.init(host: "claude.ai", ip: "203.0.113.43", country: "US", transport: "fixture", source: .systemProxySelection, milliseconds: 1)])
    }
}
