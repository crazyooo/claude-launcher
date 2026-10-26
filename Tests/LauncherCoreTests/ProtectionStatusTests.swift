import XCTest
@testable import LauncherCore

final class ProtectionStatusTests: XCTestCase {
    private let time = Date(timeIntervalSince1970: 1_800_000_000)
    private var settings: PreflightSettings {
        var value = PreflightSettings(); value.expectedIP = "203.0.113.43"; return value
    }
    private func report(missingHost: Bool = false, exit: String = "203.0.113.43") -> PreflightReport {
        let target = CheckTarget.desktop
        let ids = ["baseline", "client", "transport", "service", "unchanged"] + target.hosts.map { "exit:" + $0 }
        let observations = (missingHost ? Array(target.hosts.prefix(1)) : target.hosts).map {
            DomainObservation(host: $0, ip: exit, country: "US", transport: "http://127.0.0.1:1082",
                              milliseconds: 10, check: .init("exit:" + $0, $0, .passed, "fixture"))
        }
        return .init(target: target, startedAt: time, completedAt: time, context: "known",
                     checks: ids.map { .init($0, $0, .passed, $0 == "transport" ? "http://127.0.0.1:1082" : "fixture") },
                     observations: observations)
    }
    func testSuccessfulNetworkNeverGrantsStrictLaunch() {
        let view = ProtectionStatus(report: report(), settings: settings, context: "known", checking: false, now: time)
        XCTAssertTrue(view.networkPassed)
        XCTAssertEqual(view.layers.last?.status, "仅探测匹配")
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
        XCTAssertEqual(view.layers.first { $0.id == "firewall" }?.status, "当前未核验")
        XCTAssertEqual(view.entrance, "http://127.0.0.1:1082")
    }
    func testExpiredChangedOrBusySamplesCannotShowPass() {
        for (date, context, checking) in [(time.addingTimeInterval(31), "known", false),
                                          (time.addingTimeInterval(-1), "known", false),
                                          (time, "changed", false), (time, "known", true)] {
            let view = ProtectionStatus(report: report(), settings: settings, context: context, checking: checking, now: date)
            XCTAssertFalse(view.networkPassed)
            XCTAssertFalse(view.layers.contains { $0.status == "仅探测匹配" || $0.status.hasPrefix("出口探测匹配") })
            XCTAssertFalse(view.networkStatus.hasPrefix("出口探测匹配"))
            XCTAssertNil(view.validUntil)
        }
    }
    func testMissingOrMismatchedExitCannotShowIdentityMatch() {
        for value in [report(missingHost: true), report(exit: "192.0.2.1")] {
            let view = ProtectionStatus(report: value, settings: settings, context: "known", checking: false, now: time)
            XCTAssertEqual(view.layers.last?.status, "未验证")
        }
    }
    func testNoReportOrContextRemainsUnknown() {
        let empty = ProtectionStatus(report: nil, settings: settings, context: nil, checking: false, now: time)
        XCTAssertEqual(empty.observedExit, "尚未取得")
        XCTAssertEqual(empty.entrance, "尚未取得")
        XCTAssertFalse(empty.networkPassed)
        XCTAssertNil(empty.checkedAt)
        XCTAssertFalse(ProtectionStatus(report: report(), settings: settings, context: nil, checking: false, now: time).networkPassed)
    }
    func testLibraryLaunchesRejectBeforeConfigurationOrExecution() {
        XCTAssertThrowsError(try PreflightLaunch.wrap(binary: "/nonexistent", arguments: [])) {
            XCTAssertEqual($0.localizedDescription, StrictProtection.reason)
        }
        XCTAssertThrowsError(try OfficialDesktopLauncher.openAfterCheck()) {
            XCTAssertEqual($0.localizedDescription, StrictProtection.reason)
        }
    }
}
