import XCTest
@testable import LauncherCore
@testable import LauncherApp

/// Runs the menu's production actions against the real shared model. Fixtures
/// replace network, disk settings and notifications; no live probes or UI clicks.
final class DetectorMenuTests: XCTestCase {
    @MainActor private func settle(_ predicate: () -> Bool,
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<500 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        XCTFail("menu state did not settle", file: file, line: line)
    }

    @MainActor func testOpeningMenuWithoutEvidenceDoesNotClaimSuccessOrStartDetection() {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let menu = DetectorMenu(model: model)
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
        XCTAssertEqual(menu.checkButtonTitle, "一键检测")
        XCTAssertFalse(menu.checkDisabled)
        XCTAssertTrue(fixture.inspectedTargets.isEmpty)
        XCTAssertEqual(fixture.networkCalls, 0)
    }

    @MainActor func testMenuCheckUpdatesSharedModelAndDisablesRepeatedClicksWhileBusy() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model(), pause = DetectorTestPause()
        fixture.cli = fixture.report(.cli)
        fixture.inspectHook = { if $0 == 1 { await pause.wait() } }
        defer { pause.resume() }
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { pause.waiting }
        XCTAssertEqual(model.headline, "正在检测")
        XCTAssertEqual(menu.menuConclusionLine, "正在后台检测…")
        XCTAssertEqual(menu.checkButtonTitle, "检测中…")
        XCTAssertTrue(menu.checkDisabled)
        for _ in 0..<8 { menu.check() }
        XCTAssertEqual(fixture.inspectedTargets, [.desktop])
        pause.resume()
        try await settle { !model.busy }
        XCTAssertEqual(fixture.inspectedTargets, [.desktop, .diagnostic])
        XCTAssertEqual(fixture.peakInspections, 1)
        XCTAssertEqual(model.headline, "检查通过")
        XCTAssertEqual(menu.menuConclusionLine, "本轮环境检测可用")
        XCTAssertEqual(menu.checkButtonTitle, "一键检测")
        XCTAssertFalse(menu.checkDisabled)
    }

    @MainActor func testConsoleCheckIsReflectedInMenuWithoutAnotherInspection() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.cli = fixture.report(.cli)
        let menu = DetectorMenu(model: model)
        // The console calls detect() on this same EnvironmentModel.
        model.detect()
        XCTAssertTrue(menu.checkDisabled)
        try await settle { !model.busy }
        XCTAssertEqual(menu.menuConclusionLine, "本轮环境检测可用")
        XCTAssertEqual(fixture.inspectedTargets, [.desktop, .diagnostic])
        let reopenedMenu = DetectorMenu(model: model)
        XCTAssertEqual(reopenedMenu.menuConclusionLine, menu.menuConclusionLine)
        XCTAssertEqual(fixture.inspectedTargets.count, 2)
    }

    @MainActor func testSuccessfulProxyCannotHideMissingCLIEvidenceInMenu() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.recommendation(.desktop), .ready)
        XCTAssertEqual(model.recommendation(.diagnostic), .ready)
        XCTAssertEqual(model.recommendation(.cli), .unknown)
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
        XCTAssertFalse(fixture.inspectedTargets.contains(.cli))
    }

    @MainActor func testExpiredCLIStopsMenuFromShowingPassAfterFreshDesktopCheck() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.cli = fixture.report(.cli)
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "检查通过")
        fixture.now.addTimeInterval(EnvironmentReport.lifetime + 1)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.recommendation(.desktop), .ready)
        XCTAssertEqual(model.recommendation(.cli), .stale)
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
    }

    @MainActor func testMenuManualCheckClearsAlertOnlyAfterSuccessfulRecheck() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.cli = fixture.report(.cli)
        fixture.desktopFails = true
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "发现问题")
        XCTAssertEqual(menu.menuConclusionLine, "本轮异常，打开控制台查看")
        XCTAssertTrue(model.manualRequired)
        fixture.desktopFails = false
        model.detect(manual: false)
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "发现问题")
        XCTAssertTrue(model.manualRequired)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "检查通过")
        XCTAssertEqual(menu.menuConclusionLine, "本轮环境检测可用")
        XCTAssertFalse(model.manualRequired)
    }

    @MainActor func testNetworkChangeAndSleepRemovePreviousMenuSuccess() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.cli = fixture.report(.cli)
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "检查通过")
        model.invalidate(.networkChanged)
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
        menu.check()
        try await settle { !model.busy }
        XCTAssertEqual(model.headline, "检查通过")
        model.sleepChanged(true)
        let calls = fixture.inspectedTargets.count
        menu.check()
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
        XCTAssertEqual(fixture.inspectedTargets.count, calls)
        XCTAssertFalse(model.busy)
    }

    @MainActor func testUnreadableSettingsClearMenuSuccessAndAllowRetry() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.cli = fixture.report(.cli)
        let menu = DetectorMenu(model: model)
        menu.check()
        try await settle { !model.busy }
        fixture.settingsReadFails = true
        let calls = fixture.inspectedTargets.count
        menu.check()
        XCTAssertFalse(model.readable)
        XCTAssertEqual(model.headline, "尚未测全")
        XCTAssertEqual(menu.menuConclusionLine, "尚未测全，点一键检测")
        XCTAssertFalse(menu.checkDisabled)
        XCTAssertEqual(fixture.inspectedTargets.count, calls)
        fixture.settingsReadFails = false
        menu.check()
        try await settle { !model.busy }
        XCTAssertTrue(model.readable)
        XCTAssertEqual(model.headline, "检查通过")
    }

    @MainActor func testOpenConsoleTargetsMainWindowThenActivatesWithoutProbing() {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let menu = DetectorMenu(model: model)
        var events: [String] = []
        menu.openConsole(open: { events.append("open:" + $0) },
                         activate: { events.append("activate") })
        XCTAssertEqual(events, ["open:main", "activate"])
        XCTAssertEqual(fixture.networkCalls, 0)
        XCTAssertTrue(fixture.inspectedTargets.isEmpty)
        XCTAssertFalse(model.busy)
    }
}
