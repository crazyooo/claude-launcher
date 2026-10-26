import XCTest
import ServiceManagement
@testable import LauncherCore
@testable import LauncherApp

final class MenuBarPreferencesTests: XCTestCase {
    @MainActor private func settle(_ predicate: () -> Bool,
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<500 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        XCTFail("preferences action did not settle", file: file, line: line)
    }

    @MainActor func testPreferencesPersistAndInvalidValuesFallBack() {
        let defaults = UserDefaults(suiteName: "menu-preferences-tests-\(UUID())")!
        let preferences = MenuBarPreferences(defaults: defaults)
        XCTAssertTrue(preferences.automaticChecks)
        XCTAssertFalse(preferences.showStatusText)
        XCTAssertEqual(preferences.interval, 30)
        preferences.automaticChecks = false
        preferences.showStatusText = true
        preferences.icon = .pulse
        preferences.interval = 120
        let reopened = MenuBarPreferences(defaults: defaults)
        XCTAssertFalse(reopened.automaticChecks)
        XCTAssertTrue(reopened.showStatusText)
        XCTAssertEqual(reopened.icon, .pulse)
        XCTAssertEqual(reopened.interval, 120)
        defaults.set(-100, forKey: "detector.menu.interval")
        defaults.set("unknown", forKey: "detector.menu.icon")
        let repaired = MenuBarPreferences(defaults: defaults)
        XCTAssertEqual(repaired.interval, 30)
        XCTAssertEqual(repaired.icon, .network)
        repaired.interval = 0
        XCTAssertEqual(repaired.interval, 30)
        XCTAssertEqual(MenuBarPreferences(defaults: defaults).interval, 30)
    }

    @MainActor func testPauseBlocksTimerNetworkWakeAndDirectAutomaticCallsButNotManualCheck() async throws {
        let fixture = DetectorModelFixture()
        fixture.preferences.automaticChecks = false
        let model = fixture.model()
        model.tick()
        model.pathChanged()
        model.sleepChanged(true)
        model.sleepChanged(false)
        model.detect(manual: false)
        for _ in 0..<20 { await Task.yield() }
        XCTAssertTrue(fixture.inspectedTargets.isEmpty)
        XCTAssertFalse(model.busy)
        DetectorMenu(model: model).check()
        try await settle { !model.busy && fixture.inspectedTargets.count == 2 }
        XCTAssertEqual(model.recommendation(.desktop), .ready)
        fixture.now.addTimeInterval(EnvironmentReport.lifetime + 1)
        model.tick()
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(fixture.inspectedTargets.count, 2)
        XCTAssertEqual(model.recommendation(.desktop), .stale)
    }

    @MainActor func testConfiguredIntervalIsUsedAndResumeKeepsSingleFlight() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.preferences.interval = 120
        model.detect()
        try await settle { !model.busy }
        fixture.now.addTimeInterval(31)
        model.tick()
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(fixture.inspectedTargets.count, 2)
        fixture.now.addTimeInterval(89)
        model.tick()
        try await settle { !model.busy && fixture.inspectedTargets.count == 4 }
        fixture.preferences.automaticChecks = false
        fixture.now.addTimeInterval(120)
        model.tick()
        for _ in 0..<20 { await Task.yield() }
        XCTAssertEqual(fixture.inspectedTargets.count, 4)
        fixture.preferences.automaticChecks = true
        model.tick()
        try await settle { !model.busy && fixture.inspectedTargets.count == 6 }
        XCTAssertEqual(fixture.peakInspections, 1)
    }

    @MainActor func testPausingDuringInvalidatedScanPreventsAutomaticRescan() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model(), pause = DetectorTestPause()
        fixture.inspectHook = { if $0 == 1 { await pause.wait() } }
        defer { pause.resume() }
        model.detect()
        try await settle { pause.waiting }
        fixture.preferences.automaticChecks = false
        fixture.network = String(repeating: "b", count: 64)
        model.invalidate(.networkChanged)
        pause.resume()
        try await settle { !model.busy }
        XCTAssertEqual(fixture.inspectedTargets.count, 2)
        XCTAssertTrue(model.reports.isEmpty)
        model.detect()
        try await settle { !model.busy && model.reports[.desktop] != nil }
        XCTAssertEqual(fixture.inspectedTargets.count, 4)
    }

    @MainActor func testLoginRegistrationRequiresActualSystemStateAndReportsFailure() {
        var status = SMAppService.Status.notRegistered
        var registrationCalls = 0, removalCalls = 0
        let login = DetectorLoginItem(effects: .init(status: { status }, register: {
            registrationCalls += 1
            status = .requiresApproval
        }, unregister: {
            removalCalls += 1
            status = .notRegistered
        }))
        XCTAssertFalse(login.requested)
        XCTAssertEqual(registrationCalls, 0, "Opening settings must not register a login item")
        login.setEnabled(true)
        XCTAssertTrue(login.requested)
        XCTAssertEqual(login.status, .requiresApproval)
        XCTAssertTrue(login.detail.contains("等待系统允许"))
        status = .enabled
        login.refresh()
        XCTAssertEqual(login.status, .enabled)
        login.setEnabled(false)
        XCTAssertFalse(login.requested)
        XCTAssertEqual(removalCalls, 1)
        let failure = DetectorLoginItem(effects: .init(status: { .notRegistered }, register: {
            throw LauncherError.message("fixture registration refused")
        }, unregister: {}))
        failure.setEnabled(true)
        XCTAssertFalse(failure.requested)
        XCTAssertFalse(failure.error.isEmpty)
    }

    @MainActor func testMenuSettingsOpensSharedSettingsWindowWithoutDetection() {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let menu = DetectorMenu(model: model)
        var events: [String] = []
        menu.openSettings(open: { events.append("open:" + $0) }, activate: { events.append("activate") })
        XCTAssertEqual(events, ["open:settings", "activate"])
        XCTAssertTrue(fixture.inspectedTargets.isEmpty)
    }
}
