import XCTest
@testable import LauncherCore
@testable import LauncherApp

@MainActor final class DetectorTestPause {
    private var continuation: CheckedContinuation<Void, Never>?
    private(set) var waiting = false

    func wait() async {
        await withCheckedContinuation { continuation = $0; waiting = true }
    }

    func resume() {
        let pending = continuation
        continuation = nil; waiting = false
        pending?.resume()
    }
}

/// External effects are fixtures; scheduling, state transitions and persistence use production types.
@MainActor final class DetectorModelFixture {
    var settings = EnvironmentSettings()
    var network = String(repeating: "a", count: 64)
    var now = Date()
    var cli: EnvironmentReport?
    var networkCalls = 0
    var activeInspections = 0
    var peakInspections = 0
    var inspectedTargets: [EnvironmentTarget] = []
    var notifications: [String] = []
    var networkHook: ((Int, String) async -> String)?
    var inspectHook: ((Int) async -> Void)?
    var desktopFails = false
    var settingsReadFails = false
    let records: DetectorRecords
    let preferences = MenuBarPreferences(defaults: UserDefaults(suiteName: "detector-tests-\(UUID())")!)

    init() {
        settings.expectedIP = "203.0.113.43"
        settings.diagnosticProxy = "http://127.0.0.1:1082"
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("detector-model-\(UUID())")
        records = DetectorRecords(root: directory)
    }

    func report(_ target: EnvironmentTarget, settings captured: EnvironmentSettings? = nil) -> EnvironmentReport {
        let configuration = captured ?? settings
        let requiredIDs = ["configuration", "baseline", "network-configuration", "context-stable", "network:" + target.serviceHost] +
            target.hosts.flatMap { ["route:" + $0, "exit:" + $0] }
        let checks = requiredIDs.map { id in
            let failure = target == .desktop && desktopFails && id == "exit:claude.ai"
            return EnvironmentCheck(id, id, failure ? .failed : .passed,
                code: failure ? "exit_mismatch" : "fixture_passed", "fixture")
        }
        let source: EnvironmentRouteSource
        switch target {
        case .desktop: source = .systemNetworkRoute
        case .cli: source = .terminalConfiguration
        case .diagnostic: source = .explicitDiagnosticProxy
        }
        return .init(target: target, startedAt: now.addingTimeInterval(-1), completedAt: now,
            networkFingerprint: network,
            configurationFingerprint: EnvironmentInspector.configurationFingerprint(settings: configuration),
            context: String(repeating: "c", count: 64), checks: checks,
            observations: target.hosts.map {
                .init(host: $0, ip: configuration.expectedIP, country: "US", transport: "fixture",
                      source: source, milliseconds: 1)
            })
    }

    var effects: DetectorEffects {
        .init(settings: {
            if self.settingsReadFails { throw LauncherError.message("fixture settings unreadable") }
            return self.settings
        }, save: { self.settings = $0 }, network: {
            self.networkCalls += 1
            let captured = self.network
            if let hook = self.networkHook { return await hook(self.networkCalls, captured) }
            return captured
        }, inspect: { target, settings in
            self.activeInspections += 1
            self.peakInspections = max(self.peakInspections, self.activeInspections)
            self.inspectedTargets.append(target)
            let sample = self.report(target, settings: settings)
            await self.inspectHook?(self.inspectedTargets.count)
            self.activeInspections -= 1
            return sample
        }, cli: { self.cli }, now: { self.now }, notify: { self.notifications.append($0) })
    }

    func model() -> EnvironmentModel {
        .init(effects: effects, records: records, startMonitoring: false, preferences: preferences)
    }
}

final class DetectorModelTests: XCTestCase {
    @MainActor private func settle(_ predicate: () -> Bool,
                                  file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<500 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        XCTFail("detector did not settle", file: file, line: line)
    }

    @MainActor func testRepeatedManualChecksStaySingleFlight() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model(), pause = DetectorTestPause()
        fixture.inspectHook = { if $0 == 1 { await pause.wait() } }
        defer { pause.resume() }
        model.detect()
        try await settle { pause.waiting }
        for _ in 0..<8 { model.detect() }
        XCTAssertEqual(fixture.inspectedTargets, [.desktop])
        pause.resume()
        try await settle { !model.busy }
        XCTAssertEqual(fixture.inspectedTargets, [.desktop, .diagnostic])
        XCTAssertEqual(fixture.peakInspections, 1)
        XCTAssertEqual(model.recommendation(.desktop), .ready)
    }

    @MainActor func testNetworkChangeDiscardsOldScanAndRescansAfterItEnds() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model(), pause = DetectorTestPause()
        fixture.inspectHook = { if $0 == 1 { await pause.wait() } }
        defer { pause.resume() }
        model.detect()
        try await settle { pause.waiting }
        fixture.network = String(repeating: "b", count: 64)
        model.invalidate(.networkChanged)
        XCTAssertTrue(model.reports.isEmpty)
        XCTAssertEqual(fixture.inspectedTargets.count, 1)
        pause.resume()
        try await settle { !model.busy && model.reports[.desktop]?.networkFingerprint == fixture.network }
        XCTAssertEqual(fixture.peakInspections, 1)
        XCTAssertEqual(model.recommendation(.desktop), .ready)
    }

    @MainActor func testOldInitialNetworkReplyCannotRevalidateCachedCLI() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let firstNetwork = DetectorTestPause(), firstInspection = DetectorTestPause()
        let oldNetwork = fixture.network
        fixture.cli = fixture.report(.cli)
        fixture.networkHook = { call, captured in
            if call == 1 { await firstNetwork.wait() }
            return captured
        }
        fixture.inspectHook = { if $0 == 1 { await firstInspection.wait() } }
        defer { firstNetwork.resume(); firstInspection.resume() }
        model.detect()
        try await settle { firstNetwork.waiting }
        fixture.network = String(repeating: "b", count: 64)
        model.invalidate(.networkChanged)
        firstNetwork.resume()
        try await settle { firstInspection.waiting }
        XCTAssertNotEqual(model.currentNetwork, oldNetwork)
        model.tick()
        XCTAssertNotEqual(model.recommendation(.cli), .ready)
        firstInspection.resume()
        try await settle { !model.busy }
        XCTAssertEqual(model.currentNetwork, fixture.network)
    }

    @MainActor func testSleepInvalidatesAndWakeResamplesWithoutParallelWork() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        model.detect()
        try await settle { !model.busy }
        let oldID = model.reports[.desktop]?.id, count = fixture.inspectedTargets.count
        model.sleepChanged(true)
        fixture.now.addTimeInterval(60)
        model.tick(); model.detect()
        XCTAssertEqual(fixture.inspectedTargets.count, count)
        XCTAssertTrue(model.reports.isEmpty)
        model.sleepChanged(false)
        try await settle { !model.busy && model.reports[.desktop] != nil }
        XCTAssertNotEqual(model.reports[.desktop]?.id, oldID)
        XCTAssertGreaterThan(fixture.inspectedTargets.count, count)
        XCTAssertEqual(fixture.peakInspections, 1)
    }

    @MainActor func testCLISnapshotNeverUsesGUIInspectionAsTerminalEvidence() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        let cli = fixture.report(.cli)
        fixture.cli = cli
        model.detect()
        try await settle { !model.busy }
        XCTAssertEqual(model.reports[.cli]?.id, cli.id)
        XCTAssertEqual(model.recommendation(.cli), .ready)
        XCTAssertFalse(fixture.inspectedTargets.contains(.cli))
        fixture.cli = nil
        model.tick()
        XCTAssertNil(model.reports[.cli])
    }

    @MainActor func testWebsiteRecordCannotChangeRecommendationAndSleepMakesItHistorical() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        model.detect()
        try await settle { !model.busy }
        let reportID = model.reports[.desktop]?.id
        try model.saveWebsite(at: fixture.now, ip: "192.0.2.10", result: .issue)
        XCTAssertTrue(model.websiteRecent)
        XCTAssertEqual(model.recommendation(.desktop), .ready)
        XCTAssertEqual(model.reports[.desktop]?.id, reportID)
        model.sleepChanged(true)
        XCTAssertFalse(model.websiteRecent)
        XCTAssertNotNil(model.website)
        let reopened = fixture.model()
        XCTAssertNotNil(reopened.website)
        XCTAssertFalse(reopened.websiteRecent)
    }

    @MainActor func testWebsiteObservationBeforeCurrentNetworkEpochRemainsHistorical() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        model.detect()
        try await settle { !model.busy }
        let previousObservation = fixture.now
        fixture.now.addTimeInterval(30)
        model.invalidate(.networkChanged)
        model.detect()
        try await settle { !model.busy }
        try model.saveWebsite(at: previousObservation, ip: "192.0.2.10", result: .clear)
        XCTAssertFalse(model.websiteRecent)
        XCTAssertEqual(model.website?.observedAt, previousObservation)
        try model.saveWebsite(at: fixture.now, ip: "192.0.2.10", result: .clear)
        XCTAssertTrue(model.websiteRecent)
        XCTAssertEqual(model.recommendation(.desktop), .ready)
    }

    @MainActor func testBackgroundRecoveryRequiresManualRecheckAndDeduplicatesNotifications() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.desktopFails = true
        model.detect()
        try await settle { !model.busy }
        XCTAssertTrue(model.manualRequired)
        XCTAssertEqual(fixture.notifications.count, 1)
        model.detect(manual: false)
        try await settle { !model.busy }
        XCTAssertEqual(fixture.notifications.count, 1)
        fixture.desktopFails = false
        model.detect(manual: false)
        try await settle { !model.busy }
        XCTAssertTrue(model.manualRequired)
        XCTAssertEqual(model.recommendation(.desktop), .attention)
        model.detect()
        try await settle { !model.busy }
        XCTAssertFalse(model.manualRequired)
        XCTAssertEqual(model.recommendation(.desktop), .ready)
    }

    @MainActor func testManualAlertDoesNotTurnContextPollingIntoTwoSecondProbes() async throws {
        let fixture = DetectorModelFixture(), model = fixture.model()
        fixture.desktopFails = true
        model.detect()
        try await settle { !model.busy }
        fixture.desktopFails = false
        fixture.now.addTimeInterval(1)
        model.invalidate(.networkChanged)
        model.detect(manual: false)
        try await settle { !model.busy }
        XCTAssertTrue(model.manualRequired)
        XCTAssertNil(model.reports[.desktop])

        let inspectionCount = fixture.inspectedTargets.count
        let networkCount = fixture.networkCalls
        let unexpectedInspection = DetectorTestPause()
        fixture.inspectHook = { if $0 > inspectionCount { await unexpectedInspection.wait() } }
        defer { unexpectedInspection.resume() }
        fixture.now.addTimeInterval(2)
        model.tick()
        try await settle { fixture.networkCalls > networkCount }
        // Let the context callback reach its scheduling decision. Any accidental probe is held.
        for _ in 0..<8 { await Task.yield() }
        XCTAssertEqual(fixture.inspectedTargets.count, inspectionCount)
        XCTAssertFalse(model.busy)

        fixture.inspectHook = nil
        unexpectedInspection.resume()
        fixture.now.addTimeInterval(28)
        model.tick()
        try await settle { !model.busy && fixture.inspectedTargets.count >= inspectionCount + 2 }
        XCTAssertEqual(fixture.inspectedTargets.count, inspectionCount + 2)
        XCTAssertEqual(fixture.peakInspections, 1)
    }
}
