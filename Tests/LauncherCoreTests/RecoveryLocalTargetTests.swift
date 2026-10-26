import XCTest
import Darwin
@testable import LauncherCore

final class RecoveryLocalTargetTests: XCTestCase {
    private func directory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().appendingPathComponent("recovery-local-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false); return url
    }
    private func settings() -> PreflightSettings { var settings = PreflightSettings(); settings.expectedIP = "203.0.113.43"; return settings }
    private func snapshot(_ context: String = String(repeating: "a", count: 64), owned: Bool = true,
                          object: @escaping (URL) throws -> [String: Any] = { _ in [:] }) -> RecoveryLocalSnapshot {
        .init(context: context, source: .init(installed: true, running: false, readObject: object,
                                             wrapperInstalled: { owned }, fallbackTransport: .init()))
    }
    func testReportIsLocalOnlyTargetBoundAndExpiresWithoutNetworkPermissions() {
        let now = Date(), snapshot = snapshot()
        let report = RecoveryLocalTargetInspector.inspect(settings: settings(), connector: .init(), target: .desktopCode,
                                                          capture: { snapshot }, clock: { now })
        XCTAssertTrue(report.satisfiesLocalRequirements(target: .desktopCode, context: snapshot.context, now: now))
        XCTAssertFalse(report.satisfiesLocalRequirements(target: .vscode, context: snapshot.context, now: now))
        XCTAssertFalse(report.satisfiesLocalRequirements(target: .desktopCode, context: snapshot.context, now: now.addingTimeInterval(-1)))
        XCTAssertFalse(report.satisfiesLocalRequirements(target: .desktopCode, context: snapshot.context, now: now.addingTimeInterval(30.001)))
        XCTAssertFalse(report.satisfiesLocalRequirements(target: .desktopCode, context: String(repeating: "b", count: 64), now: now))
        XCTAssertFalse(report.checks.contains { $0.id == "service" || $0.id.hasPrefix("exit:") })
        XCTAssertTrue(report.checks.last!.detail.contains("不包含独立 CLI")); XCTAssertFalse(StrictProtection.verified)
    }
    func testMalformedMissingDuplicateMandatoryAndTimeOrderingRefuseLocalPass() {
        let now = Date(), snapshot = snapshot()
        let report = RecoveryLocalTargetInspector.inspect(settings: settings(), connector: .init(), target: .desktop,
                                                          capture: { snapshot }, clock: { now })
        for checks in [Array(report.checks.dropFirst()), report.checks + [report.checks[0]],
                       report.checks + [.init("unknown", "未知", .unknown, "test")]] {
            let invalid = RecoveryLocalTargetReport(target: report.target, startedAt: now, completedAt: now,
                startedTick: report.startedTick, completedTick: report.completedTick, context: report.context, checks: checks)
            XCTAssertFalse(invalid.satisfiesLocalRequirements(target: .desktop, context: report.context, now: now))
        }
        for completed in [now.addingTimeInterval(-1), now.addingTimeInterval(1)] {
            let invalid = RecoveryLocalTargetReport(target: .desktop, startedAt: now, completedAt: completed,
                startedTick: report.startedTick, completedTick: report.completedTick, context: report.context, checks: report.checks)
            XCTAssertFalse(invalid.satisfiesLocalRequirements(target: .desktop, context: report.context, now: now))
        }
    }
    func testChangedUnreadableAndMismatchedBaselineNeverReuseLocalEvidence() {
        for failure in ["changed", "before-read", "after-read", "baseline"] {
            var calls = 0, connector = ConnectorConfiguration()
            if failure == "baseline" { connector.expectedIPv4 = "192.0.2.1" }
            let report = RecoveryLocalTargetInspector.inspect(settings: settings(), connector: connector, target: .desktop, capture: {
                calls += 1
                if failure == "before-read" || (failure == "after-read" && calls == 2) { throw RecoveryLocalFile.failure }
                return self.snapshot(String(repeating: calls == 2 && failure == "changed" ? "b" : "a", count: 64))
            })
            XCTAssertFalse(report.satisfiesLocalRequirements(target: .desktop, context: report.context), failure)
            XCTAssertEqual(Set(report.checks.map(\.id)).count, report.checks.count)
        }
    }
    func testVSCodeRetainsWrapperAndConflictingEnvironmentChecks() {
        for kind in ["good", "wrapper", "bypass", "tls", "conflict"] {
            let report = RecoveryLocalTargetInspector.inspect(settings: settings(), connector: .init(), target: .vscode, capture: {
                self.snapshot(owned: kind != "wrapper") { url in
                    if url == ClientInspection.vscodeSettings {
                        var value: [String: Any] = ["claudeCode.claudeProcessWrapper": ClientInspection.vscodeWrapper]
                        if kind == "bypass" { value["claudeCode.environmentVariables"] = [["name": "NO_PROXY", "value": "*"]] }
                        if kind == "tls" { value["claudeCode.environmentVariables"] = [["name": "NODE_TLS_REJECT_UNAUTHORIZED", "value": "0"]] }
                        if kind == "conflict" { value["http.proxy"] = "socks5h://127.0.0.1:1082" }
                        return value
                    }
                    return [:]
                }
            })
            XCTAssertEqual(report.satisfiesLocalRequirements(target: .vscode, context: report.context), kind == "good", kind)
        }
    }
    func testBoundedReaderDistinguishesAbsenceFromSpecialLinksAndOversize() throws {
        let root = try directory(), file = root.appendingPathComponent("config.json")
        XCTAssertNil(try RecoveryLocalFile.read(file))
        try Data("{}".utf8).write(to: file)
        XCTAssertTrue(try RecoveryLocalFile.object(RecoveryLocalFile.read(file)).isEmpty)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertThrowsError(try RecoveryLocalFile.read(link))
        let fifo = root.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        XCTAssertThrowsError(try RecoveryLocalFile.read(fifo))
        XCTAssertThrowsError(try RecoveryLocalFile.read(root))
        try Data(repeating: 65, count: RecoveryLocalFile.limit + 1).write(to: file)
        XCTAssertThrowsError(try RecoveryLocalFile.read(file))
        try Data("invalid".utf8).write(to: file)
        XCTAssertThrowsError(try RecoveryLocalFile.object(RecoveryLocalFile.read(file)))
        XCTAssertThrowsError(try RecoveryLocalTargetInspector.canonicalDirectory("relative"))
        XCTAssertThrowsError(try RecoveryLocalTargetInspector.canonicalDirectory(root.appendingPathComponent("absent").path))
    }
    func testStrictSnapshotUsesCapturedExtensionWrapperManifestAndHashInputs() throws {
        let root = try directory(), app = root.appendingPathComponent("Code.app"), wrapper = URL(fileURLWithPath: ClientInspection.vscodeWrapper)
        let extensionIndex = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".vscode/extensions/extensions.json")
        let manifest = Paths.root.appendingPathComponent("installation.json"), info = app.appendingPathComponent("Contents/Info.plist")
        var files: [URL: RecoveryLocalFile.Value] = [:]
        func value(_ text: String, executable: Bool = false) -> RecoveryLocalFile.Value {
            .init(data: Data(text.utf8), executable: executable, fingerprint: fingerprintData(Data((text + String(executable)).utf8)))
        }
        let plist = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.microsoft.VSCode"], format: .xml, options: 0)
        files[info] = .init(data: plist, executable: false, fingerprint: fingerprintData(plist))
        files[extensionIndex] = value("[{\"identifier\":{\"id\":\"anthropic.claude-code\"}}]")
        files[wrapper] = value("fixture wrapper", executable: true)
        files[manifest] = value("{\"scripts\":{\"claude-vscode-preflight\":\"\(fingerprintData(files[wrapper]!.data))\"}}")
        files[ClientInspection.vscodeSettings] = value("{\"claudeCode.claudeProcessWrapper\":\"\(ClientInspection.vscodeWrapper)\"}")
        func capture(_ env: [String: String] = [:], connector: ConnectorConfiguration = .init()) throws -> RecoveryLocalSnapshot {
            try RecoveryLocalTargetInspector.snapshot(settings: settings(), connector: connector, target: .vscode,
                directory: nil, environment: env, read: { files[$0] }, locateApps: { _ in [app] })
        }
        let before = try capture()
        XCTAssertTrue(before.source.installed); XCTAssertTrue(before.source.wrapperInstalled())
        XCTAssertNotEqual(try capture(["HTTP_PROXY": "http://127.0.0.1:12345"]).context, before.context)
        var connector = ConnectorConfiguration(); connector.upstreamPort += 1
        XCTAssertNotEqual(try capture(connector: connector).context, before.context)
        files[wrapper] = value("changed", executable: true)
        XCTAssertFalse(try capture().source.wrapperInstalled()); XCTAssertNotEqual(try capture().context, before.context)
        files[extensionIndex] = value("{}"); XCTAssertThrowsError(try capture())
        files[extensionIndex] = nil; XCTAssertFalse(try capture().source.installed)
        XCTAssertThrowsError(try RecoveryLocalTargetInspector.snapshot(settings: settings(), connector: .init(), target: .desktop,
            directory: nil, environment: [:], read: { _ in throw RecoveryLocalFile.failure }, locateApps: { _ in [app] }))
    }

    func testCurrentUserExecutionPermissionIsIncludedInSnapshot() throws {
        guard getuid() != 0 else { throw XCTSkip("Requires ordinary owner permissions") }
        let file = try directory().appendingPathComponent("wrapper")
        try Data("fixture".utf8).write(to: file)
        var snapshots: [RecoveryLocalFile.Value] = []
        for mode: mode_t in [0o600, 0o601, 0o700] {
            XCTAssertEqual(chmod(file.path, mode), 0)
            let value = try XCTUnwrap(RecoveryLocalFile.read(file))
            XCTAssertEqual(value.executable, mode == 0o700)
            snapshots.append(value)
        }
        XCTAssertEqual(snapshots[1].data, snapshots[2].data)
        XCTAssertNotEqual(snapshots[1].fingerprint, snapshots[2].fingerprint)
    }

    func testEveryApplicationCandidateUsesBoundedReader() throws {
        let root = try directory()
        let candidates = ["a-missing.app", "b-good.app", "c-bad.app"].map { root.appendingPathComponent($0) }
        let info = candidates.map { $0.appendingPathComponent("Contents/Info.plist") }
        let data = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": "com.anthropic.claudefordesktop"], format: .xml, options: 0)
        for bad in [false, true] {
            var visited = Set<URL>()
            func capture() throws -> RecoveryLocalSnapshot {
                try RecoveryLocalTargetInspector.snapshot(settings: settings(), connector: .init(), target: .desktop,
                    directory: nil, environment: [:], read: { url in
                        visited.insert(url)
                        if url == info[2], bad { throw RecoveryLocalFile.failure }
                        return url == info[1] ? .init(data: data, executable: false, fingerprint: fingerprintData(data)) : nil
                    }, locateApps: { _ in candidates })
            }
            if bad { XCTAssertThrowsError(try capture()) }
            else { XCTAssertTrue(try capture().source.installed) }
            XCTAssertTrue(Set(info).isSubset(of: visited))
        }
    }

    func testCanonicalConfigurationPathsAreCapturedAndSymlinkChangesInvalidate() throws {
        let root = try directory(), first = root.appendingPathComponent("first"), second = root.appendingPathComponent("second")
        for url in [first, second] { try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false) }
        let link = root.appendingPathComponent("current")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: first)
        func capture(_ path: URL) throws -> RecoveryLocalSnapshot {
            try RecoveryLocalTargetInspector.snapshot(settings: settings(), connector: .init(), target: .vscode,
                directory: path.path, environment: [:], read: { _ in nil }, locateApps: { _ in [] })
        }
        let original = try capture(link), canonical = try capture(first)
        XCTAssertEqual(original.context, canonical.context)
        XCTAssertEqual(original.source.configurationFiles, canonical.source.configurationFiles)
        try FileManager.default.moveItem(at: link, to: root.appendingPathComponent("previous-link"))
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: second)
        XCTAssertNotEqual(try capture(link).context, original.context)
        // The captured inspector does not follow the now-retargeted original directory.
        let inspection = ClientInspection.inspect(target: .vscode, directory: link.path, environment: [:], source: original.source)
        XCTAssertEqual(inspection.checks.first { $0.id == "code-network" }?.result, .passed)
    }

    func testMonotonicLifetimeCannotBeRenewedByWallClockRollback() {
        let wall = Date(), snapshot = snapshot()
        let report = RecoveryLocalTargetInspector.inspect(settings: settings(), connector: .init(), target: .desktop,
            capture: { snapshot }, clock: { wall }, monotonic: { 100 })
        XCTAssertTrue(report.satisfiesLocalRequirements(target: .desktop, context: report.context, now: wall, tick: 130))
        for tick in [99, 130.001, 3700, Double.nan, Double.infinity] {
            XCTAssertFalse(report.satisfiesLocalRequirements(target: .desktop, context: report.context, now: wall, tick: tick))
        }
        for (start, end): (Double, Double) in [(100, 99), (100, 102), (-1, 0), (.nan, 100), (100, .infinity)] {
            let invalid = RecoveryLocalTargetReport(target: .desktop, startedAt: wall, completedAt: wall,
                startedTick: start, completedTick: end, context: report.context, checks: report.checks)
            XCTAssertFalse(invalid.satisfiesLocalRequirements(target: .desktop, context: report.context, now: wall, tick: 101))
        }
    }
}
