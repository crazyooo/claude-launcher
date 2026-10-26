import XCTest
@testable import LauncherCore

/// URL-level contract for the settings tri-state. Only a missing directory entry may be
/// treated as a first run; everything else must surface as an error so callers can refuse
/// to overwrite an existing configuration.
final class PreflightSettingsPresenceTests: XCTestCase {
    private var directory: URL!
    override func setUpWithError() throws {
        directory = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath()
            .appendingPathComponent("settings-presence-\(UUID())")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                attributes: [.posixPermissions: 0o700])
    }
    override func tearDownWithError() throws { try? FileManager.default.removeItem(at: directory) }
    private func path() -> URL { directory.appendingPathComponent("preflight-settings.json") }
    private func validSettings() -> PreflightSettings {
        var value = PreflightSettings(); value.expectedIP = "203.0.113.43"; return value
    }
    func testMissingEntryIsConfirmedAbsentButStrictReadFails() throws {
        XCTAssertNil(try PreflightSettings.readIfPresent(path()))
        XCTAssertThrowsError(try PreflightSettings.read(from: path()))
    }
    func testValidFileRoundTrips() throws {
        let url = path(), value = validSettings()
        try saveJSON(value, to: url)
        XCTAssertEqual(try PreflightSettings.readIfPresent(url), value)
    }
    func testDanglingSymlinkIsNotAbsence() throws {
        let url = path()
        try FileManager.default.createSymbolicLink(at: url, withDestinationURL: directory.appendingPathComponent("gone.json"))
        XCTAssertThrowsError(try PreflightSettings.readIfPresent(url), "a dangling link must never look like a first run")
    }
    func testCorruptEmptyAndDirectoryAreNotAbsence() throws {
        let url = path()
        try Data("{\"expectedIP\":".utf8).write(to: url)
        XCTAssertThrowsError(try PreflightSettings.readIfPresent(url))
        try Data().write(to: url)
        XCTAssertThrowsError(try PreflightSettings.readIfPresent(url))
        try FileManager.default.removeItem(at: url)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
        XCTAssertThrowsError(try PreflightSettings.readIfPresent(url))
    }
    func testCorruptFileBytesSurviveFailedRead() throws {
        let url = path(), bytes = Data("not json at all".utf8)
        try bytes.write(to: url)
        XCTAssertThrowsError(try PreflightSettings.readIfPresent(url))
        XCTAssertEqual(try Data(contentsOf: url), bytes)
    }
}
