import XCTest
@testable import LauncherCore

final class DetectorRecordsTests: XCTestCase {
    private func directory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("detector-records-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        return url
    }
    func testBoundedLogKeepsWholeNewestRecords() throws {
        let root = try directory(), store = DetectorRecords(root: root, capacity: 2048)
        for index in 0..<100 {
            try store.append(.init(event: .checked, target: .desktop, result: .failed, problem: .timeout,
                                   at: Date(timeIntervalSince1970: Double(index))))
        }
        let bytes = try Data(contentsOf: root.appendingPathComponent("detector-events.json"))
        XCTAssertLessThanOrEqual(bytes.count, 2048)
        let entries = try store.logs()
        XCTAssertEqual(entries.last?.at.timeIntervalSince1970, 99)
        XCTAssertGreaterThan(entries.count, 0); XCTAssertLessThan(entries.count, 100)
    }
    func testExportDropsUnknownPrivateFieldsAndClassifiesOnlyFixedCodes() throws {
        let root = try directory(), store = DetectorRecords(root: root)
        try store.append(.init(event: .checked, target: .cli, result: .unknown,
                               problem: .classify("password=PRIVATE_TOKEN")))
        let url = root.appendingPathComponent("detector-events.json")
        var value = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: url)) as? [[String: Any]])
        value[0]["rawEnvironment"] = "Bearer PRIVATE_TOKEN"
        value[0]["endpoint"] = "http://user:PRIVATE_PASSWORD@localhost:1082"
        try JSONSerialization.data(withJSONObject: value).write(to: url)
        let exported = String(decoding: try store.export(), as: UTF8.self)
        XCTAssertFalse(exported.contains("PRIVATE")); XCTAssertFalse(exported.contains("endpoint"))
        XCTAssertFalse(exported.contains("rawEnvironment"))
        XCTAssertEqual(try store.logs().first?.problem, .other)
        try store.append(.init(event: .networkChanged))
        XCTAssertFalse(String(decoding: try Data(contentsOf: url), as: UTF8.self).contains("PRIVATE"))
    }
    func testCorruptAndSymlinkLogsArePreserved() throws {
        let root = try directory(), store = DetectorRecords(root: root)
        let url = root.appendingPathComponent("detector-events.json"), broken = Data("broken".utf8)
        try broken.write(to: url)
        XCTAssertThrowsError(try store.append(.init(event: .checked)))
        XCTAssertEqual(try Data(contentsOf: url), broken)
        let other = try directory(), linked = other.appendingPathComponent("detector-events.json")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: url)
        XCTAssertThrowsError(try DetectorRecords(root: other).logs())
        XCTAssertThrowsError(try DetectorRecords(root: other).append(.init(event: .checked)))
        XCTAssertEqual(try Data(contentsOf: url), broken)
    }
    func testTwoStoreInstancesPreservePriorEntriesAndPrivatePermissions() throws {
        let root = try directory(), a = DetectorRecords(root: root), b = DetectorRecords(root: root)
        try a.append(.init(event: .networkChanged)); try b.append(.init(event: .settingsChanged))
        XCTAssertEqual(try a.logs().map(\.event), [.networkChanged, .settingsChanged])
        let attributes = try FileManager.default.attributesOfItem(atPath: root.appendingPathComponent("detector-events.json").path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }
    func testWebsiteRecordHasIndependentTimeNetworkAndSessionValidity() throws {
        let now = Date(timeIntervalSince1970: 1_800_000_000), session = UUID()
        let item = try WebsiteObservation(observedAt: now.addingTimeInterval(-300), observedIP: "203.0.113.43",
            result: .clear, network: "network", settings: "settings", session: session, now: now)
        XCTAssertTrue(item.isRecent(network: "network", settings: "settings", session: session, now: now))
        XCTAssertFalse(item.isRecent(network: "new", settings: "settings", session: session, now: now))
        XCTAssertFalse(item.isRecent(network: "network", settings: "settings", session: UUID(), now: now))
        XCTAssertFalse(item.isRecent(network: "network", settings: "settings", session: session, now: now.addingTimeInterval(301)))
        XCTAssertThrowsError(try WebsiteObservation(observedAt: now.addingTimeInterval(1), observedIP: "203.0.113.43", result: .clear,
            network: "network", settings: "settings", session: session, now: now))
        let store = DetectorRecords(root: try directory())
        try store.saveWebsite(item)
        XCTAssertEqual(try store.website()?.observedAt, item.observedAt)
        XCTAssertTrue(try store.logs().isEmpty)
    }

    func testBrowserSupplementSourcesAreExactlyTwoClaudePages() {
        XCTAssertEqual(WebsiteObservation.source, "https://ipsuper.com/claude/")
        XCTAssertEqual(WebsiteObservation.netCoffeeSource, "https://ip.net.coffee/claude/")
        XCTAssertEqual(BrowserSupplementPage.allPages.map(\.url), [
            "https://ipsuper.com/claude/",
            "https://ip.net.coffee/claude/",
        ])
        XCTAssertEqual(BrowserSupplementPage.oneClickPages.map(\.url), BrowserSupplementPage.allPages.map(\.url))
    }
}
