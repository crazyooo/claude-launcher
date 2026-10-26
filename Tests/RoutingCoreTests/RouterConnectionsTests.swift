import XCTest
@testable import RoutingCore

final class RouterConnectionsTests: XCTestCase {
    private let instance = UUID(), request = UUID()
    private func binding(instance: UUID? = nil, epoch: String = String(repeating: "a", count: 64)) -> RouterConnectionBinding {
        .init(mode: .userManaged, installation: nil, instance: instance ?? self.instance,
              epoch: epoch, configurationDigest: String(repeating: "b", count: 64))
    }
    private func row() -> [String: Any] {
        ["id": UUID().uuidString, "upload": 12, "download": 20, "chains": ["DIRECT"], "rule": "DomainSuffix",
         "metadata": ["network": "tcp", "type": "Tun", "process": "Example",
                      "host": "example.com", "destinationIP": "203.0.113.1", "destinationPort": "443"]]
    }
    private func body(_ rows: Any = NSNull(), up: Any = 12, down: Any = 20) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["connections": rows, "uploadTotal": up, "downloadTotal": down])
    }
    private func sample(up: Int64, down: Int64 = 0, at: Double, binding: RouterConnectionBinding? = nil) -> RouterConnectionSnapshot {
        .init(version: 1, request: request, binding: binding ?? self.binding(),
              startedAt: Date(timeIntervalSince1970: at - 0.1), completedAt: Date(timeIntervalSince1970: at),
              startedUptime: at - 0.1, completedUptime: at, uploadTotal: up, downloadTotal: down,
              totalConnections: 0, rows: [])
    }
    func testPinnedEmptyNullAndEmptyArray() throws {
        for bytes in [try body(), try body([])] {
            let result = try RouterConnectionProjection.parse(bytes, redactions: [])
            XCTAssertEqual(result.count, 0); XCTAssertTrue(result.rows.isEmpty)
            XCTAssertEqual(result.upload, 12) // Totals do not equal the sum of live rows.
        }
        XCTAssertThrowsError(try RouterConnectionProjection.parse(Data("{\"uploadTotal\":0,\"downloadTotal\":0}".utf8), redactions: []))
    }
    func testCountersRetainInt64PrecisionAndRejectInvalidNumbers() throws {
        let raw = Data("{\"connections\":null,\"uploadTotal\":9223372036854775807,\"downloadTotal\":9007199254740993}".utf8)
        let value = try RouterConnectionProjection.parse(raw, redactions: [])
        XCTAssertEqual(value.upload, Int64.max); XCTAssertEqual(value.download, 9_007_199_254_740_993)
        for counter in ["true", "-1", "1.5", "9223372036854775808", "null", "\"12\""] {
            let raw = Data("{\"connections\":null,\"uploadTotal\":\(counter),\"downloadTotal\":0}".utf8)
            XCTAssertThrowsError(try RouterConnectionProjection.parse(raw, redactions: []))
        }
    }
    func testProjectionOmitsPrivateFieldsAndRejectsURLs() throws {
        var value = row(), metadata = value["metadata"] as! [String: Any]
        metadata["processPath"] = "/Users/private/SECRET_PATH"; metadata["inboundUser"] = "SECRET_USERNAME"
        metadata["remoteDestination"] = "https://user:SECRET_PASSWORD@example.com/token"
        metadata["host"] = "https://user:SECRET_PASSWORD@example.com/path?secret=1"
        metadata["process"] = "/private/SECRET_PATH"; value["metadata"] = metadata
        value["rulePayload"] = "SECRET_RULE"; value["providerChains"] = ["SECRET_PROVIDER"]
        value["chains"] = ["https://user:SECRET_PASSWORD@example.com", "DIRECT"]
        let projected = try RouterConnectionProjection.parse(body([value]), redactions: [])
        XCTAssertNil(projected.rows[0].host); XCTAssertNil(projected.rows[0].process)
        XCTAssertEqual(projected.rows[0].chain, ["UNKNOWN", "DIRECT"])
        let text = String(decoding: try JSONEncoder().encode(projected.rows), as: UTF8.self)
        for forbidden in ["SECRET", "processPath", "inboundUser", "remoteDestination", "rulePayload", "providerChains"] {
            XCTAssertFalse(text.contains(forbidden))
        }
    }
    func testKnownSecretAndProcessAttribution() throws {
        for label in ["Google Chrome Helper (Renderer)", "浏览器助手"] {
            var value = row(), metadata = value["metadata"] as! [String: Any]
            metadata["process"] = label; metadata["type"] = "HTTPS"; value["metadata"] = metadata
            let result = try RouterConnectionProjection.parse(body([value]), redactions: [])
            XCTAssertEqual(result.rows[0].process, label); XCTAssertEqual(result.rows[0].origin, "HTTPS")
        }
        var value = row(), metadata = value["metadata"] as! [String: Any]
        metadata["host"] = "secret.example.com"; metadata["process"] = "secret"
        value["metadata"] = metadata
        let result = try RouterConnectionProjection.parse(body([value]), redactions: ["secret"])
        XCTAssertNil(result.rows[0].process); XCTAssertNil(result.rows[0].host)
        for invalid in ["x\ny", "x/y", "x\\y", "x\u{202e}y"] {
            metadata["process"] = invalid; value["metadata"] = metadata
            XCTAssertNil(try RouterConnectionProjection.parse(body([value]), redactions: []).rows[0].process)
        }
    }
    func testNullChainsAndEmptyMetadataAreDifferentFromBrokenMetadata() throws {
        var value = row(), metadata = value["metadata"] as! [String: Any]
        for key in ["process", "host", "destinationIP", "destinationPort"] { metadata[key] = "" }
        value["metadata"] = metadata; value["chains"] = NSNull()
        let result = try RouterConnectionProjection.parse(body([value]), redactions: [])
        XCTAssertNil(result.rows[0].process); XCTAssertNil(result.rows[0].destinationPort); XCTAssertTrue(result.rows[0].chain.isEmpty)
        metadata["process"] = NSNull(); value["metadata"] = metadata
        XCTAssertThrowsError(try RouterConnectionProjection.parse(body([value]), redactions: []))
    }
    func testDuplicateIdentityKeysAndNegativeCountersFail() throws {
        let duplicated = Data("{\"connections\":null,\"uploadTotal\":0,\"uploadTotal\":1,\"downloadTotal\":0}".utf8)
        XCTAssertThrowsError(try RouterConnectionProjection.parse(duplicated, redactions: []))
        var value = row()
        XCTAssertThrowsError(try RouterConnectionProjection.parse(body([value, value]), redactions: []))
        value["download"] = -1
        XCTAssertThrowsError(try RouterConnectionProjection.parse(body([value]), redactions: []))
    }
    func testLimitsReportOmittedRowsWithoutDiscardingTotals() throws {
        let result = try RouterConnectionProjection.parse(body((0..<101).map { _ in row() }, up: 888), redactions: [])
        XCTAssertEqual(result.count, 101); XCTAssertEqual(result.rows.count, 100); XCTAssertEqual(result.upload, 888)
        for bytes in [try body((0..<513).map { _ in row() }), Data(repeating: 32, count: 524_289)] {
            XCTAssertThrowsError(try RouterConnectionProjection.parse(bytes, redactions: [])) {
                XCTAssertEqual($0 as? RouterConnectionFailure, .responseTooLarge)
            }
        }
    }
    func testWireRoundTripAndStrictFieldProjection() throws {
        let original = sample(up: Int64.max, down: 9_007_199_254_740_993, at: 10)
        let encoded = try JSONEncoder().encode(original), decoded = try RouterConnectionSnapshot.decode(encoded)
        XCTAssertEqual(decoded.uploadTotal, original.uploadTotal); XCTAssertEqual(decoded.downloadTotal, original.downloadTotal)
        var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        object["token"] = "private"
        XCTAssertThrowsError(try RouterConnectionSnapshot.decode(JSONSerialization.data(withJSONObject: object)))
        XCTAssertFalse(decoded.routingVerified); XCTAssertFalse(decoded.protectionVerified); XCTAssertFalse(decoded.launchAuthorized)
    }
    func testRateResetsForRestartCounterResetOverlapAndLongGap() {
        let old = sample(up: 100, down: 200, at: 10)
        XCTAssertEqual(RouterConnectionRate.between(old, sample(up: 300, down: 600, at: 12))?.uploadBytesPerSecond, 100)
        for next in [sample(up: 99, down: 600, at: 12), sample(up: 300, down: 199, at: 12),
                     sample(up: 300, down: 600, at: 10), sample(up: 300, down: 600, at: 40),
                     sample(up: 300, down: 600, at: 12, binding: binding(instance: UUID())),
                     sample(up: 300, down: 600, at: 12, binding: binding(epoch: String(repeating: "c", count: 64)))] {
            XCTAssertNil(RouterConnectionRate.between(old, next))
        }
        XCTAssertNil(RouterConnectionRate.between(sample(up: Int64.min, at: 10), sample(up: Int64.max, at: 12)))
    }
    func testCollectorRejectsChangedIdentityAndExpiredSampling() throws {
        let before = binding(), after = binding(instance: UUID())
        var observations = 0
        XCTAssertThrowsError(try RouterConnectionCollector.read(request: request, expectedInstance: instance, mode: .userManaged,
            observe: { observations += 1; return observations == 1 ? before : after },
            readBody: { _ in (try self.body(), []) }, clock: { (Date(timeIntervalSince1970: 10), 10) })) {
                XCTAssertEqual($0 as? RouterConnectionFailure, .identityChanged)
        }
        var clockCalls = 0
        XCTAssertThrowsError(try RouterConnectionCollector.read(request: request, expectedInstance: instance, mode: .userManaged,
            observe: { before }, readBody: { _ in (try self.body(), []) }, clock: {
                clockCalls += 1; let time = clockCalls == 1 ? 10.0 : 16.0
                return (Date(timeIntervalSince1970: time), time)
            })) { XCTAssertEqual($0 as? RouterConnectionFailure, .stale) }
    }
    func testCollectorFitsWireBudgetAndPreservesExactSourceCount() throws {
        let source = try body((0..<100).map { _ -> [String: Any] in
            var value = row(), metadata = value["metadata"] as! [String: Any]
            metadata["host"] = Array(repeating: String(repeating: "a", count: 50), count: 4).joined(separator: ".")
            metadata["process"] = String(repeating: "p", count: 80); value["metadata"] = metadata
            value["chains"] = (0..<4).map { _ in "route_" + UUID().uuidString.lowercased() }
            return value
        })
        let snapshot = try RouterConnectionCollector.read(request: request, expectedInstance: instance, mode: .userManaged,
            observe: { self.binding() }, readBody: { _ in (source, []) }, clock: { (Date(timeIntervalSince1970: 10), 10) })
        XCTAssertLessThanOrEqual(try JSONEncoder().encode(snapshot).count, RouterConnectionSnapshot.wireLimit)
        XCTAssertEqual(snapshot.totalConnections, 100); XCTAssertGreaterThan(snapshot.omittedConnections, 0)
        XCTAssertEqual(snapshot.omittedConnections + snapshot.rows.count, 100)
    }
    func testSnapshotBindsRequestModeInstanceAndClock() throws {
        let value = sample(up: 100, at: 10)
        XCTAssertNoThrow(try value.validate(request: request, instance: instance, mode: .userManaged, now: Date(timeIntervalSince1970: 11), uptime: 11))
        for (req, id, mode, time) in [(UUID(), instance, RouterConnectionMode.userManaged, 11.0),
                                     (request, UUID(), .userManaged, 11), (request, instance, .system, 11),
                                     (request, instance, .userManaged, 30)] {
            XCTAssertThrowsError(try value.validate(request: req, instance: id, mode: mode, now: Date(timeIntervalSince1970: time), uptime: time))
        }
    }
}
