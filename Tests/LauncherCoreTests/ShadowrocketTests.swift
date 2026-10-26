import XCTest
@testable import LauncherCore

final class ShadowrocketTests: XCTestCase {
    func testDraftIsSeparateAndMayBeIncomplete() throws {
        let empty = try ShadowrocketDraft().validated()
        XCTAssertEqual(empty.port, "")
        XCTAssertEqual(empty.expectedIP, "")
        XCTAssertNotEqual(ShadowrocketDraft.url, Paths.config)
        var partial = empty
        partial.port = " 08080 "
        XCTAssertEqual(try partial.validated().port, "8080")
        let data = try JSONEncoder().encode(partial)
        XCTAssertEqual(try JSONDecoder().decode(ShadowrocketDraft.self, from: data), partial)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["protocolName", "host", "port", "expectedIP"])
    }

    func testDraftRejectsInvalidValues() {
        for port in ["0", "65536", "-2", "１２", "8080x", "1.2", "12\u{0}3"] {
            var draft = ShadowrocketDraft(); draft.port = port
            XCTAssertThrowsError(try draft.validated(), port)
        }
        for ip in ["localhost", "1.2.3.999", "1.2.3.4\u{0}suffix", "https://1.2.3.4"] {
            var draft = ShadowrocketDraft(); draft.expectedIP = ip
            XCTAssertThrowsError(try draft.validated(), ip)
        }
        var draft = ShadowrocketDraft(); draft.host = "192.0.2.1"
        XCTAssertThrowsError(try draft.validated())
        draft.host = ""; draft.protocolName = "https"
        XCTAssertThrowsError(try draft.validated())
    }

    func testDraftCanonicalizesSupportedValues() throws {
        var draft = ShadowrocketDraft()
        draft.protocolName = " SOCKS5 "
        draft.host = " 127.0.0.1 "
        draft.port = "1080"
        draft.expectedIP = " 203.0.113.43 "
        let result = try draft.validated()
        XCTAssertEqual(result.protocolName, "socks5")
        XCTAssertEqual(result.expectedIP, "203.0.113.43")
        XCTAssertEqual(result.endpointDescription, "SOCKS5 127.0.0.1:1080 · 草稿")
    }

    func testVPNStateUsesOnlyExactStatusHeader() {
        XCTAssertEqual(ShadowrocketVPNState.parse("Disconnected\nConnectedCount : 1"), .disconnected)
        XCTAssertEqual(ShadowrocketVPNState.parse("Connected\nStatus : 0"), .connected)
        XCTAssertEqual(ShadowrocketVPNState.parse("Connecting\n"), .connecting)
        XCTAssertEqual(ShadowrocketVPNState.parse("Invalid\nConnected"), .invalid)
        XCTAssertEqual(ShadowrocketVPNState.parse("Not Connected"), .unknown)
        XCTAssertEqual(ShadowrocketVPNState.parse(""), .unknown)
    }

    func testVPNServiceMustBelongToShadowrocket() {
        let id = "01BD83E4-6334-4A8A-B2C7-0522D60B8ED9"
        let row = "* (Disconnected) \(id) VPN (com.liguangming.Shadowrocket) \"Shadowrocket\" [VPN:com.liguangming.Shadowrocket]"
        XCTAssertEqual(ShadowrocketLocal.serviceIDs(in: row), [id])
        XCTAssertEqual(ShadowrocketLocal.serviceIDs(in: row + "\n" + row), [id])
        XCTAssertTrue(ShadowrocketLocal.serviceIDs(in: "* (Connected) \(id) VPN (other.client) \"Shadowrocket\"").isEmpty)
        XCTAssertTrue(ShadowrocketLocal.serviceIDs(in: "(com.liguangming.Shadowrocket) without UUID").isEmpty)
        let misleading = "* (Connected) \(id) VPN (other.bundle) \"(com.liguangming.Shadowrocket)\" [VPN]"
        XCTAssertTrue(ShadowrocketLocal.serviceIDs(in: misleading).isEmpty)
        let other = row.replacingOccurrences(of: id, with: "11111111-2222-3333-4444-555555555555")
        XCTAssertEqual(ShadowrocketLocal.serviceIDs(in: row + "\n" + other).count, 2)
    }
}
