import XCTest
@testable import RoutingCore

final class RouterSystemControllerDeclarationTests: XCTestCase {
    private typealias Declaration = RouterSystemControllerDeclaration
    // Constructed from pinned source schema; not a captured controller response.
    private var fixture: [String: Any] {
        ["port": 0, "socks-port": 0, "mixed-port": 0, "redir-port": 0, "tproxy-port": 0,
         "routing-mark": 0, "mode": "rule", "find-process-mode": "strict", "allow-lan": false,
         "bind-address": "127.0.0.1", "interface-name": "", "ipv6": true,
         "tun": ["enable": true, "device": "utun5", "stack": "Mixed", "auto-route": true,
                 "auto-detect-interface": true, "file-descriptor": 0,
                 "dns-hijack": ["any:53", "tcp://any:53"], "inet4-address": ["198.18.0.1/30"],
                 "inet6-address": [RouterSystemCompiler.tunIPv6], "gso-max-size": 65536,
                 "recvmsgx": true, "processors-per-channel": 1]]
    }
    private func parse(_ changes: [String: Any] = [:], general: Bool = false, omit: [String] = []) throws -> Declaration {
        var object = fixture
        if general {
            changes.forEach { object[$0.key] = $0.value }; omit.forEach { object[$0] = nil }
        } else {
            var tun = object["tun"] as! [String: Any]
            changes.forEach { tun[$0.key] = $0.value }; omit.forEach { tun[$0] = nil }
            object["tun"] = tun
        }
        return try Declaration.parse(JSONSerialization.data(withJSONObject: object))
    }
    func testPinnedEffectiveDefaultsAndIPv6DowngradeAreSeparate() throws {
        let dual = try parse()
        XCTAssertEqual(dual.device, "utun5"); XCTAssertEqual(dual.effectiveMTU, 9000)
        XCTAssertTrue(dual.generalIPv6Enabled); XCTAssertTrue(dual.tunIPv6Configured)
        XCTAssertEqual(dual.addresses, ["198.18.0.1/30", RouterSystemCompiler.tunIPv6])
        let ipv4 = try parse(omit: ["inet6-address"])
        XCTAssertTrue(ipv4.generalIPv6Enabled); XCTAssertFalse(ipv4.tunIPv6Configured)
        XCTAssertEqual(ipv4, try parse(["inet6-address": [String]()]))
        XCTAssertEqual(dual, try parse(["mtu": 0]))
        XCTAssertEqual(dual, try parse(["mtu": 9000]))
        XCTAssertThrowsError(try parse(["mtu": 1500]))
        XCTAssertThrowsError(try parse(["inet6-address": NSNull()]))
    }
    func testInactiveFallbackAndMalformedDevices() throws {
        XCTAssertNil(try parse(["device": ""]).device)
        XCTAssertNil(try parse(["enable": false]).device)
        XCTAssertEqual(try parse(["device": "utun0"]).device, "utun0")
        for device in ["utun05", "utun-1", "utun32768", "en0", "utun+1", "utun1\0"] {
            XCTAssertThrowsError(try parse(["device": device]))
        }
    }
    func testGeneralIPv6FalseIsNotTheSystemTunDowngrade() throws {
        var object = fixture, tun = fixture["tun"] as! [String: Any]
        object["ipv6"] = false; tun["inet6-address"] = [String](); object["tun"] = tun
        XCTAssertThrowsError(try Declaration.parse(JSONSerialization.data(withJSONObject: object)))
        tun["inet6-address"] = nil; object["tun"] = tun
        XCTAssertThrowsError(try Declaration.parse(JSONSerialization.data(withJSONObject: object)))
    }
    func testTypesNullAndMissingRequiredFieldsCannotBecomeDefaults() {
        for key in ["enable", "auto-route", "auto-detect-interface"] {
            XCTAssertThrowsError(try parse(omit: [key]))
            for value: Any in [1, "true", NSNull()] { XCTAssertThrowsError(try parse([key: value])) }
        }
        for value: Any in [NSNull(), 0, "false"] { XCTAssertThrowsError(try parse(["auto-redirect": value])) }
        for value: Any in [true, -1, 0.5, 4294967296 as UInt64, NSNull()] {
            XCTAssertThrowsError(try parse(["file-descriptor": value]))
            XCTAssertThrowsError(try parse(["port": value], general: true))
        }
        XCTAssertThrowsError(try parse(["stack": "mixed"]))
        XCTAssertThrowsError(try parse(["ipv6": false], general: true))
    }
    func testRouteScopeAddressesAndDNSCannotBeSilentlyChanged() throws {
        XCTAssertEqual(try parse(), try parse(["dns-hijack": ["tcp://any:53", "any:53"]]))
        for value in [["any:53"], ["any:53", "any:53"], ["any:53", "tcp://any:53", "udp://any:53"]] {
            XCTAssertThrowsError(try parse(["dns-hijack": value]))
        }
        XCTAssertThrowsError(try parse(["inet4-address": [RouterSystemCompiler.fakeIPv4]]))
        XCTAssertThrowsError(try parse(["inet6-address": ["2001:db8::1/126"]]))
        XCTAssertThrowsError(try parse(["route-exclude-address": ["0.0.0.0/0"]]))
        XCTAssertThrowsError(try parse(["include-uid": [501]]))
        XCTAssertThrowsError(try parse(["include-uid": NSNull()]))
        XCTAssertEqual(try parse(), try parse(["include-uid": [Int]()]))
    }
    func testVersionAndDuplicateKeysRemainStrict() throws {
        XCTAssertNoThrow(try Declaration.version(Data(#"{"meta":true,"version":"v1.19.32"}"#.utf8)))
        for text in [#"{"meta":1,"version":"v1.19.32"}"#, #"{"meta":true,"version":"v1.19.31"}"#,
                     #"{"meta":true,"version":"v1.19.32","\u0076ersion":"v1.19.32"}"#] {
            XCTAssertThrowsError(try Declaration.version(Data(text.utf8)))
        }
        var text = String(decoding: try JSONSerialization.data(withJSONObject: fixture), as: UTF8.self)
        text.removeLast(); text += #", "port": 0}"#
        XCTAssertThrowsError(try Declaration.parse(Data(text.utf8)))
    }
}
