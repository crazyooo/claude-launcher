import XCTest
@testable import RoutingCore

final class RouterTCPEchoWireTests: XCTestCase {
    private let nonce = UUID(uuidString: "12345678-1234-4123-a123-123456789abc")!
    private func body(_ frame: Data) throws -> Data {
        XCTAssertEqual(try RouterTCPEchoWire.bodyLength(frame.prefix(4)), frame.count - 4)
        return frame.dropFirst(4)
    }
    func testRequestAndNumericIPv4IPv6RepliesRoundTrip() throws {
        XCTAssertEqual(try RouterTCPEchoWire.parseRequest(body(RouterTCPEchoWire.request(nonce))), nonce)
        for ip in ["127.0.0.1", "::1", "2001:db8::2"] {
            let reply = try RouterTCPEchoWire.parseResponse(
                body(RouterTCPEchoWire.response(nonce, actualPeerIP: ip)), expected: nonce)
            XCTAssertEqual(reply.nonce, nonce)
            XCTAssertEqual(reply.serverReportedPeerIP, ip)
        }
    }
    func testFrameLengthIsStrictlyBounded() throws {
        for count in [0, 513, 4096] { XCTAssertThrowsError(try RouterTCPEchoWire.framed(Data(repeating: 0, count: count))) }
        for prefix: Data in [Data(), Data([1]), Data([0, 0, 0, 1, 0]), Data([0, 0, 0, 0]),
                             Data([0, 0, 2, 1]), Data([255, 255, 255, 255])] {
            XCTAssertThrowsError(try RouterTCPEchoWire.bodyLength(prefix))
        }
        XCTAssertEqual(try RouterTCPEchoWire.bodyLength(Data([0, 0, 2, 0])), 512)
    }
    func testStrictKeysTypesNonceAndAddress() throws {
        let n = nonce.uuidString.lowercased()
        let valid = #"{"version":1,"nonce":"\#(n)","peerIP":"127.0.0.1"}"#
        let bad = [
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"version\":1"),
            valid.replacingOccurrences(of: "\"version\":1", with: #""version":1,"ver\u0073ion":1"#),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1,\"extra\":0"),
            valid.replacingOccurrences(of: "\"version\":1,", with: ""),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":null"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":true"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":\"1\""),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.1"),
            valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":2"),
            valid.replacingOccurrences(of: n, with: n.uppercased()),
            valid.replacingOccurrences(of: "\"\(n)\"", with: "null"),
            valid.replacingOccurrences(of: n, with: "not-a-uuid"),
            valid.replacingOccurrences(of: "127.0.0.1", with: "hostname.test"),
            valid.replacingOccurrences(of: "127.0.0.1", with: "fe80::1%en0"),
            valid.replacingOccurrences(of: "127.0.0.1", with: #"127.0.0.1\u0000"#),
            valid + " garbage", "[]", String(repeating: " ", count: 513) + valid
        ]
        for text in bad {
            XCTAssertThrowsError(try RouterTCPEchoWire.parseResponse(Data(text.utf8), expected: nonce), text) {
                XCTAssertEqual($0 as? RouterTCPEchoError, .malformed)
            }
        }
        XCTAssertThrowsError(try RouterTCPEchoWire.parseResponse(Data([0xff, 0xfe]), expected: nonce))
        XCTAssertThrowsError(try RouterTCPEchoWire.parseResponse(Data(valid.utf8), expected: UUID())) {
            XCTAssertEqual($0 as? RouterTCPEchoError, .wrongNonce)
        }
        // Protocol intentionally allows JSON's numeric 1.0 as integer value 1.
        XCTAssertNoThrow(try RouterTCPEchoWire.parseResponse(
            Data(valid.replacingOccurrences(of: "\"version\":1", with: "\"version\":1.0").utf8), expected: nonce))
        for text in [#"{"version":true,"nonce":"\#(n)"}"#,
                     #"{"version":1,"nonce":"\#(n)","nonce":"\#(n)"}"#,
                     #"{"version":1,"nonce":"\#(n)","peerIP":"127.0.0.1"}"#,
                     #"{"nonce":"\#(n)"}"#] {
            XCTAssertThrowsError(try RouterTCPEchoWire.parseRequest(Data(text.utf8)))
        }
    }
}
