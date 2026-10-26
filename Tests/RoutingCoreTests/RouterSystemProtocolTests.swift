import XCTest
@testable import RoutingCore

final class RouterSystemProtocolTests: XCTestCase {
    private let id = UUID()
    private func decode(_ text: String) throws -> RouterSystemRequest { try RouterSystemDecoder.decode(Data(text.utf8)) }
    func testStrictStatusAndStop() throws {
        guard case .status(nil) = try decode(#"{"version":1,"action":"status"}"#) else { return XCTFail() }
        guard case .stop(let actual) = try decode("{\"version\":1,\"action\":\"stop\",\"id\":\"\(id)\"}") else { return XCTFail() }
        XCTAssertEqual(actual, id)
    }
    func testDuplicateEscapedAndNestedKeysAreRejected() {
        for text in [#"{"version":1,"version":1,"action":"status"}"#,
                     #"{"version":1,"\u0076ersion":1,"action":"status"}"#,
                     #"{"version":1,"action":"status","extra":{"key":1,"key":2}}"#] {
            XCTAssertThrowsError(try decode(text))
        }
    }
    func testWrongVersionTypesActionsUnknownFieldsAndTrailingInputRejected() {
        for text in [#"{"version":true,"action":"status"}"#, #"{"version":"1","action":"status"}"#,
                     #"{"version":2,"action":"status"}"#, #"{"version":1,"action":"exec","path":"/bin/sh"}"#,
                     #"{"version":1,"action":"status","controllerURL":"http://bad"}"#,
                     #"{"version":1,"action":"status"} {}"#, #"{"version":1,"action":"status","id":null}"#] {
            XCTAssertThrowsError(try decode(text))
        }
    }
    func testBoundedInputAndRecursion() throws {
        XCTAssertThrowsError(try RouterSystemDecoder.decode(Data(repeating: 32, count: RouterInput.maximumBytes + 1)))
        func nested(_ count: Int) -> Data {
            Data(("{\"x\":" + String(repeating: "[", count: count) + "0" + String(repeating: "]", count: count) + "}").utf8)
        }
        func many(_ count: Int) -> Data {
            Data(("{\"x\":[" + Array(repeating: "0", count: count).joined(separator: ",") + "]}").utf8)
        }
        XCTAssertNoThrow(try RouterStrictJSON.object(nested(19)))
        XCTAssertThrowsError(try RouterStrictJSON.object(nested(20)))
        XCTAssertNoThrow(try RouterStrictJSON.object(many(19_998)))
        XCTAssertThrowsError(try RouterStrictJSON.object(many(19_999)))
    }
    func testPrepareAcceptsOnlyTypedPlanAndResolver() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(plan))
        var request: [String: Any] = ["version": 1, "action": "prepare", "id": id.uuidString, "plan": encoded, "profile": ["resolver": "quad9"]]
        guard case .prepare(_, _, let profile) = try RouterSystemDecoder.decode(JSONSerialization.data(withJSONObject: request)) else { return XCTFail() }
        XCTAssertEqual(profile.resolver, .quad9)
        for invalid: [String: Any] in [["resolver": "custom"], ["resolver": "quad9", "tun": true], [:]] {
            request["profile"] = invalid
            XCTAssertThrowsError(try RouterSystemDecoder.decode(JSONSerialization.data(withJSONObject: request)))
        }
        request["profile"] = ["resolver": "quad9"]
        var bad = encoded as! [String: Any]; bad["rawYAML"] = "private"; request["plan"] = bad
        XCTAssertThrowsError(try RouterSystemDecoder.decode(JSONSerialization.data(withJSONObject: request)))
    }
    func testDuplicateCredentialReferencesAndExtraFieldsRejectedWithoutValuesInErrors() throws {
        let credential: [String: Any] = ["reference": id.uuidString, "username": "private-user", "password": "private-pass"]
        let cases: [[ [String: Any] ]] = [[credential, credential], [credential.merging(["path": "/private"]) { _, b in b }]]
        for items in cases {
            let data = try JSONSerialization.data(withJSONObject: ["version": 1, "action": "apply", "id": id.uuidString, "credentials": items])
            XCTAssertThrowsError(try RouterSystemDecoder.decode(data)) { error in
                XCTAssertFalse(String(describing: error).contains("private"))
            }
        }
    }
}
