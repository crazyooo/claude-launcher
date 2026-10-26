import XCTest
@testable import RoutingCore

final class RouterSystemHostDiagnosticTests: XCTestCase {
    func testSocketDiagnosticsRedactErrorsAndRestrictNumericFields() {
        let secret = NSError(domain: "SECRET_DOMAIN", code: 919,
                             userInfo: [NSLocalizedDescriptionKey: "SECRET_TOKEN /private/path"])
        for step in RouterSystemHostDiagnostic.SocketStep.allCases {
            let numeric = step == .activation || step == .descriptorCount ? " value=-2" : ""
            XCTAssertEqual(RouterSystemHostDiagnostic.socketMessage(step, error: secret, value: -2),
                           "host_socket_failed step=\(step.rawValue) reason=unexpectedError" + numeric)
            XCTAssertEqual(RouterSystemHostDiagnostic.socketMessage(step, error: RouterSystemError.ownershipUnknown),
                           "host_socket_failed step=\(step.rawValue) reason=ownershipUnknown")
        }
    }

    func testSocketDiagnosticsNeverRetryOrTranslateFailure() throws {
        var calls = 0
        let secret = NSError(domain: "PRIVATE", code: 919)
        do {
            try RouterSystemHostDiagnostic.socketStep(.manifest) {
                calls += 1
                throw secret
            }
            XCTFail("Expected original error")
        } catch {
            XCTAssertTrue((error as NSError) === secret)
        }
        XCTAssertEqual(calls, 1)
        XCTAssertEqual(RouterSystemHostDiagnostic.socketStep(.code) { 42 }, 42)
        try RouterSystemHostDiagnostic.requireSocket(true, at: .nodeOwner)
        XCTAssertThrowsError(try RouterSystemHostDiagnostic.requireSocket(false, at: .nodeOwner)) {
            XCTAssertEqual($0 as? RouterSystemError, .ownershipUnknown)
        }
        XCTAssertThrowsError(try RouterSystemHostDiagnostic.socketStep(.descriptorFlags) {
            throw RouterSystemError.operationUnsettled
        }) {
            XCTAssertEqual($0 as? RouterSystemError, .operationUnsettled)
        }
    }

    func testUnknownErrorCannotExposePrivateDetailsAtAnyPhase() {
        let error = NSError(domain: "SECRET_DOMAIN", code: 123, userInfo: [
            NSLocalizedDescriptionKey: "SECRET_DESCRIPTION", NSFilePathErrorKey: "/private/SECRET_PATH",
            "password": "SECRET_CREDENTIAL"])
        for phase in RouterSystemHostDiagnostic.Phase.allCases {
            let text = RouterSystemHostDiagnostic.message(phase, error: error)
            XCTAssertEqual(text, "host_failed stage=\(phase.rawValue) reason=unexpectedError")
            XCTAssertFalse(text.contains("SECRET")); XCTAssertFalse(text.contains("/private"))
        }
    }
    func testTypedFailuresRemainDistinguishableWithoutFormattingTheirError() {
        XCTAssertEqual(RouterSystemHostDiagnostic.message(.hostLease, error: RouterSystemError.operationUnsettled),
                       "host_failed stage=host_lease reason=operationUnsettled")
        XCTAssertEqual(RouterSystemHostDiagnostic.message(.journal, error: RouterSystemError.journalUnknown),
                       "host_failed stage=journal reason=journalUnknown")
    }
}
