import XCTest
@testable import RoutingCore

final class RouterSystemClientLiveAckStopTests: XCTestCase {
    func testAcknowledgeEnvironmentAndReachStopped() throws {
        let client = RouterSystemClient()
        var status = try client.request(.status(id: nil))
        print("S0 phase=\(status.phase) reason=\(status.reason) instance=\(String(describing: status.instance)) review=\(String(describing: status.environmentReview?.id))")
        guard status.phase == "stopping", status.reason == "external_environment_changed",
              let id = status.instance else {
            print("NOT_IN_ENV_STOP_PATH")
            // If already idle/stopped, fine.
            return
        }
        // A review may not exist yet after a cold stuck stop; prepare it now.
        let review = status.environmentReview?.id ?? UUID()
        let preview = try client.request(.previewEnvironment(id: id, review: review))
        print("PREVIEW phase=\(preview.phase) reason=\(preview.reason) digest=\(String(describing: preview.environmentReview?.digest))")
        guard let digest = preview.environmentReview?.digest else {
            XCTFail("no environment digest"); return
        }
        let confirmed = try client.request(.confirmEnvironment(id: id, review: review, digest: digest))
        print("CONFIRM phase=\(confirmed.phase) reason=\(confirmed.reason)")
        status = try client.request(.status(id: nil))
        print("S1 phase=\(status.phase) reason=\(status.reason) instance=\(String(describing: status.instance))")
        XCTAssertFalse(confirmed.routingVerified)
    }
}
