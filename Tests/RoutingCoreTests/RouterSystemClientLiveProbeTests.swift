import XCTest
@testable import RoutingCore

final class RouterSystemClientLiveProbeTests: XCTestCase {
    func testLiveStatusIfInstalled() throws {
        let client = RouterSystemClient()
        do {
            let status = try client.request(.status(id: nil))
            print("LIVE_STATUS phase=\(status.phase) reason=\(status.reason) instance=\(String(describing: status.instance)) routingVerified=\(status.routingVerified)")
            XCTAssertFalse(status.routingVerified)
        } catch RouterSystemClientError.unavailable {
            throw XCTSkip("system component unavailable")
        } catch {
            print("LIVE_STATUS_ERROR \(error)")
            throw error
        }
    }
}
