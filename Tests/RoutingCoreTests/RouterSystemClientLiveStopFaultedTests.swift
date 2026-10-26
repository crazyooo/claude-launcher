import XCTest
@testable import RoutingCore

final class RouterSystemClientLiveStopFaultedTests: XCTestCase {
    func testStopFaultedOrActiveInstance() throws {
        let client = RouterSystemClient()
        let status: RouterSystemStatus
        do { status = try client.request(.status(id: nil)) }
        catch RouterSystemClientError.unavailable { throw XCTSkip("unavailable") }
        print("BEFORE phase=\(status.phase) reason=\(status.reason) instance=\(String(describing: status.instance))")
        guard let id = status.instance else {
            print("NO_INSTANCE")
            return
        }
        let stopped = try client.request(.stop(id: id))
        print("STOP phase=\(stopped.phase) reason=\(stopped.reason) routingVerified=\(stopped.routingVerified)")
        let after = try client.request(.status(id: nil))
        print("AFTER phase=\(after.phase) reason=\(after.reason) instance=\(String(describing: after.instance))")
        XCTAssertFalse(stopped.routingVerified)
    }
}
