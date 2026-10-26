import XCTest
@testable import RoutingCore

final class RouterSystemClientLiveConnectionsTests: XCTestCase {
    func testLiveConnectionsSnapshotAgainstActiveInstance() throws {
        let client = RouterSystemClient()
        let status: RouterSystemStatus
        do {
            status = try client.request(.status(id: nil))
        } catch RouterSystemClientError.unavailable {
            throw XCTSkip("system component unavailable")
        }
        guard status.phase == "active", let instance = status.instance else {
            throw XCTSkip("no active instance")
        }
        do {
            let snap = try client.connections(request: UUID(), instance: instance)
            print("CONN total=\(snap.totalConnections) rows=\(snap.rows.count) omitted=\(snap.omittedConnections) routingVerified=\(snap.routingVerified)")
            XCTAssertFalse(snap.routingVerified)
            XCTAssertEqual(snap.binding.instance, instance)
        } catch {
            print("CONN_ERROR \(error)")
            // Older installed helpers may not speak the current connections wire — record, don't fake success.
            throw XCTSkip("connections protocol unavailable on installed helper: \(error)")
        }
    }
}
