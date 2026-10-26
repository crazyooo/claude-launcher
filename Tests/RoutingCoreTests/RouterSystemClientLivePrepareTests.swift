import XCTest
@testable import RoutingCore

/// Live prepare against the installed system host. Does not claim accepted/routing_verified.
final class RouterSystemClientLivePrepareTests: XCTestCase {
    func testLivePrepareMinimalDirectPlan() throws {
        let client = RouterSystemClient()
        let status: RouterSystemStatus
        do {
            status = try client.request(.status(id: nil))
        } catch RouterSystemClientError.unavailable {
            throw XCTSkip("system component unavailable")
        }
        print("PRE_STATUS phase=\(status.phase) reason=\(status.reason)")
        guard ["idle", "prepared", "stopped"].contains(status.phase) else {
            throw XCTSkip("host phase \(status.phase) not ready for prepare")
        }
        if status.phase == "prepared", let id = status.instance {
            // Stop leftover prepared preview before a fresh prepare.
            _ = try? client.request(.stop(id: id))
        }

        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let id = UUID()
        let prepared = try client.request(.prepare(id: id, plan: plan, profile: profile))
        print("PREPARE phase=\(prepared.phase) reason=\(prepared.reason) instance=\(String(describing: prepared.instance)) digest=\(String(describing: prepared.planDigest?.prefix(16))) expires=\(String(describing: prepared.previewExpiresAt))")
        XCTAssertEqual(prepared.instance, id)
        XCTAssertEqual(prepared.phase, "prepared")
        XCTAssertFalse(prepared.routingVerified)
        XCTAssertNotNil(prepared.planDigest)
        XCTAssertNotNil(prepared.previewExpiresAt)

        // Tear down prepare so we leave host idle unless a later package applies.
        let stopped = try client.request(.stop(id: id))
        print("STOP_AFTER_PREPARE phase=\(stopped.phase) reason=\(stopped.reason)")
        XCTAssertFalse(stopped.routingVerified)
    }
}
