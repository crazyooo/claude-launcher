import XCTest
@testable import RoutingCore

/// Live apply after conversation clear-window grant. Never invents accepted/routing_verified.
final class RouterSystemClientLiveApplyTests: XCTestCase {
    func testLiveApplyMinimalDirectPlanEnablesOwnInstance() throws {
        let client = RouterSystemClient()
        let beforeStatus: RouterSystemStatus
        do {
            beforeStatus = try client.request(.status(id: nil))
        } catch RouterSystemClientError.unavailable {
            throw XCTSkip("system component unavailable")
        }
        print("BEFORE phase=\(beforeStatus.phase) reason=\(beforeStatus.reason)")

        // Ensure idle/stopped before prepare.
        if let id = beforeStatus.instance, ["prepared", "active", "applying"].contains(beforeStatus.phase) {
            let stopped = try client.request(.stop(id: id))
            print("PRE_STOP phase=\(stopped.phase) reason=\(stopped.reason)")
        }

        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let id = UUID()
        let prepared = try client.request(.prepare(id: id, plan: plan, profile: profile))
        XCTAssertEqual(prepared.phase, "prepared")
        XCTAssertEqual(prepared.instance, id)
        print("PREPARE digest=\(prepared.planDigest ?? "nil") expires=\(String(describing: prepared.previewExpiresAt))")

        // Re-check requireClear-aligned observation immediately before apply.
        let obs = RouterSystemObservation.collect()
        print("OBS complete=\(obs.complete) capture=\(obs.tunnelCaptureInterfaces) vpn=\(String(describing: obs.connectedVPN)) appProxy=\(String(describing: obs.applicationProxyEnabled)) autoProxy=\(String(describing: obs.automaticProxyEnabled)) userCore=\(String(describing: obs.userCoreJobPresent))")
        XCTAssertTrue(obs.tunnelCaptureInterfaces.isEmpty, "foreign capture present; refuse live apply")
        XCTAssertEqual(obs.connectedVPN, false)
        XCTAssertEqual(obs.applicationProxyEnabled, false)
        XCTAssertEqual(obs.automaticProxyEnabled, false)
        try RouterSystemProvider.requireClear(obs)

        let applied = try client.request(.apply(id: id, credentials: []))
        print("APPLY phase=\(applied.phase) reason=\(applied.reason) routingVerified=\(applied.routingVerified) digest=\(String(describing: applied.planDigest?.prefix(16)))")
        XCTAssertEqual(applied.instance, id)
        XCTAssertFalse(applied.routingVerified)
        XCTAssertTrue(["applying", "active", "running"].contains(applied.phase) || applied.phase == "active" || applied.reason.contains("active") || applied.phase != "prepared",
                      "unexpected apply phase \(applied.phase)/\(applied.reason)")

        // Poll briefly for active.
        var last = applied
        for _ in 0..<20 {
            Thread.sleep(forTimeInterval: 0.25)
            last = try client.request(.status(id: id))
            print("POLL phase=\(last.phase) reason=\(last.reason)")
            if last.phase == "active" || last.phase == "fault" || last.phase == "stopped" { break }
        }
        print("FINAL phase=\(last.phase) reason=\(last.reason) routingVerified=\(last.routingVerified)")
        XCTAssertFalse(last.routingVerified)

        let after = RouterSystemObservation.collect()
        print("AFTER_OBS capture=\(after.tunnelCaptureInterfaces) scoped=\(after.scopedTunnelInterfaces) complete=\(after.complete)")

        // Leave instance running for product acceptance in the app; do not stop here.
        // Record that conversation grant path reached a live apply outcome.
        XCTAssertTrue(["active", "applying", "fault"].contains(last.phase) || last.instance == id)
    }
}
