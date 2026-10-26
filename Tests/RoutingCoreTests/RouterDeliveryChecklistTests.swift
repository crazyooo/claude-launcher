import XCTest
@testable import RoutingCore

final class RouterDeliveryChecklistTests: XCTestCase {
    func testChecklistKeepsGapsAndNeverClaimsComplete() {
        let report = RouterDeliveryChecklist.report()
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canClaimProductComplete)
        XCTAssertTrue(report.items.contains(where: { $0.code == "live_tun_apply" && $0.status == .partial }))
        XCTAssertTrue(report.items.contains(where: { $0.code == "pf_arming" && $0.status == .partial }))
        XCTAssertTrue(report.items.contains(where: {
            $0.code == "app_traffic_attestation" && $0.status == .partial
                && $0.evidence.contains(RouterAppTrafficMatrixAttestation.clearWindowID)
        }))
        XCTAssertTrue(report.items.contains(where: { $0.code == "live_matrix_fill" && $0.status == .gap }))
        XCTAssertTrue(report.items.contains(where: { $0.code == "final_delivery" && $0.status == .gap }))
        XCTAssertTrue(report.items.contains(where: { $0.code == "path_portrait" && $0.status == .done }))
        XCTAssertTrue(report.items.contains(where: { $0.code == "routing_event_log" && $0.status == .partial }))
        XCTAssertTrue(report.items.contains(where: {
            $0.code == "rollback_preview" && $0.status == .partial
                && $0.evidence.contains(RouterAcceptedRollbackRestore.clearWindowID)
                && $0.evidence.contains("tunEffectsWired=false")
        }))
        XCTAssertTrue(report.summary.contains("complete=false") || report.summary.contains("仍为 gap"))
    }

    func testChecklistReflectsLiveMatrixRunnerWithoutCompletingProduct() throws {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .block)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let live = try RouterTrafficMatrixLiveRunner.run(
            plan: plan, profile: profile,
            context: .init(systemPhase: "prepared", systemInstance: nil, refuseOwnTun: true))
        let report = RouterDeliveryChecklist.report(plan: plan, profile: profile, liveMatrix: live)
        XCTAssertFalse(report.canClaimProductComplete)
        XCTAssertTrue(report.items.contains(where: {
            $0.code == "live_matrix_fill" && $0.status == .partial
        }))
        XCTAssertTrue(report.items.contains(where: {
            $0.code == "pf_arming" && $0.status == .partial
                && ($0.evidence.contains("armed=false") || $0.evidence.contains("诚实拒绝"))
        }))
    }
}
