import XCTest
@testable import RoutingCore

final class RouterTrafficMatrixTests: XCTestCase {
    func testMatrixCoversTCPUDPDNSv4v6AndProductGaps() throws {
        let proxy = UUID()
        let plan = RouterPlan(
            proxies: [.init(id: proxy, name: "mei", kind: .socks5, host: "127.0.0.1", port: 1080)],
            rules: [
                .init(id: UUID(),
                      selector: .init(domain: .init(kind: .suffix, value: "claude.ai")),
                      destination: .proxy(proxy))
            ],
            defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let report = try RouterTrafficMatrix.report(plan: plan, profile: profile)

        XCTAssertEqual(report.policyVersion, RouterTrafficMatrix.policyVersion)
        XCTAssertEqual(report.livePassedCount, 0)
        XCTAssertFalse(report.canClaimMatrixComplete)
        XCTAssertGreaterThan(report.applicationCaseCount, 0)
        XCTAssertGreaterThan(report.controlPlaneCaseCount, 0)

        let app = report.cells.filter { $0.kind == .applicationTraffic }
        XCTAssertTrue(app.contains(where: { $0.transport == "tcp" && $0.family == "ipv4" }))
        XCTAssertTrue(app.contains(where: { $0.transport == "tcp" && $0.family == "ipv6" }))
        XCTAssertTrue(app.contains(where: { $0.transport == "udp" && $0.family == "ipv4" }))
        XCTAssertTrue(app.contains(where: { $0.transport == "udp" && $0.family == "ipv6" }))
        XCTAssertTrue(app.contains(where: { $0.label.contains("dnsA") }))
        XCTAssertTrue(app.contains(where: { $0.label.contains("dnsAAAA") }))
        XCTAssertTrue(app.allSatisfy { $0.status == .notRun })

        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .existingConnectionMigration && $0.status == .liveUntested
        }))
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .coreExitFailClosed && $0.status == .capabilityGap
                && $0.gaps.contains("reject_rules_are_not_proof")
        }))
        XCTAssertTrue(report.cells.contains(where: {
            $0.kind == .foreignTunnelCoexistence && $0.status == .liveUntested
        }))
        XCTAssertTrue(report.summary.contains("尚未 live 验收") || report.summary.contains("能力缺口"))
    }

    func testFixtureShapeInventoryNeverClaimsLivePassOrAccepted() throws {
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                  destination: .block)
        ], defaultDestination: .block)
        let profile = RouterSystemProfile(resolver: .quad9)
        let inventory = try RouterTrafficMatrix.fixtureShapeInventory(plan: plan, profile: profile)
        XCTAssertEqual(inventory.livePassedCount, 0)
        XCTAssertFalse(inventory.canClaimMatrixComplete)
        XCTAssertTrue(inventory.cells.filter { $0.kind == .applicationTraffic }
            .allSatisfy { $0.status == .fixtureShapeOnly })
        XCTAssertTrue(inventory.cells.contains(where: {
            $0.kind == .coreExitFailClosed && $0.status == .capabilityGap
        }))
        XCTAssertTrue(inventory.summary.contains("不能提升 accepted") || inventory.summary.contains("无 live"))
    }

    func testInvalidPlanRefusesMatrix() {
        let bad = RouterPlan(proxies: [], rules: [
            .init(id: UUID(), selector: .init(), destination: .proxy(UUID()))
        ], defaultDestination: .direct)
        XCTAssertThrowsError(try RouterTrafficMatrix.report(
            plan: bad, profile: .init(resolver: .cloudflare)))
    }
}
