import XCTest
@testable import RoutingCore

final class RouterTakeoverChangeManifestTests: XCTestCase {
    func testManifestListsExactChangesAndNeverClaimsAcceptance() throws {
        let proxy = RouterProxy(id: UUID(), name: "mei", kind: .socks5, host: "203.0.113.43", port: 9034,
                                udp: false, credentialReference: UUID())
        let plan = RouterPlan(proxies: [proxy], rules: [
            .init(id: UUID(), selector: .init(domain: .init(kind: .suffix, value: "claude.ai")),
                  destination: .proxy(proxy.id))
        ], defaultDestination: .block)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let digest = try RouterSystemCompiler.digest(plan: plan, profile: profile)
        let report = RouterTakeoverChangeManifest.make(plan: plan, profile: profile, digest: digest)
        XCTAssertEqual(report.digest, digest)
        XCTAssertTrue(report.requiresExplicitUserConfirm)
        XCTAssertTrue(report.requiresClearNetwork)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertTrue(report.bullets.contains(where: { $0.contains("TUN") && $0.contains("DNS") }))
        XCTAssertTrue(report.bullets.contains(where: { $0.contains("1 条线路") && $0.contains("1 条规则") }))
        XCTAssertTrue(report.bullets.contains(where: { $0.contains("阻断") }))
        XCTAssertTrue(report.bullets.contains(where: { $0.contains("requireClear") }))
        XCTAssertTrue(report.bullets.contains(where: {
            $0.contains("accepted") && ($0.contains("证据门禁") || $0.contains("空"))
        }))
        XCTAssertTrue(report.bullets.contains(where: {
            $0.contains("断流尚未验证") || ($0.contains("REJECT") && $0.contains("不能代替"))
        }))
        XCTAssertTrue(report.confirmationSummary.contains("不是分流验收通过"))
        let forced = RouterTakeoverChangeManifest.Report(
            digest: digest, bullets: [], confirmationSummary: "x",
            requiresExplicitUserConfirm: false, requiresClearNetwork: false,
            routingVerified: true, accepted: true)
        XCTAssertTrue(forced.requiresExplicitUserConfirm)
        XCTAssertTrue(forced.requiresClearNetwork)
        XCTAssertFalse(forced.routingVerified)
        XCTAssertFalse(forced.accepted)
    }

    func testValidateJournalStillRejectsFakeAcceptedFills() throws {
        var state = RouterSystemJournal.empty()
        try RouterSystemProvider.validateJournal(state)
        state.accepted = RouterAcceptedConfiguration(
            plan: RouterPlan(proxies: [], rules: [], defaultDestination: .direct),
            profile: .init(resolver: .cloudflare),
            configurationDigest: String(repeating: "a", count: 64),
            acceptanceEvidenceDigest: String(repeating: "b", count: 64))
        XCTAssertThrowsError(try RouterSystemProvider.validateJournal(state)) { error in
            XCTAssertEqual(error as? RouterSystemError, .journalUnknown)
        }
        state.accepted = nil
        state.previousAccepted = RouterAcceptedConfiguration(
            plan: RouterPlan(proxies: [], rules: [], defaultDestination: .direct),
            profile: .init(resolver: .quad9),
            configurationDigest: String(repeating: "c", count: 64),
            acceptanceEvidenceDigest: String(repeating: "d", count: 64))
        XCTAssertThrowsError(try RouterSystemProvider.validateJournal(state)) { error in
            XCTAssertEqual(error as? RouterSystemError, .journalUnknown)
        }
    }
}