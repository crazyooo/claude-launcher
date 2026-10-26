import XCTest
@testable import LauncherCore

final class ConnectorTests: XCTestCase {
    private let token = String(repeating: "a", count: 64)
    private var auth: String { "Basic " + Data("probe:\(token)".utf8).base64EncodedString() }
    private func consume(_ grant: inout ConnectorGrant, at time: Double) throws {
        for host in ConnectorConfiguration.hosts {
            XCTAssertEqual(grant.authorize(target: try Target.parse("\(host):443"), connect: true, auth: auth, now: time), true)
        }
    }
    private func allowed() throws -> ConnectorGrant {
        var grant = ConnectorGrant(); let id = UUID(); grant.heartbeat(100)
        XCTAssertTrue(grant.begin(id: id, token: token, manual: true, now: 100))
        grant.heartbeat(110); try consume(&grant, at: 110)
        XCTAssertTrue(grant.revoke(id: id, now: 110))
        XCTAssertTrue(grant.commit(id: id, manual: true, now: 110)); return grant
    }
    func testHeartbeatNeverGrantsAndRequiresAllProbes() throws {
        var grant = ConnectorGrant(); grant.heartbeat(100)
        XCTAssertNil(grant.authorize(target: try Target.parse("example.com:443"), connect: true, auth: nil, now: 100))
        let id = UUID(); XCTAssertTrue(grant.begin(id: id, token: token, manual: true, now: 100))
        XCTAssertFalse(grant.commit(id: id, manual: true, now: 100))
        XCTAssertTrue(grant.revoke(id: id, now: 100)); XCTAssertFalse(grant.commit(id: id, manual: true, now: 100))
    }
    func testProbeCapabilityIsSingleUseExactTargetAndExpires() throws {
        var grant = ConnectorGrant(); grant.heartbeat(100)
        let id = UUID(); XCTAssertTrue(grant.begin(id: id, token: token, manual: true, now: 100))
        let target = try Target.parse("claude.ai:443")
        XCTAssertNil(grant.authorize(target: target, connect: false, auth: auth, now: 100))
        for address in ["claude.ai:80", "not-claude.ai:443", "localhost:443"] {
            XCTAssertNil(grant.authorize(target: try Target.parse(address), connect: true, auth: auth, now: 100))
        }
        XCTAssertEqual(grant.authorize(target: target, connect: true, auth: auth, now: 100), true)
        XCTAssertNil(grant.authorize(target: target, connect: true, auth: auth, now: 100))
        grant.heartbeat(112); XCTAssertTrue(grant.expired(112)); XCTAssertFalse(grant.revoke(id: id, now: 112))
    }
    func testBlockRevokesOldReceiptsAndCannotAutoRecover() throws {
        var grant = try allowed(); let epoch = grant.epoch; grant.block(); grant.heartbeat(111)
        XCTAssertGreaterThan(grant.epoch, epoch); XCTAssertFalse(grant.allowed)
        XCTAssertFalse(grant.begin(id: UUID(), token: token, manual: false, now: 111))
    }
    func testLeaseUsesStartAndLateAutomaticCommitCannotRevive() throws {
        var grant = try allowed(); XCTAssertEqual(grant.evidenceDeadline, 140)
        grant.heartbeat(135); let id = UUID()
        XCTAssertTrue(grant.begin(id: id, token: token, manual: false, now: 135))
        try consume(&grant, at: 135); XCTAssertTrue(grant.revoke(id: id, now: 135))
        grant.heartbeat(140); XCTAssertFalse(grant.commit(id: id, manual: false, now: 140)); XCTAssertTrue(grant.expired(140))
    }
    func testBadCredentialsNeverFallThroughToNormalTraffic() throws {
        var grant = try allowed(); let target = try Target.parse("example.com:443")
        XCTAssertEqual(grant.authorize(target: target, connect: true, auth: nil, now: 110), false)
        XCTAssertNil(grant.authorize(target: target, connect: true, auth: "Basic bad", now: 110))
        XCTAssertFalse(grant.heartbeatCurrent(109)); XCTAssertTrue(grant.heartbeatCurrent(112.99))
        XCTAssertFalse(grant.heartbeatCurrent(113))
    }
    func testConfigAndSnapshotCannotClaimProtection() throws {
        var config = ConnectorConfiguration(); XCTAssertNoThrow(try config.validate())
        XCTAssertEqual(config.digest, config.digest); config.upstreamHost = "example.com"; XCTAssertThrowsError(try config.validate())
        var state = ConnectorSnapshot(); state.state = "allowed"; state.port = 12345
        XCTAssertTrue(state.isCurrent()); state.launchAuthorized = true; XCTAssertFalse(state.isCurrent())
    }

    func testTransactionBudgetRequiresFiveExactAuthoritiesBeforePreparation() throws {
        var grant = ConnectorGrant(); grant.heartbeat(100)
        let id = UUID(); XCTAssertTrue(grant.transactionProbe(id: id, token: token, now: 100, deadline: 112))
        try consume(&grant, at: 100)
        XCTAssertFalse(grant.revokeCompletedTransaction(id: id, now: 100))
        XCTAssertNil(grant.authorize(target: try Target.parse("platform.claude.com:443"), connect: true, auth: auth, now: 100))
        for address in ["api.anthropic.com:80", "other.example:443", "[::1]:443"] {
            XCTAssertNil(grant.authorize(target: try Target.parse(address), connect: true, auth: auth, now: 100))
        }
        for host in ["claude.ai", "api.anthropic.com"] {
            let target = try Target.parse(host + ":443")
            XCTAssertNil(grant.authorize(target: target, connect: false, auth: auth, now: 100))
            XCTAssertEqual(grant.authorize(target: target, connect: true, auth: auth, now: 100), true)
            XCTAssertNil(grant.authorize(target: target, connect: true, auth: auth, now: 100))
        }
        XCTAssertTrue(grant.revokeCompletedTransaction(id: id, now: 100))
        XCTAssertFalse(grant.allowed)
        grant.block(); XCTAssertFalse(grant.commit(id: id, manual: true, now: 100))
    }
}
