import XCTest
@testable import LauncherCore

final class ConnectorTransactionTests: XCTestCase {
    private func binding() throws -> ConnectorTransactionBinding {
        var snapshot = ConnectorSnapshot()
        snapshot.state = "blocked"; snapshot.port = 12345; snapshot.transactionProtocol = 2
        snapshot.configDigest = ConnectorConfiguration().digest
        let pf = ConnectorPFBinding(requestID: String(repeating: "a", count: 32), expectedRevision: 3,
            planID: String(repeating: "b", count: 32), planSHA256: String(repeating: "c", count: 64),
            runtimeSHA256: String(repeating: "d", count: 64), serviceInstance: String(repeating: "e", count: 32),
            generation: String(repeating: "f", count: 32), receivedNotBefore: 100)
        return try XCTUnwrap(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
    }

    func testSnapshotAndPFIdentityAreRequiredBeforeReservation() throws {
        let pf = try binding().pf
        var snapshot = ConnectorSnapshot(); snapshot.state = "blocked"; snapshot.port = 12345
        snapshot.configDigest = ConnectorConfiguration().digest
        XCTAssertNil(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
        snapshot.transactionProtocol = 1
        XCTAssertNil(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
        snapshot.transactionProtocol = 2
        XCTAssertNotNil(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
        snapshot.epoch = UInt64.max
        XCTAssertNil(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
        snapshot.epoch = 0; snapshot.sampledAt = Date().addingTimeInterval(-5)
        XCTAssertNil(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
        var json = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(pf)) as? [String: Any])
        for (key, value): (String, Any) in [("expectedRevision", -1), ("generation", "ABC"),
            ("requestID", String(repeating: "A", count: 32)), ("receivedNotBefore", -1)] {
            let old = json[key]; json[key] = value
            let bad = try JSONDecoder().decode(ConnectorPFBinding.self, from: JSONSerialization.data(withJSONObject: json))
            XCTAssertFalse(bad.valid); json[key] = old
        }
    }

    func testReservationBudgetAndPreparationCannotBeExtendedByReplay() throws {
        var fence = ConnectorFence(binding: try binding(), effectiveEpoch: 1, now: 100)
        let probe = UUID()
        XCTAssertFalse(fence.begin(id: probe, now: 100))
        fence.reserved(); XCTAssertTrue(fence.begin(id: probe, now: 110))
        XCTAssertFalse(fence.begin(id: probe, now: 111))
        XCTAssertEqual(fence.deadline, 112)
        XCTAssertFalse(fence.revoking(id: UUID(), now: 111))
        XCTAssertTrue(fence.revoking(id: probe, now: 111)); fence.prepared()
        XCTAssertFalse(fence.commit(now: 112, pfDeadline: 200, grantDeadline: 200))
        XCTAssertTrue(fence.expired(at: 112))
    }

    func testCommitUsesOriginalPFDeadlineAndNeverRenewsIt() throws {
        var fence = ConnectorFence(binding: try binding(), effectiveEpoch: 1, now: 100)
        let probe = UUID(); fence.reserved()
        XCTAssertTrue(fence.begin(id: probe, now: 101)); XCTAssertTrue(fence.revoking(id: probe, now: 102))
        fence.prepared()
        XCTAssertFalse(fence.commit(now: 103, pfDeadline: nil, grantDeadline: 140))
        XCTAssertFalse(fence.commit(now: 103, pfDeadline: 103, grantDeadline: 140))
        XCTAssertTrue(fence.commit(now: 103, pfDeadline: 106, grantDeadline: 140))
        XCTAssertEqual(fence.deadline, 106)
        XCTAssertFalse(fence.commit(now: 104, pfDeadline: 200, grantDeadline: 200))
        fence.shorten(to: 200); XCTAssertEqual(fence.deadline, 106)
        fence.shorten(to: 105); XCTAssertEqual(fence.deadline, 105)
        XCTAssertTrue(fence.expired(at: 105))
    }

    func testCancellationKeepsFenceUntilExplicitDrainedLeave() throws {
        var fence = ConnectorFence(binding: try binding(), effectiveEpoch: 1, now: 100)
        fence.stop("transaction_cancelled"); fence.cancelling()
        XCTAssertFalse(fence.terminal); XCTAssertTrue(fence.fenced)
        XCTAssertFalse(fence.leaving()); XCTAssertFalse(fence.expired(at: 200))
        fence.cancelled(); XCTAssertTrue(fence.terminal)
        fence.stop("new_fault"); XCTAssertEqual(fence.reason, "transaction_cancelled")
        XCTAssertTrue(fence.leaving()); XCTAssertTrue(fence.fenced)
        fence.released(); XCTAssertFalse(fence.fenced)
        fence.stop("old_callback"); XCTAssertEqual(fence.phase, "released")
        XCTAssertFalse(fence.begin(id: UUID(), now: 101))
    }

    func testTransactionProbeSharesReservationDeadlineAndBlocksUntilConsumed() throws {
        var grant = ConnectorGrant(); grant.heartbeat(109)
        let id = UUID(), token = String(repeating: "a", count: 64)
        XCTAssertTrue(grant.transactionProbe(id: id, token: token, now: 109, deadline: 112))
        XCTAssertEqual(grant.capability?.deadline, 112)
        XCTAssertNil(grant.authorize(target: try Target.parse("example.com:443"), connect: true, auth: nil, now: 109))
        XCTAssertTrue(grant.revoke(id: id, now: 110))
        XCTAssertFalse(grant.commit(id: id, manual: true, now: 110))
        grant.block(); grant.heartbeat(112)
        XCTAssertFalse(grant.transactionProbe(id: UUID(), token: token, now: 112, deadline: 112))
    }

    func testBoundedInputReachesEOFAndRejectsOversizeBeforeLaunch() {
        let input = Data(repeating: 65, count: 4096)
        let capture = BoundedProcess.capture(executable: "/usr/bin/python3",
            arguments: ["-I", "-S", "-B", "-c", "import sys; print(len(sys.stdin.buffer.read()))"], timeout: 5, input: input)
        XCTAssertTrue(capture.complete); XCTAssertTrue(capture.settled)
        XCTAssertEqual(String(decoding: capture.data, as: UTF8.self), "4096\n")
        let rejected = BoundedProcess.capture(executable: "/usr/bin/true", arguments: [], timeout: 1,
            input: Data(repeating: 65, count: 4097))
        XCTAssertFalse(rejected.complete); XCTAssertTrue(rejected.settled)
    }

    func testEarlyExitOrUnreadInputDoesNotHangOrChangeSIGPIPEPolicy() {
        var before = sigaction(), after = sigaction()
        XCTAssertEqual(sigaction(SIGPIPE, nil, &before), 0)
        let start = connectorTime()
        for _ in 0..<10 {
            let result = BoundedProcess.capture(executable: "/usr/bin/true", arguments: [], timeout: 1,
                input: Data(repeating: 65, count: 4096))
            XCTAssertTrue(result.settled)
        }
        let stalled = BoundedProcess.capture(executable: "/bin/sleep", arguments: ["3"], timeout: 0.1,
            input: Data(repeating: 65, count: 4096))
        XCTAssertFalse(stalled.complete); XCTAssertTrue(stalled.settled)
        XCTAssertLessThan(connectorTime() - start, 5)
        XCTAssertEqual(sigaction(SIGPIPE, nil, &after), 0)
        XCTAssertEqual(before.sa_flags, after.sa_flags)
        XCTAssertEqual(unsafeBitCast(before.__sigaction_u.__sa_handler, to: UInt.self),
                       unsafeBitCast(after.__sigaction_u.__sa_handler, to: UInt.self))
    }
}
