import XCTest
import Darwin
@testable import LauncherCore

struct RecoveryFixture {
    var config = ConnectorConfiguration()
    var settings: PreflightSettings { var value = PreflightSettings(); value.expectedIP = config.expectedIPv4; return value }
    let context = String(repeating: "c", count: 64)
    func operation() throws -> RecoveryOperationIntent {
        var snapshot = ConnectorSnapshot()
        snapshot.port = 12345; snapshot.state = "blocked"; snapshot.configDigest = config.digest
        snapshot.controlProtocol = 2; snapshot.transactionProtocol = 2; snapshot.holdProtocol = 1
        snapshot.gatewayLifetime = .init(device: 1, inode: 2)
        return try .init(snapshot: snapshot, target: .desktop, settings: settings, environment: [:], localContext: context)
    }
    func authorization() throws -> PFAuthorizationIntent {
        .init(request: try PFAuthorizationExecutionTests().request(), executionID: UUID())
    }
    func prepared() throws -> (RecoveryOperationIntent, PFAuthorizationIntent) {
        let authorization = try authorization(), operation = try operation().associating(authorization)
        let request = authorization.request
        let pf = ConnectorPFBinding(requestID: request.id, expectedRevision: request.context.receipt_revision,
            planID: request.context.plan_id, planSHA256: request.context.plan_sha256, runtimeSHA256: request.context.runtime_sha256,
            serviceInstance: request.context.service_instance, generation: String(repeating: "f", count: 32),
            receivedNotBefore: request.createdAt.timeIntervalSince1970)
        return (try operation.preparing(XCTUnwrap(ConnectorTransactionBinding(hold: operation.hold, pf: pf))), authorization)
    }
    func directory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().appendingPathComponent("unified-recovery-\(UUID())")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    func reply(_ operation: RecoveryOperationIntent, query: ConnectorHoldRequest, phase: String,
               mutate: (inout ConnectorSnapshot) -> Void = { _ in }) -> ConnectorHoldReply {
        var snapshot = ConnectorSnapshot()
        snapshot.port = 12345; snapshot.state = phase == "committed" ? "allowed" : "blocked"
        snapshot.instanceID = operation.hold.gatewayInstance; snapshot.configDigest = operation.hold.configurationDigest
        snapshot.epoch = operation.hold.initialEpoch + 1
        snapshot.controlProtocol = 2; snapshot.transactionProtocol = 2; snapshot.holdProtocol = 1
        snapshot.hold = .init(id: operation.hold.id, phase: ["prepared", "committed"].contains(phase) ? "attached" : phase)
        if let transaction = operation.transaction {
            snapshot.transaction = .init(id: transaction.id, phase: phase, reason: "fixture")
        }
        mutate(&snapshot)
        return .init(version: 2, commandID: query.commandID, holdID: operation.hold.id, accepted: true,
                     reason: "hold_observed", operation: phase, localWorkPending: false, snapshot: snapshot)
    }
}

final class RecoveryOperationTests: XCTestCase {
    let fixture = RecoveryFixture()
    func testStrictSchemaAndExactOriginalPFSelector() throws {
        let (operation, authorization) = try fixture.prepared()
        let bytes = try JSONEncoder().encode(operation)
        XCTAssertEqual(try JSONDecoder().decode(RecoveryOperationIntent.self, from: bytes), operation)
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for key in original.keys {
            var missing = original; missing.removeValue(forKey: key)
            XCTAssertThrowsError(try JSONDecoder().decode(RecoveryOperationIntent.self, from: JSONSerialization.data(withJSONObject: missing)))
        }
        for (key, value): (String, Any) in [("passed", true), ("version", 2), ("target", "cli"), ("localContext", "bad"), ("checkpoint", "authorization")] {
            var invalid = original; invalid[key] = value
            XCTAssertThrowsError(try JSONDecoder().decode(RecoveryOperationIntent.self, from: JSONSerialization.data(withJSONObject: invalid)))
        }
        for key in ["requestID", "planSHA256", "runtimeSHA256", "serviceInstance", "expectedRevision", "receivedNotBefore"] {
            var invalid = original, transaction = invalid["transaction"] as! [String: Any], pf = transaction["pf"] as! [String: Any]
            if key == "expectedRevision" { pf[key] = authorization.request.context.receipt_revision + 1 }
            else if key == "receivedNotBefore" { pf[key] = authorization.request.createdAt.timeIntervalSince1970 + 1 }
            else { pf[key] = String(repeating: "e", count: key.contains("SHA") ? 64 : 32) }
            transaction["pf"] = pf; invalid["transaction"] = transaction
            XCTAssertThrowsError(try JSONDecoder().decode(RecoveryOperationIntent.self, from: JSONSerialization.data(withJSONObject: invalid)), key)
        }
    }
    func testLegacyReadDoesNotRewriteAndFirstMutationUsesCompositeState() throws {
        let root = try fixture.directory(), old = try fixture.authorization(), path = root.appendingPathComponent("pf-authorization.json")
        let bytes = try JSONEncoder().encode(old)
        try bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
        let store = try PFAuthorizationJournal(directory: root)
        XCTAssertEqual(try store.loadState()?.authorization, old); XCTAssertNil(try store.loadState()?.recovery)
        XCTAssertEqual(try Data(contentsOf: path), bytes)
        let operation = try fixture.operation()
        try store.saveRecovery(operation, replacing: nil)
        let state = try XCTUnwrap(store.loadState())
        XCTAssertEqual(state.authorization, old); XCTAssertEqual(state.recovery, operation)
        XCTAssertEqual(try JSONSerialization.jsonObject(with: Data(contentsOf: path)) as? [String: Any] != nil, true)
    }
    func testAtomicAssociationArmingAndCancellationPreserveBothIdentities() throws {
        let root = try fixture.directory(), operation = try fixture.operation(), authorization = try fixture.authorization()
        var store: PFAuthorizationJournal? = try .init(directory: root)
        try store!.saveRecovery(operation, replacing: nil)
        let linked = try operation.associating(authorization)
        try store!.associateAuthorization(authorization, recovery: linked, replacing: XCTUnwrap(store!.loadState()))
        let armed = try authorization.armed(with: PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: authorization.executionID))
        let cancelled = try linked.cancelling()
        try store!.saveRecovery(cancelled, replacing: linked)
        try store!.save(armed, replacing: authorization)
        let state = try XCTUnwrap(store!.loadState())
        XCTAssertEqual(state.recovery, cancelled); XCTAssertEqual(state.authorization, armed)
        store = nil
        let reopened = try PFAuthorizationJournal(directory: root)
        XCTAssertEqual(try reopened.loadState(), state)
        XCTAssertThrowsError(try reopened.saveRecovery(fixture.operation(), replacing: cancelled))
    }
    func testWriteAfterReplaceFailureRetainsHoldAndRequiresReopen() throws {
        let root = try fixture.directory(), operation = try fixture.operation()
        var store: PFAuthorizationJournal? = try .init(directory: root, afterReplace: { throw RecoveryOperationIntent.failure })
        XCTAssertThrowsError(try store!.saveRecovery(operation, replacing: nil))
        XCTAssertThrowsError(try store!.loadState())
        store = nil
        let restored = try XCTUnwrap(PFAuthorizationJournal(directory: root).loadState()?.recovery)
        XCTAssertEqual(restored, operation); XCTAssertEqual(restored.cancellation, operation.cancellation)
    }
    func testAssociationFailureAndFullCASCannotCreateSplitIdentities() throws {
        for afterWrite in [false, true] {
            let root = try fixture.directory(), operation = try fixture.operation(), authorization = try fixture.authorization()
            var fail = false
            var store: PFAuthorizationJournal? = try .init(directory: root, afterReplace: { if fail { throw RecoveryOperationIntent.failure } })
            try store!.saveRecovery(operation, replacing: nil)
            let expected = try XCTUnwrap(store!.loadState()), linked = try operation.associating(authorization)
            if afterWrite { fail = true }
            else { try store!.saveRecovery(operation.cancelling(), replacing: operation) }
            XCTAssertThrowsError(try store!.associateAuthorization(authorization, recovery: linked, replacing: expected))
            store = nil
            let restored = try XCTUnwrap(PFAuthorizationJournal(directory: root).loadState())
            XCTAssertTrue(restored.valid)
            XCTAssertEqual(restored.authorization, afterWrite ? authorization : nil)
            XCTAssertEqual(restored.recovery, afterWrite ? linked : try operation.cancelling())
        }
    }
    func testStandaloneAuthorizationAndBackwardTransitionsAreRejected() throws {
        let operation = try fixture.operation(), authorization = try fixture.authorization()
        let root = try fixture.directory(), store = try PFAuthorizationJournal(directory: root)
        try store.saveRecovery(operation, replacing: nil)
        XCTAssertThrowsError(try store.save(authorization, replacing: nil))
        let (prepared, _) = try fixture.prepared(), cancelled = try prepared.cancelling()
        XCTAssertThrowsError(try cancelled.committing()); XCTAssertThrowsError(try cancelled.preparing(prepared.transaction!))
        XCTAssertFalse(prepared.follows(cancelled)); XCTAssertFalse(try fixture.operation().follows(operation))
    }
    func testClosingRequiresCorrelatedSettledLeaveAndAllowsOrphanCleanup() throws {
        let (prepared, _) = try fixture.prepared(), leaving = try prepared.cancelling().leaving()
        let query = ConnectorHoldRequest(action: .status, hold: leaving.hold)
        let good = fixture.reply(leaving, query: query, phase: "released")
        XCTAssertFalse(try leaving.closing(after: good, for: query).active)
        XCTAssertThrowsError(try leaving.closing(after: good, for: .init(action: .status, hold: leaving.hold)))
        for bad in ["version", "pending", "transaction", "epoch", "drain"] {
            let sample = fixture.reply(leaving, query: query, phase: "released") { snapshot in
                if bad == "transaction" { snapshot.transaction = .init(id: UUID(), phase: "committed", reason: "fixture") }
                if bad == "epoch" { snapshot.epoch = leaving.hold.initialEpoch }
                if bad == "drain" { snapshot.hold?.drainPending = true }
            }
            let reply = ConnectorHoldReply(version: bad == "version" ? 1 : 2, commandID: query.commandID, holdID: leaving.hold.id,
                accepted: true, reason: "fixture", operation: "released", localWorkPending: bad == "pending", snapshot: sample.snapshot)
            XCTAssertThrowsError(try leaving.closing(after: reply, for: query), bad)
        }
        var stopped = good.snapshot; stopped.state = "stopped"; stopped.instanceID = UUID(); stopped.configDigest = ""; stopped.epoch = 0
        let orphan = ConnectorHoldReply(version: 2, commandID: query.commandID, holdID: leaving.hold.id,
            accepted: true, reason: "orphan_released_restart_required", operation: "released", localWorkPending: false, snapshot: stopped)
        XCTAssertFalse(try leaving.closing(after: orphan, for: query).active)
        for old in [false, true] {
            let unattached = fixture.reply(leaving, query: query, phase: "released") { snapshot in
                snapshot.transaction = old ? .init(id: UUID(), phase: "released", reason: "older_operation") : nil
            }
            XCTAssertFalse(try leaving.closing(after: unattached, for: query).active)
        }
    }
}
