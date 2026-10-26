import XCTest
@testable import LauncherCore

final class RecoveryCoordinatorTests: XCTestCase {
    let fixture = RecoveryFixture()
    func pf(_ operation: RecoveryOperationIntent, now: Date, expiry: Double = 20, checkedAge: Double = 0) throws -> PFObservation {
        let request = operation.request!, context = request.context, start = request.createdAt.timeIntervalSince1970
        let receipt: [String: Any] = ["version": 1, "revision": context.receipt_revision + 1,
            "plan_id": context.plan_id, "plan_sha256": context.plan_sha256, "runtime_sha256": context.runtime_sha256,
            "service_instance": context.service_instance, "request_id": request.id, "status": "passed", "reason": "checks_passed",
            "generation": operation.transaction!.pf.generation, "received_at": start + 0.1, "started_at": start + 0.2,
            "checked_at": start + 0.3, "finished_at": start + 0.5, "updated_at": start + 0.5,
            "request_deadline": start + 90, "evidence_expires_at": start + expiry,
            "checks": ["installed": true, "pf_enabled": true, "root_matches": true, "destinations_match": true, "evidence_fresh": true]]
        let root: [String: Any] = ["version": 1, "plan_id": context.plan_id, "checked_at": now.timeIntervalSince1970 - checkedAge,
            "service_running": true, "rules_observed": true, "evidence_fresh": true, "manual_recheck_required": false,
            "status": "observed", "reason": "same_addresses_observed", "protection_verified": false, "launch_authorized": false,
            "evidence_expires_at": start + 100, "recovery_current": true, "recovery": receipt,
            "control_context": ["version": 1, "plan_id": context.plan_id, "plan_sha256": context.plan_sha256,
                "runtime_sha256": context.runtime_sha256, "service_instance": context.service_instance, "receipt_revision": context.receipt_revision + 1]]
        return try JSONDecoder().decode(PFObservation.self, from: JSONSerialization.data(withJSONObject: root))
    }
    func local(at now: Date) -> RecoveryLocalTargetReport {
        RecoveryLocalTargetInspector.inspect(settings: fixture.settings, connector: fixture.config, target: .desktop,
            capture: { .init(context: self.fixture.context, source: .init(installed: true, running: false,
                readObject: { _ in [:] }, wrapperInstalled: { true }, fallbackTransport: .init())) }, clock: { now })
    }
    func testRestartIsObservationOnlyAndExplicitPreparedContinueRequiresFreshEvidence() throws {
        let (intent, authorization) = try fixture.prepared(), now = authorization.request.createdAt.addingTimeInterval(1)
        let report = try pf(intent, now: now)
        var state = RecoveryCoordinator(), auth = PFRecoveryCoordinator()
        state.restore(intent); auth.restoreForObservation(authorization)
        let query = ConnectorHoldRequest(action: .status, hold: intent.hold)
        state.observe(fixture.reply(intent, query: query, phase: "prepared"), for: query, ticket: state.generation)
        func allowed(_ report: PFObservation?, context: String = fixture.context) -> Bool {
            state.canCommit(local: local(at: now), context: context, settings: fixture.settings, connector: fixture.config,
                            target: .desktop, environment: [:], pf: report, authorization: auth, at: now)
        }
        XCTAssertFalse(allowed(report)); XCTAssertFalse(state.canAuthorize(at: now))
        XCTAssertThrowsError(try state.mutationPermit(for: XCTUnwrap(intent.pending)))
        try state.continuePrepared(at: now)
        XCTAssertTrue(allowed(report)); XCTAssertFalse(allowed(nil)); XCTAssertFalse(allowed(report, context: String(repeating: "d", count: 64)))
        XCTAssertFalse(allowed(try pf(intent, now: now, expiry: 0.9))) // Outer evidence lasts longer; original receipt still expires.
        state.becameUnknown(); XCTAssertFalse(allowed(report))
    }
    func testIdentityEpochDrainAndStaleRepliesCannotAuthorize() throws {
        let operation = try fixture.operation()
        for field in ["good", "instance", "config", "epoch", "hold", "drain", "stale", "protocol", "old-released"] {
            var state = RecoveryCoordinator(); try state.begin(operation)
            let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
            let reply = fixture.reply(operation, query: query, phase: "held") { snapshot in
                switch field {
                case "instance": snapshot.instanceID = UUID()
                case "config": snapshot.configDigest = String(repeating: "f", count: 64)
                case "epoch": snapshot.epoch += 1
                case "hold": snapshot.hold = .init(id: UUID(), phase: "held")
                case "drain": snapshot.hold?.drainPending = true
                case "stale": snapshot.sampledAt = Date().addingTimeInterval(-10)
                case "protocol": snapshot.transactionProtocol = 1
                case "old-released": snapshot.transaction = .init(id: UUID(), phase: "released", reason: "fixture")
                default: break
                }
            }
            state.observe(reply, for: query, ticket: state.generation)
            XCTAssertEqual(state.canAuthorize(), ["good", "old-released"].contains(field), field)
        }
    }
    func testStaleGenerationAndWrongReplyCannotReplaceObservation() throws {
        let operation = try fixture.operation(); var state = RecoveryCoordinator(); try state.begin(operation)
        let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
        let reply = fixture.reply(operation, query: query, phase: "held"), ticket = state.generation
        state.observe(reply, for: .init(action: .status, hold: operation.hold), ticket: ticket)
        XCTAssertNil(state.observation)
        state.invalidate(); state.observe(reply, for: query, ticket: ticket)
        XCTAssertNil(state.observation); XCTAssertFalse(state.canAuthorize())
        state.observe(reply, for: query, ticket: state.generation)
        XCTAssertNotNil(state.observation); XCTAssertFalse(state.canAuthorize())
    }
    func testInvalidationCancelsPendingWriteAndLateSaveDoesNotRestoreContinuation() throws {
        let operation = try fixture.operation(); var state = RecoveryCoordinator(); try state.begin(operation)
        let permit = try state.mutationPermit(for: XCTUnwrap(operation.pending)), ticket = state.generation
        state.invalidate()
        try state.recordSaved(operation.cancelling())
        state.mutationReturned(ticket: ticket)
        XCTAssertThrowsError(try permit.write(-1, data: Data([10]), deadline: connectorTime() + 1) { _, _ in XCTFail("invalidated write"); return 1 })
        XCTAssertEqual(state.mode, .invalidated); XCTAssertEqual(state.intent?.checkpoint, .cancel)
        XCTAssertThrowsError(try state.mutationPermit(for: XCTUnwrap(state.intent?.pending)))
    }
    func testCommitStillWaitsForOriginalAuthorizationProcessToExit() throws {
        let (operation, intent) = try fixture.prepared(), now = intent.request.createdAt.addingTimeInterval(1)
        var state = RecoveryCoordinator(), auth = PFRecoveryCoordinator()
        state.restore(operation)
        let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
        state.observe(fixture.reply(operation, query: query, phase: "prepared"), for: query, ticket: state.generation)
        try state.continuePrepared(at: now)
        let armed = try intent.armed(with: PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: intent.executionID))
        auth.restoreForObservation(armed)
        XCTAssertFalse(state.canCommit(local: local(at: now), context: fixture.context, settings: fixture.settings,
            connector: fixture.config, target: .desktop, environment: [:], pf: try pf(operation, now: now), authorization: auth, at: now))
        XCTAssertFalse(StrictProtection.verified)
    }
    func testMutationReturnNeverEnablesAutomaticResend() throws {
        var state = RecoveryCoordinator(); let operation = try fixture.operation()
        try state.begin(operation)
        _ = try state.mutationPermit(for: XCTUnwrap(operation.pending))
        state.mutationReturned(ticket: state.generation)
        XCTAssertThrowsError(try state.mutationPermit(for: XCTUnwrap(operation.pending)))
    }
    func testCommitIntentRequiresExplicitContinueAndRetainsOriginalCommand() throws {
        let (prepared, authorization) = try fixture.prepared(), operation = try prepared.committing()
        let now = authorization.request.createdAt.addingTimeInterval(1), report = try pf(operation, now: now)
        var state = RecoveryCoordinator(), auth = PFRecoveryCoordinator()
        auth.restoreForObservation(authorization); state.restore(operation)
        let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
        let reply = fixture.reply(operation, query: query, phase: "prepared")
        state.observe(reply, for: query, ticket: state.generation)
        let local = local(at: now)
        func issue() throws -> RecoveryMutationPermit {
            try state.commitPermit(local: local, context: fixture.context, settings: fixture.settings, connector: fixture.config,
                                   target: .desktop, environment: [:], pf: report, authorization: auth, now: now, tick: connectorTime())
        }
        XCTAssertThrowsError(try issue())
        XCTAssertThrowsError(try RecoveryMutationPermit(command: XCTUnwrap(operation.pending), generation: state.generation))
        try state.continuePrepared(at: now)
        XCTAssertThrowsError(try state.mutationPermit(for: XCTUnwrap(operation.pending)))
        let permit = try issue(), ticket = state.generation
        XCTAssertEqual(permit.command, operation.pending)
        state.mutationReturned(ticket: ticket); XCTAssertThrowsError(try issue())
        state.becameUnknown()
        state.observe(reply, for: query, ticket: ticket)
        XCTAssertNil(state.observation); XCTAssertThrowsError(try state.continuePrepared(at: now))
        state.observe(reply, for: query, ticket: state.generation)
        XCTAssertThrowsError(try issue()) // Polling alone never resumes a commit.
        try state.continuePrepared(at: now)
        XCTAssertEqual(try issue().command, operation.pending)
        state.invalidate(); XCTAssertThrowsError(try issue())
    }
    func testPreparedContinuationCannotResendPrepare() throws {
        let (operation, authorization) = try fixture.prepared()
        var state = RecoveryCoordinator(); state.restore(operation)
        let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
        state.observe(fixture.reply(operation, query: query, phase: "prepared"), for: query, ticket: state.generation)
        try state.continuePrepared(at: authorization.request.createdAt.addingTimeInterval(1))
        XCTAssertThrowsError(try state.mutationPermit(for: XCTUnwrap(operation.pending)))
    }
    func testCommitDeadlineSurvivesSocketWaitAndCannotBeExtended() throws {
        for limit in ["local-tick", "local-wall", "receipt", "report", "heartbeat", "snapshot-age"] {
            let (prepared, authorization) = try fixture.prepared(), operation = try prepared.committing()
            let now = authorization.request.createdAt.addingTimeInterval(15), tick = 100.0
            var state = RecoveryCoordinator(), auth = PFRecoveryCoordinator()
            state.restore(operation); auth.restoreForObservation(authorization)
            let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
            state.observe(fixture.reply(operation, query: query, phase: "prepared") { snapshot in
                snapshot.sampledAt = now.addingTimeInterval(limit == "snapshot-age" ? -2.5 : 0)
                snapshot.heartbeatAge = limit == "heartbeat" ? 2.5 : 0
            }, for: query, ticket: state.generation)
            try state.continuePrepared(at: now)
            let local = RecoveryLocalTargetReport(target: .desktop,
                startedAt: now.addingTimeInterval(limit == "local-wall" ? -29.5 : 0), completedAt: now,
                startedTick: limit == "local-tick" ? 70.5 : tick, completedTick: tick,
                context: fixture.context, checks: self.local(at: now).checks)
            let report = try pf(operation, now: now, expiry: limit == "receipt" ? 15.5 : 40,
                                checkedAge: limit == "report" ? 9.5 : 0)
            let permit = try state.commitPermit(local: local, context: fixture.context, settings: fixture.settings,
                connector: fixture.config, target: .desktop, environment: [:], pf: report,
                authorization: auth, now: now, tick: tick)
            XCTAssertEqual(permit.validUntil, 100.5, accuracy: 0.001, limit)
            var writes = 0
            XCTAssertThrowsError(try permit.write(-1, data: Data([1]), deadline: tick + 5,
                clock: { permit.validUntil }) { _, _ in writes += 1; return 1 }, limit)
            XCTAssertThrowsError(try permit.write(-1, data: Data([1]), deadline: tick + 50,
                clock: { tick }) { _, _ in writes += 1; return 1 }, limit)
            XCTAssertEqual(writes, 0, limit)
        }
    }
    func testLeaveRequiresOriginalTerminalAndDrainedOperation() throws {
        let (operation, _) = try fixture.prepared()
        for phase in ["held", "prepared", "committed", "cancelled", "interrupted", "released"] {
            var state = RecoveryCoordinator(); state.restore(operation)
            let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
            state.observe(fixture.reply(operation, query: query, phase: phase), for: query, ticket: state.generation)
            XCTAssertEqual(state.canRequestLeave, ["cancelled", "interrupted", "released"].contains(phase), phase)
        }
        for fault in ["hold-drain", "transaction-drain", "other-live-transaction", "instance", "config", "epoch", "worker", "hold-unknown"] {
            var state = RecoveryCoordinator(); state.restore(operation)
            let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
            let sample = fixture.reply(operation, query: query, phase: "cancelled") { snapshot in
                switch fault {
                case "hold-drain": snapshot.hold?.drainPending = true
                case "transaction-drain": snapshot.transaction?.drainPending = true
                case "other-live-transaction": snapshot.transaction = .init(id: UUID(), phase: "prepared", reason: "fixture")
                case "instance": snapshot.instanceID = UUID()
                case "config": snapshot.configDigest = "changed"
                case "epoch": snapshot.epoch = operation.hold.initialEpoch
                default: break
                }
            }
            let reply = ConnectorHoldReply(version: 2, commandID: query.commandID, holdID: operation.hold.id,
                accepted: fault != "hold-unknown", reason: fault, operation: sample.operation,
                localWorkPending: fault == "worker", snapshot: sample.snapshot)
            state.observe(reply, for: query, ticket: state.generation)
            XCTAssertFalse(state.canRequestLeave, fault)
        }
    }
    func testLeaveRequestsExitProofWithoutTreatingItAsCompletedCleanup() throws {
        let operation = try fixture.operation()
        for scenario in ["orphan", "gateway-exited", "hold-not-sent"] {
            var state = RecoveryCoordinator(); state.restore(operation)
            let query = ConnectorHoldRequest(action: .status, hold: operation.hold)
            let reply = fixture.reply(operation, query: query, phase: "interrupted") { snapshot in
                snapshot.sampledAt = Date().addingTimeInterval(-100)
                if scenario == "orphan" {
                    snapshot.state = "stopped"; snapshot.reason = "orphan_hold"; snapshot.instanceID = UUID()
                    snapshot.port = 0; snapshot.hold?.drainPending = true
                } else if scenario == "gateway-exited" {
                    snapshot.state = "stopped"; snapshot.reason = "gateway_exited"
                } else { snapshot.hold = nil }
            }
            state.observe(reply, for: query, ticket: state.generation)
            XCTAssertTrue(state.canRequestLeave, scenario)
            XCTAssertFalse(state.canAuthorize()); XCTAssertFalse(state.canExplicitlyContinue)
            XCTAssertThrowsError(try operation.leaving().closing(after: reply, for: query))
        }
    }
}
