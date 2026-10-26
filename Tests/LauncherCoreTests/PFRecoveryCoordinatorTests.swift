import XCTest
@testable import LauncherCore

final class PFRecoveryCoordinatorTests: XCTestCase {
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private let plan = String(repeating: "a", count: 32)
    private func context(_ revision: Int64 = 0) -> [String: Any] {
        ["version": 1, "plan_id": plan, "plan_sha256": String(repeating: "b", count: 64),
         "runtime_sha256": String(repeating: "c", count: 64), "service_instance": String(repeating: "d", count: 32),
         "receipt_revision": revision]
    }
    private func report(at offset: Double = 0, receipt: [String: Any]? = nil,
                        changes: [String: Any] = [:]) throws -> PFObservation {
        var value: [String: Any] = [
            "version": 1, "plan_id": plan, "checked_at": start.timeIntervalSince1970 + offset,
            "service_running": true, "rules_observed": true, "evidence_fresh": false,
            "manual_recheck_required": true, "status": "fault", "reason": "dns_refresh_failed",
            "protection_verified": false, "launch_authorized": false,
            "control_context": context(receipt == nil ? 0 : 1)]
        if let receipt { value["recovery"] = receipt }
        value.merge(changes) { _, new in new }
        return try JSONDecoder().decode(PFObservation.self, from: JSONSerialization.data(withJSONObject: value))
    }
    private func receipt(_ request: PFRecoveryRequest, _ state: String = "passed",
                         changes: [String: Any] = [:]) -> [String: Any] {
        let base = start.timeIntervalSince1970
        var value: [String: Any] = [
            "version": 1, "revision": request.context.receipt_revision + 1,
            "plan_id": plan, "plan_sha256": request.context.plan_sha256,
            "runtime_sha256": request.context.runtime_sha256, "service_instance": request.context.service_instance,
            "request_id": request.id, "status": state, "reason": "checks_passed",
            "generation": String(repeating: "f", count: 32), "received_at": base + 0.1,
            "started_at": base + 0.2, "checked_at": base + 0.3, "finished_at": base + 0.5,
            "updated_at": base + 0.5, "request_deadline": base + 90, "evidence_expires_at": base + 20,
            "checks": ["installed": true, "pf_enabled": true, "root_matches": true,
                       "destinations_match": true, "evidence_fresh": true]]
        if state != "passed" {
            value["checks"] = NSNull(); value["checked_at"] = NSNull(); value["evidence_expires_at"] = NSNull()
        }
        switch state {
        case "received":
            value["reason"] = "request_received"; value["generation"] = NSNull(); value["started_at"] = NSNull()
            value["finished_at"] = NSNull(); value["updated_at"] = base + 0.1
        case "checking":
            value["reason"] = "checks_in_progress"; value["finished_at"] = NSNull(); value["updated_at"] = base + 0.2
        case "failed": value["reason"] = "proxy_probe_failed"
        case "interrupted": value["reason"] = "service_restarted"
        default: break
        }
        value.merge(changes) { _, new in new }; return value
    }
    private func begin(_ coordinator: inout PFRecoveryCoordinator) throws -> PFRecoveryRequest {
        try XCTUnwrap(coordinator.begin(report: report(), epoch: 4, now: start))
    }

    func testInvalidContextAndInvalidOptionalReceiptCannotOfferAuthorization() throws {
        for change: [String: Any] in [["version": true], ["version": 2], ["receipt_revision": true],
            ["receipt_revision": -1], ["receipt_revision": PFControlContext.maximumRevision + 1],
            ["plan_id": "$(touch /tmp/unwanted)"], ["runtime_sha256": String(repeating: "A", count: 64)],
            ["service_instance": "bad"], ["secret": "not-displayed"]] {
            var invalid = context(); invalid.merge(change) { _, new in new }
            XCTAssertNil(try report(changes: ["control_context": invalid]).availableControlContext(at: start))
        }
        for bad: Any in [true, "private", [:], ["revision": 1]] {
            let value = try report(changes: ["recovery": bad])
            XCTAssertTrue(value.isCurrent(at: start))
            XCTAssertNil(value.availableControlContext(at: start))
        }
        XCTAssertNotNil(try report(changes: ["recovery": NSNull()]).availableControlContext(at: start))
        XCTAssertNil(try report(changes: ["control_context": NSNull()]).availableControlContext(at: start))
        var other = context(); other["plan_id"] = String(repeating: "e", count: 32)
        XCTAssertNil(try report(changes: ["control_context": other]).availableControlContext(at: start))
        let maximum = try report(changes: ["control_context": context(PFControlContext.maximumRevision)])
        XCTAssertFalse(maximum.canBeginRecovery(at: start))
    }

    func testRestoredExecutionOnlyObservesOriginalRequestAndNeverRestoresPermission() throws {
        var old = PFRecoveryCoordinator(); let request = try begin(&old)
        let initial = PFAuthorizationIntent(request: request, executionID: old.authorizationID!)
        let identity = try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: initial.executionID)
        let armed = try initial.armed(with: identity)
        var restored = PFRecoveryCoordinator(); restored.restoreForObservation(armed)
        XCTAssertTrue(restored.restoredForObservationOnly); XCTAssertTrue(restored.authorizationInFlight)
        restored.invalidate() // Initial network callback in a new App cannot destroy historical correlation.
        restored.observeExecution(.unknown, identity: identity)
        XCTAssertTrue(restored.authorizationInFlight)
        let pass = try report(at: 1, receipt: receipt(request), changes: ["status": "observed", "evidence_fresh": true,
            "manual_recheck_required": false, "recovery_current": true, "evidence_expires_at": start.timeIntervalSince1970 + 20])
        restored.observe(pass, epoch: 0, now: start.addingTimeInterval(1))
        XCTAssertEqual(restored.phase, .passed); XCTAssertTrue(restored.authorizationInFlight)
        XCTAssertNil(restored.connectorBinding(report: pass, at: start.addingTimeInterval(1)))
        restored.observeExecution(.originalExited, identity: identity)
        XCTAssertFalse(restored.authorizationInFlight); XCTAssertEqual(restored.phase, .passed)
        XCTAssertNil(restored.connectorBinding(report: pass, at: start.addingTimeInterval(1)))
        XCTAssertEqual(restored.request, request)
    }

    func testRestoredUnknownRequiresOriginalProcessExitBeforeExplicitRetry() throws {
        var old = PFRecoveryCoordinator(); let request = try begin(&old)
        let initial = PFAuthorizationIntent(request: request, executionID: old.authorizationID!)
        let identity = try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: initial.executionID)
        var restored = PFRecoveryCoordinator(); restored.restoreForObservation(try initial.armed(with: identity))
        XCTAssertFalse(restored.canRetry(report: try report(), epoch: 0, at: start))
        let stranger = try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: UUID())
        restored.observeExecution(.originalExited, identity: stranger)
        XCTAssertTrue(restored.authorizationInFlight)
        restored.observeExecution(.originalExited, identity: identity)
        XCTAssertTrue(restored.canRetry(report: try report(), epoch: 0, at: start))
        XCTAssertEqual(restored.retry(report: try report(), epoch: 0, now: start), request)
        let executionID = try XCTUnwrap(restored.authorizationID)
        XCTAssertNotEqual(executionID, initial.executionID)
        restored.completed(.init(.cancelled), for: request, executionID: executionID, epoch: 0)
        XCTAssertEqual(restored.phase, .unknown); XCTAssertTrue(restored.restoredForObservationOnly)
        restored.observeExecution(.originalExited, identity: identity)
        XCTAssertEqual(restored.request, request)
    }

    func testUnarmedRestoreDoesNotClaimHelperExitAndExecutionIdentityCannotChange() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        let initial = PFAuthorizationIntent(request: request, executionID: coordinator.authorizationID!)
        var restored = PFRecoveryCoordinator(); restored.restoreForObservation(initial)
        XCTAssertFalse(restored.authorizationInFlight); XCTAssertEqual(restored.phase, .interrupted)
        XCTAssertTrue(restored.lines(report: nil, at: start).joined().contains("尚未准许"))
        XCTAssertTrue(restored.canBegin(report: try report(), at: start))
        let identity = try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: initial.executionID)
        coordinator.recordExecution(try initial.armed(with: identity))
        let changed = PFAuthorizationExecutionIdentity(executionID: identity.executionID, bootUUID: identity.bootUUID,
            pid: identity.pid, startSeconds: identity.startSeconds + 1, startMicroseconds: identity.startMicroseconds)
        coordinator.recordExecution(try initial.armed(with: changed))
        XCTAssertEqual(coordinator.executionIdentity, identity)
        coordinator.observeExecution(.originalExited, identity: changed)
        XCTAssertTrue(coordinator.authorizationInFlight)
    }

    func testActiveReceiptBlocksNewRequestButOldInstanceTerminalCanStart() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        for state in ["received", "checking"] {
            XCTAssertFalse(try report(at: 1, receipt: receipt(request, state)).canBeginRecovery(at: start.addingTimeInterval(1)))
        }
        var next = context(1); next["service_instance"] = String(repeating: "9", count: 32)
        let current = try report(at: 1, receipt: receipt(request, "interrupted"), changes: ["control_context": next])
        XCTAssertTrue(current.canBeginRecovery(at: start.addingTimeInterval(1)))
    }

    func testReceiptBeforeTransportCompletionDoesNotAllowSecondDialog() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        XCTAssertNil(coordinator.begin(report: try report(), epoch: 4, now: start))
        for state in ["received", "checking", "passed"] {
            let status = try report(at: 1, receipt: receipt(request, state))
            coordinator.observe(status, epoch: 4, now: start.addingTimeInterval(1))
            XCTAssertEqual(coordinator.phase.rawValue, state)
            XCTAssertTrue(coordinator.authorizationInFlight)
            XCTAssertFalse(coordinator.canBegin(report: status, at: start.addingTimeInterval(1)))
        }
        coordinator.completed(.init(.unknown), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        XCTAssertFalse(coordinator.authorizationInFlight); XCTAssertEqual(coordinator.phase, .passed)
    }

    func testUnknownRetryUsesOriginalPairAndCancellationCannotEraseUncertainty() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        coordinator.completed(.init(.unknown), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        XCTAssertNil(coordinator.begin(report: try report(), epoch: 4, now: start))
        let retry = try XCTUnwrap(coordinator.retry(report: report(at: 1), epoch: 4, now: start.addingTimeInterval(1)))
        XCTAssertEqual(retry, request)
        coordinator.completed(.init(.cancelled), for: retry, executionID: coordinator.authorizationID!, epoch: 4)
        XCTAssertEqual(coordinator.phase, .unknown)
        let observed = try report(at: 2, receipt: receipt(request, "checking"))
        coordinator.observe(observed, epoch: 4, now: start.addingTimeInterval(2))
        XCTAssertEqual(coordinator.phase, .checking)
        XCTAssertFalse(coordinator.canRetry(report: observed, epoch: 4, at: start.addingTimeInterval(2)))
    }

    func testInitialCancellationIsTerminalAndDoesNotAutomaticallyRetry() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        let oldExecution = try XCTUnwrap(coordinator.authorizationID)
        coordinator.completed(.init(.cancelled), for: request, executionID: oldExecution, epoch: 4)
        XCTAssertEqual(coordinator.phase, .cancelled)
        coordinator.observe(try report(at: 1), epoch: 4, now: start.addingTimeInterval(1))
        XCTAssertEqual(coordinator.phase, .cancelled)
        XCTAssertNil(coordinator.retry(report: try report(at: 1), epoch: 4, now: start.addingTimeInterval(1)))
        let next = try XCTUnwrap(coordinator.begin(report: report(at: 1), epoch: 4, now: start.addingTimeInterval(1)))
        XCTAssertNotEqual(request.id, next.id)
        coordinator.completed(.init(.unknown), for: request, executionID: oldExecution, epoch: 4)
        XCTAssertTrue(coordinator.authorizationInFlight); XCTAssertEqual(coordinator.request, next)
    }

    func testOldAuthorizationCallbackCannotReleaseRetryOfSameRequest() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        let oldExecution = try XCTUnwrap(coordinator.authorizationID)
        coordinator.completed(.init(.unknown), for: request, executionID: oldExecution, epoch: 4)
        XCTAssertEqual(coordinator.retry(report: try report(at: 1), epoch: 4, now: start.addingTimeInterval(1)), request)
        let newExecution = try XCTUnwrap(coordinator.authorizationID)
        XCTAssertNotEqual(newExecution, oldExecution)
        coordinator.completed(.init(.cancelled), for: request, executionID: oldExecution, epoch: 4)
        XCTAssertTrue(coordinator.authorizationInFlight); XCTAssertEqual(coordinator.phase, .authorizing)
        coordinator.completed(.init(.cancelled), for: request, executionID: newExecution, epoch: 4)
        XCTAssertFalse(coordinator.authorizationInFlight); XCTAssertEqual(coordinator.phase, .unknown)
    }

    func testLostDaemonAfterAcknowledgedReceiptTimesOutWithoutInventingFailure() throws {
        for state in ["received", "checking"] {
            var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
            coordinator.completed(.init(.acknowledged), for: request, executionID: coordinator.authorizationID!, epoch: 4)
            coordinator.observe(try report(at: 1, receipt: receipt(request, state)), epoch: 4, now: start.addingTimeInterval(1))
            coordinator.observe(nil, epoch: 4, now: start.addingTimeInterval(101))
            XCTAssertEqual(coordinator.phase, .unknown); XCTAssertEqual(coordinator.request, request)
            XCTAssertFalse(coordinator.authorizationInFlight)
            let stillActive = try report(at: 101, receipt: receipt(request, state))
            coordinator.observe(stillActive, epoch: 4, now: start.addingTimeInterval(101))
            XCTAssertEqual(coordinator.phase, .unknown)
            XCTAssertNil(coordinator.begin(report: stillActive, epoch: 4, now: start.addingTimeInterval(101)))
            let expired = receipt(request, "failed", changes: ["reason": "request_expired",
                "finished_at": start.timeIntervalSince1970 + 100, "updated_at": start.timeIntervalSince1970 + 100])
            coordinator.observe(try report(at: 102, receipt: expired), epoch: 4, now: start.addingTimeInterval(102))
            XCTAssertEqual(coordinator.phase, .failed)
        }
    }

    func testChangedEpochOrInstallationCannotBeRevivedByDelayedResults() throws {
        for changed: String in ["epoch", "plan_sha256", "runtime_sha256", "service_instance"] {
            var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
            var binding = context()
            if changed != "epoch" { binding[changed] = String(repeating: "8", count: changed == "service_instance" ? 32 : 64) }
            coordinator.observe(try report(at: 1, changes: ["control_context": binding]),
                                epoch: changed == "epoch" ? 5 : 4, now: start.addingTimeInterval(1))
            XCTAssertEqual(coordinator.phase, .invalidated)
            XCTAssertTrue(coordinator.authorizationInFlight)
            coordinator.completed(.init(.acknowledged), for: request, executionID: coordinator.authorizationID!, epoch: 4)
            coordinator.observe(try report(at: 2, receipt: receipt(request)), epoch: 4, now: start.addingTimeInterval(2))
            XCTAssertEqual(coordinator.phase, .invalidated)
        }
    }

    func testForeignRequestCannotSatisfyAttemptAndStaleReportsCannotRollBack() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        coordinator.completed(.init(.acknowledged), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        let foreign = receipt(request, changes: ["request_id": String(repeating: "8", count: 32)])
        coordinator.observe(try report(at: 1, receipt: foreign), epoch: 4, now: start.addingTimeInterval(1))
        XCTAssertEqual(coordinator.phase, .invalidated)
        for key in ["plan_sha256", "runtime_sha256", "service_instance"] {
            let value = receipt(request, changes: [key: String(repeating: "8", count: key == "service_instance" ? 32 : 64)])
            let decoded = try JSONDecoder().decode(PFRecoveryReceipt.self, from: JSONSerialization.data(withJSONObject: value))
            XCTAssertNil(decoded.correlatedStatus(for: request))
        }
        coordinator = PFRecoveryCoordinator(); let next = try begin(&coordinator)
        let current = try report(at: 2, receipt: receipt(next, "checking"))
        coordinator.observe(current, epoch: 4, now: start.addingTimeInterval(2))
        coordinator.observe(try report(at: 1, receipt: receipt(next, "received")), epoch: 4, now: start.addingTimeInterval(2))
        XCTAssertEqual(coordinator.phase, .checking)
    }

    func testHistoricalPassExpiryAndFaultNeverBecomeLaunchPermission() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        let pass = try report(at: 1, receipt: receipt(request), changes: ["status": "observed", "evidence_fresh": true,
            "manual_recheck_required": false, "recovery_current": true, "evidence_expires_at": start.timeIntervalSince1970 + 20])
        coordinator.observe(pass, epoch: 4, now: start.addingTimeInterval(1))
        XCTAssertTrue(coordinator.lines(report: pass, at: start.addingTimeInterval(1)).joined().contains("证据当前有效"))
        XCTAssertFalse(coordinator.lines(report: pass, at: start.addingTimeInterval(21)).joined().contains("证据当前有效"))
        let fault = try report(at: 2, receipt: receipt(request), changes: ["recovery_current": true])
        XCTAssertTrue(coordinator.lines(report: fault, at: start.addingTimeInterval(2)).joined().contains("历史通过"))
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    func testUnsettledAuthorizationKeepsBusyAndAwaitingTimeoutKeepsIdentity() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        coordinator.completed(.init(.unknown, settled: false), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        XCTAssertTrue(coordinator.authorizationInFlight)
        XCTAssertFalse(coordinator.canRetry(report: try report(), epoch: 4, at: start))
        coordinator.completed(.init(.acknowledged), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        coordinator.observe(nil, epoch: 4, now: start.addingTimeInterval(241))
        XCTAssertEqual(coordinator.phase, .unknown); XCTAssertEqual(coordinator.request, request)
        coordinator.observe(nil, epoch: 4, now: start.addingTimeInterval(-1))
        XCTAssertEqual(coordinator.phase, .invalidated)
    }

    func testConnectorBindingRequiresSettledCurrentMatchingPassAndOriginalExpiry() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        let now = start.addingTimeInterval(1)
        let healthy: [String: Any] = ["status": "observed", "evidence_fresh": true,
            "manual_recheck_required": false, "recovery_current": true,
            "evidence_expires_at": start.timeIntervalSince1970 + 30]
        let pass = try report(at: 1, receipt: receipt(request), changes: healthy)
        coordinator.observe(pass, epoch: 4, now: now)
        XCTAssertNil(coordinator.connectorBinding(report: pass, at: now))
        coordinator.completed(.init(.acknowledged), for: request, executionID: coordinator.authorizationID!, epoch: 4)
        let binding = try XCTUnwrap(coordinator.connectorBinding(report: pass, at: now))
        XCTAssertEqual(pass.connectorExpiry(matching: binding, at: now), start.timeIntervalSince1970 + 20)
        let extended = try report(at: 21, receipt: receipt(request), changes: healthy)
        XCTAssertNil(extended.connectorExpiry(matching: binding, at: start.addingTimeInterval(21)))
        for alteration: [String: Any] in [["generation": String(repeating: "e", count: 32)],
            ["request_id": String(repeating: "e", count: 32)], ["revision": 2],
            ["runtime_sha256": String(repeating: "e", count: 64)],
            ["service_instance": String(repeating: "e", count: 32)]] {
            let different = try report(at: 1, receipt: receipt(request, changes: alteration), changes: healthy)
            XCTAssertNil(different.connectorExpiry(matching: binding, at: now))
        }
        for alteration: [String: Any] in [["recovery_current": false], ["service_running": false],
            ["rules_observed": false], ["manual_recheck_required": true],
            ["evidence_expires_at": start.timeIntervalSince1970 + 1]] {
            var changed = healthy; changed.merge(alteration) { _, new in new }
            let rejected = try report(at: 1, receipt: receipt(request), changes: changed)
            XCTAssertNil(rejected.connectorExpiry(matching: binding, at: now))
        }
        coordinator.invalidate()
        XCTAssertNil(coordinator.connectorBinding(report: pass, at: now))
    }

    func testAuthorizationFramesRequireMatchingReceiptAndNeverInferPassFromExit() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        func frame(_ change: [String: Any] = [:]) throws -> Data {
            var payload: [String: Any] = ["reason": "recheck_requested", "launch_authorized": false,
                "protection_verified": false, "recovery": receipt(request, "received")]
            payload.merge(change) { _, new in new }
            var result = Data("PF_CONTROL_JSON_V1\n".utf8)
            result.append(try JSONSerialization.data(withJSONObject: payload)); result.append(10); return result
        }
        XCTAssertEqual(PFAuthorizationTransport.decode(try frame(), for: request), .acknowledged)
        for value in [Data(), Data("PF_CONTROL_ERROR_V1\n".utf8), Data("PF_CONTROL_CANCELLED_V1\nextra".utf8),
            try frame(["launch_authorized": true]), try frame(["protection_verified": 0]),
            try frame(["reason": "arbitrary"]), try frame(["recovery": receipt(request, changes: ["request_id": String(repeating: "8", count: 32)])]),
            try frame() + Data("{}".utf8), Data(repeating: 65, count: 16_385)] {
            XCTAssertEqual(PFAuthorizationTransport.decode(value, for: request), .unknown)
        }
        XCTAssertEqual(PFAuthorizationTransport.decode(Data("PF_CONTROL_CANCELLED_V1\n".utf8), for: request), .cancelled)
        let script = PFAuthorizationTransport.script(for: request)
        XCTAssertTrue(script.contains("/usr/bin/python3 -I -S -B '/Library/Application Support/Claude Launcher PF/pf_control.py'"))
        XCTAssertTrue(script.contains("--request-id " + request.id)); XCTAssertFalse(script.contains("sudo"))
    }

    func testBoundedRunnerHandlesOutputExitTimeoutAndHeldPipesWithoutAuthorization() {
        func run(_ source: String, timeout: Double = 2) -> PFAuthorizationTransport.Capture {
            PFAuthorizationTransport.capture(executable: "/usr/bin/python3", arguments: ["-I", "-S", "-B", "-c", source], timeout: timeout)
        }
        let complete = run("import sys; print('fixture'); sys.stderr.write('hidden-secret')")
        XCTAssertTrue(complete.complete); XCTAssertTrue(complete.settled)
        XCTAssertEqual(String(decoding: complete.data, as: UTF8.self), "fixture\n")
        let noOutput = run("pass"); XCTAssertTrue(noOutput.complete); XCTAssertTrue(noOutput.data.isEmpty)
        for source in ["raise SystemExit(3)", "print('x'*20000)", "import os\nwhile True: os.write(1,b'x'*4096)",
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(3)",
            "import os,time\nif os.fork()==0: time.sleep(0.8)"] {
            let before = ProcessInfo.processInfo.systemUptime
            let output = run(source, timeout: 0.15)
            XCTAssertFalse(output.complete); XCTAssertTrue(output.settled); XCTAssertTrue(output.data.isEmpty)
            XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - before, 2)
        }
        let missing = PFAuthorizationTransport.capture(executable: "/no/such/program", arguments: [], timeout: 1)
        XCTAssertFalse(missing.complete); XCTAssertTrue(missing.settled)
    }

    func testGeneratedAppleScriptCompilesWithoutExecutingAuthorizationBranch() throws {
        var coordinator = PFRecoveryCoordinator(); let request = try begin(&coordinator)
        // Parse the full production script in an unreachable branch. No auth call executes.
        let source = "if false then\n" + PFAuthorizationTransport.script(for: request) + "\nend if\nreturn \"fixture\""
        let output = PFAuthorizationTransport.capture(executable: "/usr/bin/osascript", arguments: ["-e", source], timeout: 5)
        XCTAssertTrue(output.complete); XCTAssertTrue(output.settled)
        XCTAssertEqual(String(decoding: output.data, as: UTF8.self), "fixture\n")
    }
}
