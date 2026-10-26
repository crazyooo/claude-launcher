import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemCoreChildTests: XCTestCase {
    private enum ReachedExec: Error { case simulated }
    private func exercise(_ scenario: String) throws -> (executions: Int, receives: Int) {
        let f = try RouterSystemDispatchFixture()
        let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
        try f.applying(fence)
        try f.baseline.claim(intent: f.intent, fence: fence, verifyApplying: {})
        if scenario == "already_saved" { try f.record(f.work) }
        var reads = 0, identities = 0, stages = 0, executions = 0, receives = 0
        let operations = RouterSystemCoreChild.Operations(load: { deadline in
            reads += 1
            XCTAssertEqual(deadline, reads == 1 ? 14 : f.intent.deadlineUptime)
            if scenario == "initial_read_late" && reads == 1 { f.uptime = 14 }
            var state = try f.journal.load()
            if scenario == "foreign_installation" { state.installation = .init(id: UUID(), ownerUID: 501) }
            if scenario == "changed_phase" && reads >= 2 { state.phase = .fault; state.reason = "execution_outcome_unconfirmed" }
            if scenario == "changed_revision" && reads >= 3 { state.revision = UUID() }
            return state
        }, clock: { f.clock }, identity: { observed in
            XCTAssertEqual(observed, fence); identities += 1
            if scenario == "changed_identity" && identities > 1 { throw RouterSystemError.ownershipUnknown }
            return f.work
        }, claim: { try f.baseline.verifyClaim(intent: $0, fence: $1) }, stage: { intent, digest in
            XCTAssertEqual(intent, f.intent); XCTAssertEqual(digest, f.digest); stages += 1
            if scenario == "stage_changed" { throw RouterSystemError.ownershipUnknown }
            if scenario == "late_stage" && stages == 2 { f.uptime = 70; f.seconds = 1060 }
        }, receive: { id, deadline in
            receives += 1
            XCTAssertEqual(id, f.intent.id); XCTAssertEqual(deadline, f.intent.deadlineUptime)
            if scenario == "no_permit" { throw RouterSystemError.invalidRequest }
            if scenario != "missing_work" && scenario != "already_saved" { try f.record(f.work) }
            if scenario == "late_gate" { f.uptime = 70; f.seconds = 1060 }
        }, prepareExec: { id in
            XCTAssertEqual(id, f.intent.id)
            if scenario == "prepare_failed" { throw RouterSystemError.operationUnsettled }
            if scenario == "clock_reversed" { f.seconds = 999 }
        }, execute: {
            executions += 1
            throw ReachedExec.simulated // Never creates a process, opens a controller or enables TUN.
        })
        do {
            try RouterSystemCoreChild.fixture(instance: f.intent.id, installation: f.identity, operations: operations)
        } catch ReachedExec.simulated {
            XCTAssertTrue(["nil_then_saved", "already_saved"].contains(scenario), scenario)
        } catch {
            XCTAssertFalse(["nil_then_saved", "already_saved"].contains(scenario), "\(scenario): \(error)")
        }
        return (executions, receives)
    }
    func testGateBeforeWorkAndAlreadySavedWorkBothRequireExactPostGateRecord() throws {
        for scenario in ["nil_then_saved", "already_saved"] {
            let result = try exercise(scenario)
            XCTAssertEqual(result.executions, 1); XCTAssertEqual(result.receives, 1)
        }
    }
    func testPostGateFailuresNeverExecuteOrRequestAnotherPermit() throws {
        for scenario in ["changed_phase", "changed_revision", "changed_identity", "stage_changed", "late_stage",
                         "no_permit", "missing_work", "late_gate", "prepare_failed", "clock_reversed", "foreign_installation", "initial_read_late"] {
            let result = try exercise(scenario)
            XCTAssertEqual(result.executions, 0, scenario)
            XCTAssertEqual(result.receives, ["foreign_installation", "initial_read_late"].contains(scenario) ? 0 : 1, scenario)
        }
    }
    func testPrivateEntryAcceptsOnlyCanonicalInstanceAndNeverRunsAsNormalUser() throws {
        let id = UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!, args = ["--core-child", id.uuidString.lowercased()]
        XCTAssertEqual(try RouterSystemCoreChild.instance(args), id)
        for invalid in [[], ["--host"], ["--core-child", id.uuidString], args + ["--config", "/tmp/config"], ["--core-child", "invalid"]] {
            XCTAssertThrowsError(try RouterSystemCoreChild.instance(invalid))
        }
        XCTAssertThrowsError(try RouterSystemCoreChild.run(args))
    }
    func testClaimVerificationRequiresExactDurableReceiptAndSurvivesHistoricalRead() throws {
        let f = try RouterSystemDispatchFixture()
        let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
        XCTAssertThrowsError(try f.baseline.verifyClaim(intent: f.intent, fence: fence))
        try f.baseline.claim(intent: f.intent, fence: fence, verifyApplying: {})
        try f.baseline.verifyClaim(intent: f.intent, fence: fence)
        f.uptime = 100; f.seconds = 1100
        XCTAssertNoThrow(try f.baseline.verifyClaim(intent: f.intent, fence: fence)) // Evidence, not renewed authorization.
        let path = f.url.appendingPathComponent("stage-" + f.intent.id.uuidString.lowercased()).appendingPathComponent("dispatch-claim.json")
        let original = try Data(contentsOf: path)
        for bytes in [Data(), Data("{}".utf8), original + Data("\n".utf8)] {
            try bytes.write(to: path)
            XCTAssertThrowsError(try f.baseline.verifyClaim(intent: f.intent, fence: fence))
            XCTAssertThrowsError(try f.baseline.requireUnclaimed(f.intent.id))
        }
    }
}
