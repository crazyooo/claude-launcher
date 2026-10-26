import XCTest
@testable import RoutingCore

final class RouterSystemHostTests: XCTestCase {
    private func provider(_ f: RouterSystemDispatchFixture, beforeLoad: (() -> Void)? = nil) -> RouterSystemProvider {
        RouterSystemProvider(effects: .init(clock: { f.clock }, load: { beforeLoad?(); return try f.journal.load() },
            save: { try f.journal.save($0, expecting: $1) }, network: { throw RouterSystemError.networkConflict },
            stage: { _, _ in throw RouterSystemError.configurationRejected },
            prepareDispatch: { _, _ in throw RouterSystemError.operationUnsettled },
            start: { _, _, _, _ in XCTFail("unexpected execution"); throw RouterSystemError.operationUnsettled },
            observe: { _ in throw RouterSystemError.operationUnsettled }, stop: { _ in XCTFail("unexpected signal") },
            cleanup: { _ in throw RouterSystemError.cleanupUnproven }))
    }
    func testApplyingWritesKeepOriginalPermissionAndHistoricalWritesDoNotRenewIt() throws {
        let f = try RouterSystemDispatchFixture(), d = try f.dispatcher()
        let fence = try d.prepare(f.intent, digest: f.digest); try f.applying(fence)
        let state = try f.journal.load()
        XCTAssertEqual(try RouterSystemHost.saveDeadline(state, now: f.clock), 70)
        f.uptime = 70; f.seconds = 1060
        XCTAssertThrowsError(try RouterSystemHost.saveDeadline(state, now: f.clock))
        var fault = state; fault.phase = .fault; fault.reason = "execution_outcome_unconfirmed"
        XCTAssertEqual(try RouterSystemHost.saveDeadline(fault, now: f.clock), 72)
        XCTAssertEqual(fault.intent?.deadlineUptime, 70)
        let rebooted = RouterSystemClock(bootID: UUID(), uptime: 12, date: Date(timeIntervalSince1970: 1002))
        XCTAssertThrowsError(try RouterSystemHost.saveDeadline(state, now: rebooted))
        let rollback = RouterSystemClock(bootID: f.boot, uptime: 12, date: Date(timeIntervalSince1970: 999))
        XCTAssertThrowsError(try RouterSystemHost.saveDeadline(state, now: rollback))
    }
    func testEndpointRetiresOnlyConfirmedSlotBeforeProviderAndPreservesClaim() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
        try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record)
        try dispatch.stop(fence)
        try f.change { $0.phase = .stopped; $0.reason = "owned_cleanup_confirmed" }
        let lease = try RouterSystemHostLease.acquire(in: f.directory)
        let endpoint = RouterSystemHostEndpoint(directory: f.directory, lease: lease, journal: f.journal, baselines: f.baseline, dispatch: dispatch,
            provider: provider(f, beforeLoad: { XCTAssertEqual(dispatch.localSettlement(fence), .unknown) }))
        XCTAssertEqual(try endpoint.handle(.status(id: f.intent.id)).phase, "stopped")
        XCTAssertThrowsError(try endpoint.handle(.prepare(id: f.intent.id, plan: f.intent.plan, profile: f.intent.profile)))
        XCTAssertThrowsError(try f.baseline.requireUnclaimed(f.intent.id))
        XCTAssertEqual(f.spawns, 1); XCTAssertEqual(f.child.grants, 1)
        let restarted = try f.dispatcher()
        XCTAssertNoThrow(try restarted.retireAfterConfirmedCleanup(fence))
        XCTAssertThrowsError(try restarted.stop(fence))
    }
    func testUnknownRunningSlotCannotBeDiscardedByFalseStoppedRecord() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
        try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record)
        try f.change { $0.phase = .stopped; $0.reason = "owned_cleanup_confirmed" }
        let endpoint = RouterSystemHostEndpoint(directory: f.directory, lease: try .acquire(in: f.directory), journal: f.journal,
            baselines: f.baseline, dispatch: dispatch, provider: provider(f, beforeLoad: { XCTFail("provider must not run") }))
        XCTAssertThrowsError(try endpoint.handle(.status(id: f.intent.id)))
        XCTAssertEqual(dispatch.localSettlement(fence), .running)
        XCTAssertTrue(f.child.signals.isEmpty)
    }
    func testLeaseReplacementBlocksRequestsBeforeProvider() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher(), lease = try RouterSystemHostLease.acquire(in: f.directory)
        let endpoint = RouterSystemHostEndpoint(directory: f.directory, lease: lease, journal: f.journal, baselines: f.baseline,
            dispatch: dispatch, provider: provider(f, beforeLoad: { XCTFail("provider must not run") }))
        try FileManager.default.moveItem(at: f.url.appendingPathComponent("host.lock"), to: f.url.appendingPathComponent("old-host.lock"))
        XCTAssertThrowsError(try endpoint.handle(.status(id: nil)))
        XCTAssertEqual(f.spawns, 0)
    }
    func testInstallerOperationGateBlocksRequestsBeforeProviderAndReleasesForRetry() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        var queries = 0
        let endpoint = RouterSystemHostEndpoint(directory: f.directory, lease: try .acquire(in: f.directory),
            journal: f.journal, baselines: f.baseline, dispatch: dispatch, provider: provider(f, beforeLoad: { queries += 1 }))
        var maintenance: RouterSystemHostLease? = try .acquire(in: f.directory, purpose: .operation)
        try maintenance?.verify()
        XCTAssertThrowsError(try endpoint.handle(.status(id: nil)))
        XCTAssertThrowsError(try endpoint.handle(.apply(id: f.intent.id, credentials: [])))
        XCTAssertEqual(queries, 0); XCTAssertEqual(f.spawns, 0)
        maintenance = nil
        XCTAssertEqual(try endpoint.handle(.status(id: nil)).phase, "prepared")
        XCTAssertEqual(queries, 1)
    }

    func testOuterEndpointLockRejectsConcurrentRequests() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let completed = expectation(description: "first query")
        let endpoint = RouterSystemHostEndpoint(directory: f.directory, lease: try .acquire(in: f.directory), journal: f.journal,
            baselines: f.baseline, dispatch: dispatch, provider: provider(f, beforeLoad: {
                do {
                    _ = try RouterSystemHostLease.acquire(in: f.directory, purpose: .operation)
                    XCTFail("maintenance must not enter during a request")
                } catch { XCTAssertEqual(error as? RouterSystemError, .operationUnsettled) }
                entered.signal(); XCTAssertEqual(release.wait(timeout: .now() + 2), .success)
            }))
        DispatchQueue.global().async {
            do { _ = try endpoint.handle(.status(id: nil)) }
            catch { XCTFail("first query failed") }
            completed.fulfill()
        }
        XCTAssertEqual(entered.wait(timeout: .now() + 2), .success)
        XCTAssertThrowsError(try endpoint.handle(.status(id: nil))) { XCTAssertEqual($0 as? RouterSystemError, .operationUnsettled) }
        release.signal(); wait(for: [completed], timeout: 3)
        XCTAssertEqual(f.spawns, 0)
    }
}
