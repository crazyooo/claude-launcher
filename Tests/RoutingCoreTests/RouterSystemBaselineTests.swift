import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemDispatchFixture {
    let identity = RouterSystemInstallationIdentity(id: UUID(), ownerUID: 501)
    let boot: UUID
    let url: URL
    let directory: RouterSystemDirectory
    let journal: RouterSystemJournalStore
    var uptime: TimeInterval = 12
    var seconds: TimeInterval = 1002
    var syncFails = false
    var dns = "DNS configuration\nresolver #1\n  nameserver[0] : 192.0.2.53\n  flags : Request A records\n  reach : 0x00000002 (Reachable)\n"
    var v4 = "Internet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGScg en0\n"
    let v6 = "Internet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::1 UGc en0\n"
    let digest = String(repeating: "b", count: 64)
    var captureCount = 0, spawns = 0
    var captureHook: ((Int) throws -> Void)?
    var identifyFails = false, spawnFails = false
    var execReads = 0
    var execHook: ((Int) throws -> Bool)?
    let child = Child()
    var clock: RouterSystemClock { .init(bootID: boot, uptime: uptime, date: Date(timeIntervalSince1970: seconds)) }
    var host: RouterSystemWork { .init(bootID: boot, pid: 700, birthSeconds: 900, birthMicroseconds: 12) }
    var work: RouterSystemWork { .init(bootID: boot, pid: 701, birthSeconds: 1001, birthMicroseconds: 13) }
    let intent: RouterSystemIntent
    var baseline: RouterSystemBaselineStore!
    var devices: [RouterSystemInterfaceSnapshot.Interface] = [
        .init(name: "en0", index: 4, flags: UInt32(IFF_UP), mtu: 1500,
              addresses: [.init(family: AF_INET, address: "192.0.2.2", netmask: "255.255.255.0", destination: nil)])]
    init(boot: UUID = UUID()) throws {
        self.boot = boot
        url = FileManager.default.temporaryDirectory.appendingPathComponent("router-dispatch-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(fd) }
        directory = try .fixture(directoryFD: fd, owner: getuid())
        journal = try .init(directory: directory, installation: identity)
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct), profile = RouterSystemProfile(resolver: .quad9)
        let issued = RouterSystemClock(bootID: boot, uptime: 10, date: Date(timeIntervalSince1970: 1000))
        intent = .init(id: UUID(), plan: plan, profile: profile, digest: try RouterSystemCompiler.digest(plan: plan, profile: profile),
            networkFingerprint: String(repeating: "a", count: 64), issued: issued, expiresAt: issued.date.addingTimeInterval(60), deadlineUptime: 70)
        try journal.initialize()
        try change { $0.intent = self.intent; $0.phase = .prepared; $0.reason = "prepared_not_applied" }
        _ = try directory.createDirectory("stage-" + intent.id.uuidString.lowercased())
        baseline = try .fixture(state: directory, identity: identity, clock: { self.clock }, synchronize: { self.syncFails ? -1 : fsync($0) })
        child.instance = intent.id
    }
    func snapshot(captured: RouterSystemClock? = nil) -> RouterSystemBaselineSnapshot {
        .init(captured: captured ?? clock, networkFingerprint: intent.networkFingerprint, interfaces: devices, routesIPv4: v4, routesIPv6: v6, dns: dns)
    }
    func change(_ edit: (inout RouterSystemJournal) -> Void) throws {
        var state = try journal.load(); let revision = state.revision
        edit(&state); state.revision = UUID()
        try journal.save(state, expecting: revision)
    }
    func applying(_ fence: RouterSystemDispatchFence) throws {
        try change { $0.dispatch = fence; $0.configurationDigest = digest; $0.phase = .applying; $0.reason = "execution_pending" }
    }
    func record(_ work: RouterSystemWork) throws { try change { $0.work = work } }
    func dispatcher() throws -> RouterSystemDispatch {
        try .fixture(identity: identity, host: host, journal: journal, baselines: baseline,
            operations: .init(clock: { self.clock }, currentHost: { self.host }, verifyCode: {}, verifyStage: { _, _ in },
                capture: {
                    self.captureCount += 1; try self.captureHook?(self.captureCount)
                    return self.snapshot()
                }, spawn: { _ in
                    self.spawns += 1
                    if self.spawnFails { throw RouterSystemError.operationUnsettled }
                    return self.child
                }, identify: { _, _ in
                    if self.identifyFails { throw RouterSystemError.ownershipUnknown }
                    return self.work
                }, coreExecObserved: { _, _ in
                    self.execReads += 1
                    return try self.execHook?(self.execReads) ?? true
                }, loadForExecution: { deadline in
                    XCTAssertEqual(deadline, self.intent.deadlineUptime)
                    return try self.journal.load()
                }, waitForExecPoll: { self.uptime += 1; self.seconds += 1 }))
    }
    final class Child: RouterSystemDispatchChild {
        var instance = UUID()
        let pid: Int32 = 701
        var observation: RouterOwnedChild.Observation = .running
        var gatesClosed = 0, grants = 0
        var grantFails = false
        var signals: [Int32] = []
        func observe() -> RouterOwnedChild.Observation { observation }
        func closeGate() { gatesClosed += 1 }
        func releaseGate() throws {
            grants += 1
            if grantFails { throw RouterSystemError.operationUnsettled }
        }
        func signal(_ number: Int32) throws { signals.append(number); observation = .exited(0) }
        func waitUntil(_ deadline: TimeInterval) -> RouterOwnedChild.Observation { observation }
    }
}

final class RouterSystemBaselineTests: XCTestCase {
    func testImmutableReceiptReopensAndHistoricalReadSurvivesExpiry() throws {
        let f = try RouterSystemDispatchFixture()
        let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
        f.uptime = 100; f.seconds = 1100
        let reopened = try RouterSystemBaselineStore.fixture(state: f.directory, identity: f.identity, clock: { f.clock })
        let receipt = try reopened.read(intent: f.intent, fence: fence)
        XCTAssertEqual(receipt.fence(digest: fence.baselineDigest), fence)
        XCTAssertEqual(receipt.snapshot.interfaces, f.devices)
        XCTAssertThrowsError(try reopened.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot()))
        let foreign = try RouterSystemBaselineStore.fixture(state: f.directory, identity: .init(id: UUID(), ownerUID: 501), clock: { f.clock })
        XCTAssertThrowsError(try foreign.read(intent: f.intent, fence: fence))
    }
    func testFutureSamplesAndPostWriteExpiryCannotReturnFence() throws {
        for future in [RouterSystemClock(bootID: UUID(), uptime: 12, date: Date(timeIntervalSince1970: 1002)),
                       .init(bootID: UUID(), uptime: 13, date: Date(timeIntervalSince1970: 1002))] {
            let f = try RouterSystemDispatchFixture()
            let captured = RouterSystemClock(bootID: f.boot, uptime: future.uptime, date: future.date)
            let sample = f.snapshot(captured: captured.uptime == 12 ? .init(bootID: f.boot, uptime: 12, date: Date(timeIntervalSince1970: 1003)) : captured)
            XCTAssertThrowsError(try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: sample))
        }
        let f = try RouterSystemDispatchFixture()
        let store = try RouterSystemBaselineStore.fixture(state: f.directory, identity: f.identity, clock: { f.clock }, synchronize: { fd in
            f.uptime = 70; f.seconds = 1060
            return fsync(fd)
        })
        XCTAssertThrowsError(try store.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot()))
        let files = try FileManager.default.contentsOfDirectory(atPath: f.url.appendingPathComponent("stage-" + f.intent.id.uuidString.lowercased()).path)
        XCTAssertEqual(files.filter { $0.hasPrefix("baseline-") }.count, 1)
    }
    func testFailedSynchronizationPreservesOriginalEvidenceAndRetryUsesNewFile() throws {
        let f = try RouterSystemDispatchFixture(); f.syncFails = true
        XCTAssertThrowsError(try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot()))
        let directory = f.url.appendingPathComponent("stage-" + f.intent.id.uuidString.lowercased())
        let original = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first)
        let bytes = try Data(contentsOf: original)
        f.syncFails = false
        _ = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
        XCTAssertEqual(try Data(contentsOf: original), bytes)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: directory.path).count, 2)
    }
    func testUnknownNestedFieldsRejectedEvenWithMatchingDigest() throws {
        let f = try RouterSystemDispatchFixture()
        let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
        let receipt = try f.baseline.read(intent: f.intent, fence: fence)
        let file = f.url.appendingPathComponent("stage-" + f.intent.id.uuidString.lowercased()).appendingPathComponent("baseline-" + fence.baselineID.uuidString.lowercased() + ".json")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        var snapshot = try XCTUnwrap(object["snapshot"] as? [String: Any]); snapshot["unowned"] = true; object["snapshot"] = snapshot
        let bytes = try JSONSerialization.data(withJSONObject: object); try bytes.write(to: file)
        XCTAssertThrowsError(try f.baseline.read(intent: f.intent, fence: receipt.fence(digest: RouterSystemObservation.hash(bytes))))
    }
    func testClaimIsConsumedAcrossStoreReopensAndFailedFinalCheck() throws {
        for fail in [false, true] {
            let f = try RouterSystemDispatchFixture()
            let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
            var validations = 0
            let claim = {
                try f.baseline.claim(intent: f.intent, fence: fence) {
                    validations += 1
                    if fail && validations == 2 { throw RouterSystemError.conflict }
                }
            }
            if fail { XCTAssertThrowsError(try claim()) } else { XCTAssertNoThrow(try claim()) }
            XCTAssertEqual(validations, 2)
            let restarted = try RouterSystemBaselineStore.fixture(state: f.directory, identity: f.identity, clock: { f.clock })
            XCTAssertThrowsError(try restarted.requireUnclaimed(f.intent.id))
            XCTAssertThrowsError(try restarted.claim(intent: f.intent, fence: fence, verifyApplying: {}))
            XCTAssertThrowsError(try restarted.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot()))
        }
    }
    func testPartialClaimAndClaimSyncFailureCannotBeRetried() throws {
        for partial in [false, true] {
            let f = try RouterSystemDispatchFixture()
            let fence = try f.baseline.create(intent: f.intent, configurationDigest: f.digest, host: f.host, snapshot: f.snapshot())
            if partial {
                try f.directory.child("stage-" + f.intent.id.uuidString.lowercased()).create("dispatch-claim.json", data: Data())
            } else { f.syncFails = true }
            XCTAssertThrowsError(try f.baseline.claim(intent: f.intent, fence: fence, verifyApplying: {}))
            f.syncFails = false
            XCTAssertThrowsError(try f.baseline.claim(intent: f.intent, fence: fence, verifyApplying: {}))
        }
    }
}

final class RouterSystemDispatchTests: XCTestCase {
    func testExecTransitionWaitsWithoutReleasingAnotherGate() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
        f.execHook = { count in
            XCTAssertEqual(try f.journal.load().phase, .applying)
            XCTAssertEqual(f.child.grants, 1)
            return count >= 3
        }
        try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record)
        XCTAssertEqual(f.execReads, 4); XCTAssertEqual(f.child.grants, 1)
    }
    func testExecTransitionFailuresRetainOwnerAndConsumedPermission() throws {
        for failure in ["timeout", "exited", "unknown", "revision", "late"] {
            let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
            let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
            f.execHook = { _ in
                if failure == "exited" { f.child.observation = .exited(0) }
                if failure == "unknown" { throw RouterSystemError.ownershipUnknown }
                if failure == "revision" { try f.change { _ in } }
                if failure == "late" { f.uptime = 70; f.seconds = 1060 }
                return failure != "timeout"
            }
            XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record), failure)
            XCTAssertEqual(f.spawns, 1); XCTAssertEqual(f.child.grants, 1); XCTAssertGreaterThan(f.child.gatesClosed, 0)
            XCTAssertEqual(dispatch.localSettlement(fence), failure == "exited" ? .exited : .running)
            XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record))
            XCTAssertThrowsError(try f.baseline.requireUnclaimed(f.intent.id))
        }
    }
    func testSaveWorkBeforeGrantAndNeverStartAgain() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
        try dispatch.start(f.intent, digest: f.digest, fence: fence) { work in
            XCTAssertEqual(f.child.grants, 0); XCTAssertEqual(f.spawns, 1)
            try f.record(work)
        }
        XCTAssertEqual(f.child.grants, 1); XCTAssertEqual(dispatch.localSettlement(fence), .running)
        XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record))
        XCTAssertEqual(f.spawns, 1)
    }
    func testUnclaimedReservationCanChangeButWrongJournalCannotSpawn() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let first = try dispatch.prepare(f.intent, digest: f.digest), second = try dispatch.prepare(f.intent, digest: f.digest)
        XCTAssertNotEqual(first.baselineID, second.baselineID)
        XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: second, recordWork: f.record))
        try f.applying(first)
        XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: second, recordWork: f.record))
        XCTAssertEqual(f.spawns, 0)
    }
    func testPostSpawnFailuresKeepOwnerAndCloseGate() throws {
        for failure in ["identity", "save", "save_after_write", "expiry", "network", "permit"] {
            let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
            let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
            f.identifyFails = failure == "identity"; f.child.grantFails = failure == "permit"
            f.captureHook = { count in
                if count == 3 && failure == "network" { f.dns = f.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54") }
            }
            XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence) { work in
                if failure == "save" { throw RouterSystemError.journalUnknown }
                try f.record(work)
                if failure == "save_after_write" { throw RouterSystemError.journalUnknown }
                if failure == "expiry" { f.uptime = 70; f.seconds = 1060 }
            }, failure)
            XCTAssertEqual(f.spawns, 1); XCTAssertGreaterThan(f.child.gatesClosed, 0)
            XCTAssertEqual(f.child.grants, failure == "permit" ? 1 : 0)
            XCTAssertEqual(dispatch.localSettlement(fence), .running)
            XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record))
            try dispatch.stop(fence)
            XCTAssertEqual(f.child.signals, [SIGTERM]); XCTAssertEqual(dispatch.localSettlement(fence), .exited)
        }
    }
    func testExplicitSpawnFailureConsumesIdentityWithoutCreatingOwner() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence); f.spawnFails = true
        XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record))
        XCTAssertEqual(dispatch.localSettlement(fence), .neverSpawned)
        try dispatch.stop(fence); XCTAssertTrue(f.child.signals.isEmpty)
        XCTAssertThrowsError(try f.baseline.requireUnclaimed(f.intent.id))
    }
    func testRestartHasNoHistoricalSignalOwnerAndRetirementRequiresConfirmedCleanup() throws {
        let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
        let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
        try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record)
        let restarted = try f.dispatcher()
        XCTAssertEqual(restarted.localSettlement(fence), .unknown)
        XCTAssertThrowsError(try restarted.stop(fence)); XCTAssertTrue(f.child.signals.isEmpty)
        try dispatch.stop(fence)
        XCTAssertThrowsError(try dispatch.retireAfterConfirmedCleanup(fence))
        try f.change { $0.phase = .stopped; $0.reason = "owned_cleanup_confirmed" }
        try dispatch.retireAfterConfirmedCleanup(fence)
        XCTAssertEqual(dispatch.localSettlement(fence), .unknown)
        try f.change { $0.dispatch = nil; $0.work = nil; $0.configurationDigest = nil; $0.phase = .prepared; $0.reason = "prepared_not_applied" }
        XCTAssertThrowsError(try restarted.prepare(f.intent, digest: f.digest))
    }
    func testChangedEnvironmentAndExpiredClaimNeverSpawn() throws {
        for expiration in [false, true] {
            let f = try RouterSystemDispatchFixture(), dispatch = try f.dispatcher()
            let fence = try dispatch.prepare(f.intent, digest: f.digest); try f.applying(fence)
            if expiration { f.uptime = 70; f.seconds = 1060 }
            else { f.dns = f.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54") }
            XCTAssertThrowsError(try dispatch.start(f.intent, digest: f.digest, fence: fence, recordWork: f.record))
            XCTAssertEqual(f.spawns, 0); XCTAssertEqual(f.child.grants, 0)
        }
    }
}
