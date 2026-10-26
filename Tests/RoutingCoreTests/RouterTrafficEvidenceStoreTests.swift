import XCTest
import Darwin
@testable import RoutingCore

final class RouterTrafficEvidenceStoreTests: XCTestCase {
    struct Fixture {
        let rootURL: URL
        let root: RouterSystemDirectory
        let stage: RouterSystemStage
        let source: RouterSystemStage.EvidenceSource
        var stageURL: URL { rootURL.appendingPathComponent("stage-" + source.intent.id.uuidString.lowercased()) }
    }
    func fixture() throws -> Fixture {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("traffic-history-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(fd) }
        let root = try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid())
        let identity = RouterSystemInstallationIdentity(id: UUID(), ownerUID: 501)
        let clock = RouterSystemClock(bootID: UUID(), uptime: 1, date: Date(timeIntervalSince1970: 1_000))
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct), profile = RouterSystemProfile(resolver: .quad9)
        let intent = RouterSystemIntent(id: UUID(), plan: plan, profile: profile,
            digest: try RouterSystemCompiler.digest(plan: plan, profile: profile),
            networkFingerprint: String(repeating: "a", count: 64), issued: clock,
            expiresAt: clock.date.addingTimeInterval(60), deadlineUptime: 61)
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity,
            check: { _ in .init(exitCode: 0, timedOut: false, settled: true) })
        let digest = try stage.stage(intent, credentials: [:])
        return .init(rootURL: url, root: root, stage: stage,
                     source: try stage.evidenceSource(intent, configurationDigest: digest))
    }
    func receipt(_ source: RouterSystemStage.EvidenceSource, session: UUID = UUID(), end: Double = 120) -> RouterTrafficReceipt {
        let binding = RouterTrafficBinding(phase: .active, installation: source.installation,
            instance: source.intent.id, revision: UUID(),
            work: .init(bootID: source.intent.issued.bootID, pid: 999, birthSeconds: 1_000, birthMicroseconds: 0),
            planDigest: source.intent.digest, configurationDigest: source.configurationDigest,
            stageReceiptDigest: source.receiptDigest, baselineID: UUID(), baselineDigest: String(repeating: "b", count: 64),
            networkFingerprint: String(repeating: "c", count: 64), coreSHA256: RouterCoreRelease.executableSHA256,
            coreVersion: RouterCoreRelease.version, compilerPolicy: RouterSystemCompiler.policyVersion)
        return .init(version: 1, coveragePolicy: 1, session: session, before: binding, after: binding,
            interval: .init(start: .init(bootID: binding.work.bootID, uptime: 100, date: Date(timeIntervalSince1970: 2_000)),
                end: .init(bootID: binding.work.bootID, uptime: end, date: Date(timeIntervalSince1970: 1_900 + end))),
            records: [])
    }
    func files(_ fixture: Fixture) throws -> [String: Data] {
        try Dictionary(uniqueKeysWithValues: FileManager.default.contentsOfDirectory(at: fixture.stageURL,
            includingPropertiesForKeys: nil).map { ($0.lastPathComponent, try Data(contentsOf: $0)) })
    }
    func replacePreservingOld(_ path: URL, bytes: Data) throws {
        try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("preserved"))
        try bytes.write(to: path, options: .withoutOverwriting)
        XCTAssertEqual(chmod(path.path, 0o600), 0)
    }

    func testReadAndInspectionAreReadOnlyAndNeverAuthorizeRollback() throws {
        let f = try fixture(), store = RouterTrafficEvidenceStore(source: f.source), record = receipt(f.source)
        let before = try files(f)
        XCTAssertTrue(try store.read().isEmpty)
        XCTAssertThrowsError(try store.inspect(session: UUID()))
        XCTAssertEqual(try files(f), before)
        try store.recordFixture(record)
        let saved = try files(f)
        XCTAssertEqual(try store.read().map(\.session), [record.session])
        let result = try store.inspect(session: record.session)
        XCTAssertFalse(result.canExecuteRollback); XCTAssertFalse(result.canPromoteAccepted)
        XCTAssertFalse(result.currentNetworkChecked); XCTAssertFalse(result.currentCleanupChecked)
        XCTAssertFalse(result.currentCredentialsChecked)
        XCTAssertEqual(result.assessment.status, "incomplete")
        let exported = try XCTUnwrap(JSONSerialization.jsonObject(with: RouterTrafficCodec.encode(result)) as? [String: Any])
        for key in ["canExecuteRollback", "canPromoteAccepted", "currentNetworkChecked",
                    "currentCleanupChecked", "currentCredentialsChecked"] {
            XCTAssertEqual(exported[key] as? Bool, false, key)
        }
        XCTAssertEqual(try files(f), saved)
        // The stage is historical: its expired execution preview is not revived.
        XCTAssertLessThan(f.source.intent.expiresAt, record.interval.start.date)
    }

    func testRetryResynchronizesSameBytesAndConflictingSessionIsPreserved() throws {
        let f = try fixture(), record = receipt(f.source), store = RouterTrafficEvidenceStore(source: f.source)
        try store.recordFixture(record)
        let path = f.stageURL.appendingPathComponent("traffic-evidence-0.json")
        var first = stat(); XCTAssertEqual(lstat(path.path, &first), 0)
        var syncs = 0
        let retry = RouterTrafficEvidenceStore(source: f.source, synchronize: { syncs += 1; return fsync($0) })
        try retry.recordFixture(record)
        XCTAssertEqual(syncs, 2)
        var last = stat(); XCTAssertEqual(lstat(path.path, &last), 0)
        XCTAssertEqual(first.st_ino, last.st_ino)
        let saved = try files(f)
        XCTAssertThrowsError(try retry.recordFixture(receipt(f.source, session: record.session, end: 110)))
        XCTAssertEqual(try files(f), saved)
    }

    func testFileAndDirectorySyncFailureRemainRetryableUnderSameIdentity() throws {
        for failedKind in [mode_t(S_IFREG), mode_t(S_IFDIR)] {
            let f = try fixture(), record = receipt(f.source)
            let failing = RouterTrafficEvidenceStore(source: f.source, synchronize: { fd in
                var info = stat()
                guard fstat(fd, &info) == 0 else { return -1 }
                return info.st_mode & S_IFMT == failedKind ? -1 : fsync(fd)
            })
            XCTAssertThrowsError(try failing.recordFixture(record))
            let saved = try files(f)
            let retry = RouterTrafficEvidenceStore(source: f.source)
            try retry.recordFixture(record)
            XCTAssertEqual(try files(f), saved)
            XCTAssertEqual(try retry.read().map(\.session), [record.session])
        }
    }

    func testSourceReplacementAndMutationDuringOperationRejectEvenForSameBytes() throws {
        for leaf in ["config.json", "receipt.json", "controller-secret"] {
            let f = try fixture(), path = f.stageURL.appendingPathComponent(leaf), bytes = try Data(contentsOf: path)
            XCTAssertThrowsError(try f.source.withVerifiedDirectory { _ in try replacePreservingOld(path, bytes: bytes) })
            XCTAssertThrowsError(try RouterTrafficEvidenceStore(source: f.source).read())
            XCTAssertTrue(FileManager.default.fileExists(atPath: path.appendingPathExtension("preserved").path))
        }
    }

    func testForeignInstallationInstanceAndSourceCannotSupplyEvidence() throws {
        let first = try fixture(), other = try fixture()
        let store = RouterTrafficEvidenceStore(source: first.source), before = try files(first)
        XCTAssertThrowsError(try store.recordFixture(receipt(other.source)))
        XCTAssertThrowsError(try first.stage.evidenceSource(other.source.intent, configurationDigest: other.source.configurationDigest))
        XCTAssertThrowsError(try first.stage.evidenceSource(first.source.intent, configurationDigest: String(repeating: "d", count: 64)))
        XCTAssertEqual(try files(first), before)
    }

    func testPartialDuplicateAndCapacityFailuresNeverSkipOrDeleteHistory() throws {
        let damaged = try fixture()
        let leaf = damaged.stageURL.appendingPathComponent("traffic-evidence-0.json")
        try Data("{".utf8).write(to: leaf); XCTAssertEqual(chmod(leaf.path, 0o600), 0)
        let store = RouterTrafficEvidenceStore(source: damaged.source)
        XCTAssertThrowsError(try store.read())
        XCTAssertThrowsError(try store.recordFixture(receipt(damaged.source)))
        XCTAssertEqual(try Data(contentsOf: leaf), Data("{".utf8))

        let duplicate = try fixture(), repeated = receipt(duplicate.source)
        let duplicateStore = RouterTrafficEvidenceStore(source: duplicate.source)
        try duplicateStore.recordFixture(repeated)
        let second = duplicate.stageURL.appendingPathComponent("traffic-evidence-1.json")
        try RouterTrafficCodec.encode(repeated).write(to: second); XCTAssertEqual(chmod(second.path, 0o600), 0)
        XCTAssertThrowsError(try duplicateStore.read())

        let full = try fixture(), fullStore = RouterTrafficEvidenceStore(source: full.source)
        for _ in 0..<RouterTrafficEvidenceStore.capacity { try fullStore.recordFixture(receipt(full.source)) }
        let before = try files(full)
        XCTAssertThrowsError(try fullStore.recordFixture(receipt(full.source)))
        XCTAssertEqual(try files(full), before)
        XCTAssertEqual(try fullStore.read().count, RouterTrafficEvidenceStore.capacity)
    }

    func testSameBytesSlotReplacementDuringSyncCannotBeAcknowledged() throws {
        let f = try fixture(), record = receipt(f.source)
        let path = f.stageURL.appendingPathComponent("traffic-evidence-0.json")
        var replaced = false
        let store = RouterTrafficEvidenceStore(source: f.source, synchronize: { fd in
            if !replaced {
                replaced = true
                do { try self.replacePreservingOld(path, bytes: Data(contentsOf: path)) }
                catch { return -1 }
            }
            return fsync(fd)
        })
        XCTAssertThrowsError(try store.recordFixture(record))
        XCTAssertTrue(replaced)
        XCTAssertTrue(FileManager.default.fileExists(atPath: path.appendingPathExtension("preserved").path))
    }
}
