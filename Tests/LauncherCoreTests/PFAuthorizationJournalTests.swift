import XCTest
import Darwin
@testable import LauncherCore

final class PFAuthorizationJournalTests: XCTestCase {
    private func directory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().appendingPathComponent("pf-auth-journal-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    private func intent() throws -> PFAuthorizationIntent {
        .init(request: try PFAuthorizationExecutionTests().request(), executionID: UUID())
    }

    func testOwnerLockAndFullRecordCASPreserveOriginal() throws {
        let root = try directory(), next = try intent()
        var store: PFAuthorizationJournal? = try .init(directory: root)
        XCTAssertNil(try store?.load())
        XCTAssertThrowsError(try PFAuthorizationJournal(directory: root))
        try store?.save(next, replacing: nil)
        XCTAssertEqual(try store?.load(), next)
        XCTAssertThrowsError(try store?.save(try intent(), replacing: nil))
        XCTAssertThrowsError(try store?.load()) // CAS error latches this owner.
        store = nil
        let reopened = try PFAuthorizationJournal(directory: root)
        XCTAssertEqual(try reopened.load(), next)
        let bytes = try Data(contentsOf: root.appendingPathComponent("pf-authorization.json"))
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("passed"))
        XCTAssertFalse(String(decoding: bytes, as: UTF8.self).contains("token"))
    }

    func testAtomicReplaceFailureRetainsArmedRecordAndNeverSendsStart() throws {
        let root = try directory(), initial = try intent()
        var failAfterReplace = false
        var store: PFAuthorizationJournal? = try .init(directory: root, afterReplace: {
            if failAfterReplace { throw PFAuthorizationGate.failure }
        })
        try store?.save(initial, replacing: nil)
        let armed = try initial.armed(with: PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: initial.executionID))
        failAfterReplace = true
        XCTAssertThrowsError(try store?.save(armed, replacing: initial))
        XCTAssertThrowsError(try store?.save(initial, replacing: armed))
        store = nil
        XCTAssertEqual(try PFAuthorizationJournal(directory: root).load(), armed)
        let result = PFAuthorizationTransport.submitGated(armed, permit: .init()) { _ in XCTFail("armed intent replayed") }
        XCTAssertEqual(result.outcome, .unknown); XCTAssertFalse(result.localProcessSettled)
    }

    func testLiveExecutionCannotBeOverwrittenOrDowngraded() throws {
        for downgrade in [false, true] {
            let root = try directory(), initial = try intent(), store = try PFAuthorizationJournal(directory: root)
            try store.save(initial, replacing: nil)
            let armed = try initial.armed(with: PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: initial.executionID))
            try store.save(armed, replacing: initial)
            XCTAssertThrowsError(try store.save(downgrade ? initial : intent(), replacing: armed))
            XCTAssertEqual(try JSONDecoder().decode(PFAuthorizationState.self,
                                                   from: Data(contentsOf: root.appendingPathComponent("pf-authorization.json"))).authorization, armed)
        }
    }

    func testUnarmedRecordCanBeReplacedOnlyByExplicitNewIntent() throws {
        let root = try directory(), store = try PFAuthorizationJournal(directory: root), original = try intent(), next = try intent()
        try store.save(original, replacing: nil)
        try store.save(next, replacing: original)
        XCTAssertEqual(try store.load(), next)
        XCTAssertThrowsError(try next.armed(with: PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: UUID())))
    }

    func testTransportJournalAndRestartObservationRetainOriginalThenAllowExplicitReplacement() throws {
        let root = try directory(), initial = try intent()
        var store: PFAuthorizationJournal? = try .init(directory: root)
        try store?.save(initial, replacing: nil)
        let script = "import sys,json,os\nprint('PF_AUTH_READY_V1 '+sys.argv[1],flush=True)\nf=json.load(sys.stdin)\nassert f['execution']['pid']==os.getpid()\nprint('fixture-only')"
        let result = GatedAuthorizationProcess.capture(executable: "/usr/bin/python3",
            arguments: ["-I", "-S", "-B", "-c", script, initial.executionID.uuidString], intent: initial) { armed in
                try store?.save(armed, replacing: initial)
                XCTAssertEqual(try store?.load(), armed)
            }
        XCTAssertTrue(result.complete); XCTAssertTrue(result.settled)
        let persisted = try XCTUnwrap(store?.load())
        XCTAssertTrue(persisted.startMayHaveBeenSent)
        store = nil
        let reopened = try PFAuthorizationJournal(directory: root)
        let restored = try XCTUnwrap(reopened.load())
        XCTAssertEqual(restored, persisted)
        var coordinator = PFRecoveryCoordinator(); coordinator.restoreForObservation(restored)
        XCTAssertTrue(coordinator.authorizationInFlight)
        let identity = try XCTUnwrap(restored.identity)
        coordinator.observeExecution(identity.observe(), identity: identity)
        XCTAssertFalse(coordinator.authorizationInFlight)
        XCTAssertEqual(coordinator.phase, .unknown); XCTAssertEqual(coordinator.request, initial.request)
        let next = PFAuthorizationIntent(request: initial.request, executionID: UUID())
        try reopened.save(next, replacing: restored)
        XCTAssertEqual(try reopened.load(), next)
    }

    func testPermissionsSymlinkHardlinkAndCorruptionAreNotAbsence() throws {
        for kind in ["mode", "symlink", "hardlink", "corrupt", "oversize"] {
            let root = try directory(), path = root.appendingPathComponent("pf-authorization.json")
            if kind == "symlink" { try FileManager.default.createSymbolicLink(atPath: path.path, withDestinationPath: "/no/such/file") }
            else {
                try Data((kind == "oversize" ? String(repeating: "x", count: 8193) : "{}").utf8).write(to: path)
                XCTAssertEqual(chmod(path.path, kind == "mode" ? 0o644 : 0o600), 0)
                if kind == "hardlink" { XCTAssertEqual(link(path.path, root.appendingPathComponent("other").path), 0) }
            }
            let store = try PFAuthorizationJournal(directory: root)
            XCTAssertThrowsError(try store.load(), kind)
            XCTAssertThrowsError(try store.save(try intent(), replacing: nil), kind)
        }
        let wrongRoot = try directory()
        XCTAssertEqual(chmod(wrongRoot.path, 0o755), 0)
        XCTAssertThrowsError(try PFAuthorizationJournal(directory: wrongRoot))
    }

    func testReplacedLifecyclePathAndDirectoryInvalidateOwner() throws {
        let root = try directory(), store = try PFAuthorizationJournal(directory: root)
        let lock = root.appendingPathComponent("pf-authorization-app.lock")
        try FileManager.default.moveItem(at: lock, to: root.appendingPathComponent("old-lock"))
        try Data().write(to: lock); XCTAssertEqual(chmod(lock.path, 0o600), 0)
        XCTAssertThrowsError(try store.load())
        let otherRoot = try directory(), other = try PFAuthorizationJournal(directory: otherRoot)
        try FileManager.default.moveItem(at: otherRoot, to: otherRoot.appendingPathExtension("retained"))
        try FileManager.default.createDirectory(at: otherRoot, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertThrowsError(try other.save(try intent(), replacing: nil))
    }
}
