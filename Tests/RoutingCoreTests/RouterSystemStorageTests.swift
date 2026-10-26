import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemStorageTests: XCTestCase {
    private let identity = RouterSystemInstallationIdentity(id: UUID(), ownerUID: 501)
    private func fixture() throws -> (URL, RouterSystemDirectory) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-system-storage-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(fd) }
        return (url, try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid()))
    }
    func testMissingIsNotNewInstallationAndInitializeCannotOverwrite() throws {
        let (_, directory) = try fixture(), store = try RouterSystemJournalStore(directory: directory, installation: identity)
        XCTAssertThrowsError(try store.load())
        try store.initialize()
        let initial = try store.load()
        XCTAssertThrowsError(try store.initialize())
        XCTAssertEqual(try store.load().revision, initial.revision)
    }
    func testInstallationBindingRejectsDifferentOwnerOrInstallation() throws {
        let (_, directory) = try fixture()
        let store = try RouterSystemJournalStore(directory: directory, installation: identity)
        try store.initialize()
        let original = try store.load()
        XCTAssertEqual(original.installation, identity)
        for other in [RouterSystemInstallationIdentity(id: UUID(), ownerUID: identity.ownerUID),
                      RouterSystemInstallationIdentity(id: identity.id, ownerUID: 502)] {
            let foreign = try RouterSystemJournalStore(directory: directory, installation: other)
            XCTAssertThrowsError(try foreign.load())
            XCTAssertThrowsError(try foreign.initialize())
            var replacement = original
            replacement.installation = other; replacement.revision = UUID()
            XCTAssertThrowsError(try store.save(replacement, expecting: original.revision))
            XCTAssertEqual(try store.load().revision, original.revision)
        }
        var unbound = original; unbound.installation = nil; unbound.revision = UUID()
        XCTAssertThrowsError(try store.save(unbound, expecting: original.revision))
        XCTAssertEqual(try store.load().revision, original.revision)
    }
    func testUnboundJournalIsPreservedAndCannotBeAdopted() throws {
        let (_, directory) = try fixture()
        let bytes = try JSONEncoder().encode(RouterSystemJournal.empty())
        try directory.create("journal.json", data: bytes)
        let store = try RouterSystemJournalStore(directory: directory, installation: identity)
        XCTAssertThrowsError(try store.load())
        XCTAssertThrowsError(try store.initialize())
        XCTAssertEqual(try directory.read("journal.json", maximum: 4096), bytes)
        for uid: UInt32 in [0, 500, UInt32.max] {
            XCTAssertThrowsError(try RouterSystemJournalStore(directory: directory,
                installation: .init(id: identity.id, ownerUID: uid)))
        }
    }
    func testTwoStoresAndSameRevisionExternalEditCannotPassCAS() throws {
        let (url, directory) = try fixture()
        let first = try RouterSystemJournalStore(directory: directory, installation: identity), second = try RouterSystemJournalStore(directory: directory, installation: identity)
        try first.initialize()
        var a = try first.load(), b = try second.load()
        let original = a.revision
        a.revision = UUID(); try first.save(a, expecting: original)
        b.revision = UUID()
        XCTAssertThrowsError(try second.save(b, expecting: original))
        var latest = try first.load(); let expected = latest.revision
        // Same semantic object and revision, different bytes: external modification still conflicts.
        let file = url.appendingPathComponent("journal.json")
        let current = try Data(contentsOf: file); try (current + Data("\n".utf8)).write(to: file)
        latest.revision = UUID()
        XCTAssertThrowsError(try first.save(latest, expecting: expected))
    }
    func testPostRenameFailureRequiresReadAndKeepsPublishedIdentity() throws {
        let (_, directory) = try fixture()
        var failSync = false
        let store = try RouterSystemJournalStore(directory: directory, installation: identity, synchronize: { fd in failSync ? -1 : fsync(fd) })
        try store.initialize()
        var state = try store.load(); let old = state.revision; state.revision = UUID()
        failSync = true
        XCTAssertThrowsError(try store.save(state, expecting: old))
        failSync = false
        XCTAssertThrowsError(try store.save(state, expecting: old))
        let loaded = try store.load()
        XCTAssertEqual(loaded.revision, state.revision)
        var next = loaded; next.revision = UUID()
        try store.save(next, expecting: loaded.revision)
        XCTAssertEqual(try store.load().revision, next.revision)
    }
    func testCorruptEmptyAndFutureJournalRemainUntouched() throws {
        for content in [Data(), Data("not json".utf8), Data(#"{"version":2}"#.utf8)] {
            let (_, directory) = try fixture()
            try directory.create("journal.json", data: content)
            let store = try RouterSystemJournalStore(directory: directory, installation: identity)
            XCTAssertThrowsError(try store.load()); XCTAssertThrowsError(try store.initialize())
            XCTAssertEqual(try directory.read("journal.json", maximum: 100), content)
        }
    }
    func testPrivateFileRejectsSymlinkHardlinkFIFOAndPublicModes() throws {
        let (url, directory) = try fixture()
        try directory.create("original", data: Data("test".utf8))
        try FileManager.default.createSymbolicLink(at: url.appendingPathComponent("symlink"), withDestinationURL: url.appendingPathComponent("original"))
        XCTAssertThrowsError(try directory.read("symlink", maximum: 100))
        XCTAssertEqual(link(url.appendingPathComponent("original").path, url.appendingPathComponent("hardlink").path), 0)
        XCTAssertThrowsError(try directory.read("hardlink", maximum: 100))
        XCTAssertEqual(mkfifo(url.appendingPathComponent("fifo").path, 0o600), 0)
        XCTAssertThrowsError(try directory.read("fifo", maximum: 100))
        try directory.create("public", data: Data("test".utf8))
        XCTAssertEqual(chmod(url.appendingPathComponent("public").path, 0o644), 0)
        XCTAssertThrowsError(try directory.read("public", maximum: 100))
        XCTAssertThrowsError(try directory.read("../escape", maximum: 100))
    }
    func testChildDirectoryReplacementAndLockReplacementRejected() throws {
        let (url, directory) = try fixture()
        let child = try directory.createDirectory("child")
        try FileManager.default.moveItem(at: url.appendingPathComponent("child"), to: url.appendingPathComponent("old-child"))
        _ = try directory.createDirectory("child")
        XCTAssertThrowsError(try child.create("file", data: Data()))
        let store = try RouterSystemJournalStore(directory: directory, installation: identity); try store.initialize()
        try FileManager.default.moveItem(at: url.appendingPathComponent("journal.lock"), to: url.appendingPathComponent("old.lock"))
        try directory.create("journal.lock", data: Data())
        XCTAssertThrowsError(try store.load())
    }
    func testRealACLIsRejectedWhileNoACLWorks() throws {
        let (url, directory) = try fixture()
        try directory.create("acl-file", data: Data("fixture".utf8))
        XCTAssertNotNil(try directory.read("acl-file", maximum: 100))
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/chmod")
        process.arguments = ["+a", "everyone allow read", url.appendingPathComponent("acl-file").path]
        try process.run(); process.waitUntilExit(); XCTAssertEqual(process.terminationStatus, 0)
        XCTAssertThrowsError(try directory.read("acl-file", maximum: 100))
    }
    func testStrictJournalRejectsUnknownNestedAndNullFields() throws {
        let state = RouterSystemJournal.empty()
        let encoded = try JSONEncoder().encode(state)
        var object = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertNoThrow(try RouterSystemJournalDecoder.decode(encoded))
        object["intent"] = NSNull()
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "intent"); object["command"] = "private-value"
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object))) { error in
            XCTAssertFalse(String(describing: error).contains("private"))
        }
        object.removeValue(forKey: "command"); object["reason"] = "arbitrary"
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object)))
    }
    func testProductionDirectoryRefusesNonrootAndCustomPaths() {
        XCTAssertThrowsError(try RouterSystemDirectory.installed("/tmp/custom", privateLeaf: true))
        if getuid() != 0 { XCTAssertThrowsError(try RouterSystemDirectory.installed(RouterSystemLayout.state, privateLeaf: true)) }
    }
    func testNestedJournalFieldsAndExpiredHistoricalPreview() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .quad9)
        let issued = RouterSystemClock(bootID: UUID(), uptime: 10, date: Date(timeIntervalSince1970: 1000))
        var state = RouterSystemJournal.empty()
        state.phase = .prepared; state.reason = "prepared_not_applied"
        state.intent = .init(id: UUID(), plan: plan, profile: profile, digest: try RouterSystemProvider.digest(plan: plan, profile: profile),
            networkFingerprint: String(repeating: "a", count: 64), issued: issued, expiresAt: issued.date.addingTimeInterval(60), deadlineUptime: 70)
        let bytes = try JSONEncoder().encode(state)
        XCTAssertNoThrow(try RouterSystemJournalDecoder.decode(bytes)) // Expired records remain loadable for query/stop.
        var object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        var intent = object["intent"] as! [String: Any]
        var nested = intent["profile"] as! [String: Any]; nested["override"] = "private"
        intent["profile"] = nested; object["intent"] = intent
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object)))
        object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        intent = object["intent"] as! [String: Any]
        nested = intent["plan"] as! [String: Any]; nested["rawYAML"] = "private"
        intent["plan"] = nested; object["intent"] = intent
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object)))
    }
    func testInstallManifestCannotSelectCodeOrTrustDifferentCore() throws {
        let manifest = RouterSystemInstallManifest(version: 1, installationID: UUID(), ownerUID: 501,
            helperSHA256: String(repeating: "a", count: 64), coreVersion: RouterCoreRelease.version, coreSHA256: RouterCoreRelease.executableSHA256)
        let bytes = try JSONEncoder().encode(manifest)
        XCTAssertEqual(try RouterSystemInstallManifest.decode(bytes), manifest)
        for (key, value): (String, Any) in [("path", "/bin/sh"), ("ownerUID", 0), ("ownerUID", true),
                                          ("version", 2), ("coreVersion", "latest"), ("coreSHA256", String(repeating: "0", count: 64))] {
            var object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]; object[key] = value
            XCTAssertThrowsError(try RouterSystemInstallManifest.decode(JSONSerialization.data(withJSONObject: object)))
        }
    }

    func testDispatchSurvivesStoreReopenBeforeAndAfterWorkIsRecorded() throws {
        let (_, directory) = try fixture()
        let store = try RouterSystemJournalStore(directory: directory, installation: identity)
        try store.initialize()
        var state = try store.load()
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .quad9)
        let clock = RouterSystemClock(bootID: UUID(), uptime: 10, date: Date(timeIntervalSince1970: 1000))
        let intent = RouterSystemIntent(id: UUID(), plan: plan, profile: profile,
            digest: try RouterSystemCompiler.digest(plan: plan, profile: profile), networkFingerprint: String(repeating: "a", count: 64),
            issued: clock, expiresAt: clock.date.addingTimeInterval(60), deadlineUptime: 70)
        var previous = state.revision
        state.revision = UUID(); state.intent = intent; state.phase = .prepared; state.reason = "prepared_not_applied"
        try store.save(state, expecting: previous)
        let fence = RouterSystemDispatchFence(instance: intent.id,
            host: .init(bootID: clock.bootID, pid: 700, birthSeconds: 90, birthMicroseconds: 12),
            processGroup: 700, gateDeadlineUptime: 70, gateExpiresAt: intent.expiresAt,
            baselineID: UUID(), baselineDigest: String(repeating: "c", count: 64),
            networkFingerprint: intent.networkFingerprint, configurationDigest: String(repeating: "b", count: 64))
        previous = state.revision
        state.revision = UUID(); state.phase = .applying; state.reason = "execution_pending"
        state.dispatch = fence; state.configurationDigest = fence.configurationDigest
        try store.save(state, expecting: previous)

        let reopened = try RouterSystemJournalStore(directory: directory, installation: identity)
        var loaded = try reopened.load()
        XCTAssertEqual(loaded.revision, state.revision); XCTAssertEqual(loaded.installation, identity)
        XCTAssertEqual(loaded.dispatch, fence); XCTAssertNil(loaded.work)
        previous = loaded.revision
        loaded.revision = UUID()
        loaded.work = .init(bootID: clock.bootID, pid: 701, birthSeconds: 100, birthMicroseconds: 13)
        try reopened.save(loaded, expecting: previous)
        let again = try RouterSystemJournalStore(directory: directory, installation: identity).load()
        XCTAssertEqual(again.dispatch, fence); XCTAssertEqual(again.work, loaded.work)
        XCTAssertEqual(again.revision, loaded.revision)

        // Decoder failures must not require changing or erasing the valid on-disk journal.
        let base = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(again)) as? [String: Any])
        var missing = base; missing.removeValue(forKey: "dispatch")
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: missing)))
        let invalidFields: [(String, Any)] = [
            ("unexpected", true), ("processGroup", 701), ("configurationDigest", String(repeating: "d", count: 64)),
            ("gateDeadlineUptime", 71), ("gateExpiresAt", 0), ("networkFingerprint", String(repeating: "e", count: 64))]
        for (key, value) in invalidFields {
            var object = base
            var dispatch = try XCTUnwrap(object["dispatch"] as? [String: Any])
            dispatch[key] = value; object["dispatch"] = dispatch
            XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: object)), key)
        }
        var changedBoot = base
        var dispatch = try XCTUnwrap(base["dispatch"] as? [String: Any])
        var host = try XCTUnwrap(dispatch["host"] as? [String: Any])
        host["bootID"] = UUID().uuidString; dispatch["host"] = host; changedBoot["dispatch"] = dispatch
        XCTAssertThrowsError(try RouterSystemJournalDecoder.decode(JSONSerialization.data(withJSONObject: changedBoot)))
        XCTAssertEqual(try reopened.load().dispatch, fence)
    }
}
