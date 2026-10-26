import XCTest
import Darwin
import Security
@testable import RoutingCore

final class RouterPlanStoreTests: XCTestCase {
    private func root() throws -> URL {
        let parent = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("router-store-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return parent.appendingPathComponent("routing")
    }
    private func plan(_ kind: RouterDestination.Kind = .block) -> RouterPlan {
        .init(proxies: [], rules: [], defaultDestination: .init(kind: kind))
    }
    private func changeRecord(_ root: URL, _ mutate: (inout [String: Any]) -> Void) throws {
        let file = root.appendingPathComponent("plans.json")
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
        mutate(&object)
        try JSONSerialization.data(withJSONObject: object).write(to: file)
        XCTAssertEqual(chmod(file.path, 0o600), 0)
    }

    func testMissingReadDoesNotCreateAndFirstSaveIsPrivate() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let empty = try store.load()
        XCTAssertNil(empty.current); XCTAssertFalse(FileManager.default.fileExists(atPath: directory.path))
        let saved = try store.save(plan(), expecting: empty)
        XCTAssertEqual(saved.current, plan()); XCTAssertNil(saved.previous)
        for (url, expected) in [(directory, 0o700), (directory.appendingPathComponent("plans.json"), 0o600), (directory.appendingPathComponent("store.lock"), 0o600)] {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, expected)
        }
    }
    func testTwoInstancesAndRestoreUseCAS() throws {
        let directory = try root(), first = RouterPlanStore(directory: directory), second = RouterPlanStore(directory: directory)
        let a = try first.load(), b = try second.load()
        let saved = try first.save(plan(), expecting: a)
        XCTAssertThrowsError(try second.save(plan(.direct), expecting: b)) { XCTAssertEqual($0 as? RouterStoreError, .conflict) }
        let changed = try first.save(plan(.direct), expecting: saved)
        XCTAssertEqual(changed.previous, plan())
        XCTAssertThrowsError(try second.restore(expecting: saved))
        let restored = try first.restore(expecting: changed)
        XCTAssertEqual(restored.current, plan()); XCTAssertEqual(restored.previous, plan(.direct))
        XCTAssertNotEqual(restored.revision, changed.revision)
        XCTAssertThrowsError(try first.save(plan(), expecting: saved))
    }
    func testDifferentOriginAndReplacedEmptyDirectoryAreRejected() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let empty = try store.load()
        try FileManager.default.moveItem(at: directory, to: directory.appendingPathExtension("preserved"))
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        XCTAssertThrowsError(try store.save(plan(), expecting: empty)) { XCTAssertEqual($0 as? RouterStoreError, .conflict) }
        let another = RouterPlanStore(directory: try root())
        XCTAssertThrowsError(try another.save(plan(), expecting: empty))
    }
    func testUnknownVersionAndDamagedFilesAreNeverInitializedOver() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let original = try store.save(plan(), expecting: store.load())
        try changeRecord(directory) { $0["version"] = 99 }
        let future = try Data(contentsOf: directory.appendingPathComponent("plans.json"))
        XCTAssertThrowsError(try store.load()) { XCTAssertEqual($0 as? RouterStoreError, .unsupportedVersion) }
        XCTAssertThrowsError(try store.save(plan(.direct), expecting: original))
        XCTAssertEqual(try Data(contentsOf: directory.appendingPathComponent("plans.json")), future)
        try Data("damaged".utf8).write(to: directory.appendingPathComponent("plans.json"))
        XCTAssertThrowsError(try store.load()) { XCTAssertEqual($0 as? RouterStoreError, .damaged) }
        XCTAssertThrowsError(try store.save(plan(), expecting: original))
    }
    func testFuturePreviousPlanAndUnknownFieldsRejected() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let first = try store.save(plan(), expecting: store.load())
        _ = try store.save(plan(.direct), expecting: first)
        try changeRecord(directory) { object in
            var previous = object["previous"] as! [String: Any]; previous["schemaVersion"] = 2; object["previous"] = previous
        }
        XCTAssertThrowsError(try store.load()) { XCTAssertEqual($0 as? RouterStoreError, .unsupportedVersion) }
        try changeRecord(directory) { $0["password"] = "secret" }
        XCTAssertThrowsError(try store.load())
    }
    func testInvalidPlanAndNoBackupDoNotModifyFile() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let first = try store.save(plan(), expecting: store.load())
        let bytes = try Data(contentsOf: directory.appendingPathComponent("plans.json"))
        XCTAssertThrowsError(try store.restore(expecting: first)) { XCTAssertEqual($0 as? RouterStoreError, .noPreviousVersion) }
        XCTAssertThrowsError(try store.save(plan(.proxy), expecting: first))
        XCTAssertEqual(bytes, try Data(contentsOf: directory.appendingPathComponent("plans.json")))
    }
    func testFailureBeforeReplacePreservesOriginalAndAfterReplaceIsUnknown() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let original = try store.save(plan(), expecting: store.load())
        let before = RouterPlanStore(directory: directory, checkpoint: { if $0 == .beforeReplace { throw RouterStoreError.writeFailed } })
        XCTAssertThrowsError(try before.save(plan(.direct), expecting: original)) { XCTAssertEqual($0 as? RouterStoreError, .writeFailed) }
        XCTAssertEqual(try store.load().revision, original.revision)
        let after = RouterPlanStore(directory: directory, checkpoint: { if $0 == .afterReplace { throw RouterStoreError.writeFailed } })
        var candidate: UUID?
        XCTAssertThrowsError(try after.save(plan(.direct), expecting: original)) { if case .outcomeUnknown(let id) = $0 as? RouterStoreError { candidate = id } }
        let readback = try store.load()
        XCTAssertNotNil(candidate); XCTAssertEqual(readback.revision, candidate)
        XCTAssertEqual(readback.current, plan(.direct)); XCTAssertEqual(readback.previous, plan())
    }
    func testTemporaryReplacementAndContentModificationPreserveSavedVersion() throws {
        for replace in [false, true] {
            let directory = try root(), store = RouterPlanStore(directory: directory)
            let original = try store.save(plan(), expecting: store.load())
            let bytes = try Data(contentsOf: directory.appendingPathComponent("plans.json"))
            let hostile = RouterPlanStore(directory: directory, checkpoint: { stage in
                guard stage == .beforeReplace else { return }
                let temporary = try XCTUnwrap(FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil).first { $0.lastPathComponent.hasPrefix(".pending-") })
                if replace {
                    try FileManager.default.moveItem(at: temporary, to: temporary.appendingPathExtension("preserved"))
                    try bytes.write(to: temporary)
                    _ = chmod(temporary.path, 0o600)
                } else {
                    var object = try JSONSerialization.jsonObject(with: Data(contentsOf: temporary)) as! [String: Any]
                    object["previous"] = object["current"]
                    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]).write(to: temporary)
                }
            })
            XCTAssertThrowsError(try hostile.save(plan(.direct), expecting: original))
            XCTAssertEqual(bytes, try Data(contentsOf: directory.appendingPathComponent("plans.json")))
        }
    }
    func testConcurrentExternalRecordChangeBeforeReplaceDoesNotGetOverwritten() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let original = try store.save(plan(), expecting: store.load())
        let externalRevision = UUID().uuidString
        let changing = RouterPlanStore(directory: directory, checkpoint: { stage in
            if stage == .beforeReplace { try self.changeRecord(directory) { $0["revision"] = externalRevision } }
        })
        XCTAssertThrowsError(try changing.save(plan(.direct), expecting: original)) { XCTAssertEqual($0 as? RouterStoreError, .conflict) }
        XCTAssertEqual(try store.load().revision?.uuidString, externalRevision)
    }
    func testUnsafePathsAndHardlinksRefused() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let empty = try store.load()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        XCTAssertThrowsError(try store.save(plan(), expecting: empty))
        XCTAssertEqual(chmod(directory.path, 0o700), 0)
        let saved = try store.save(plan(), expecting: store.load())
        let file = directory.appendingPathComponent("plans.json")
        try FileManager.default.linkItem(at: file, to: directory.appendingPathComponent("hardlink"))
        XCTAssertThrowsError(try store.load()); XCTAssertThrowsError(try store.save(plan(), expecting: saved))
        let linked = directory.appendingPathExtension("link")
        try FileManager.default.createSymbolicLink(at: linked, withDestinationURL: directory)
        XCTAssertThrowsError(try RouterPlanStore(directory: linked).load())
    }
    func testCooperatingWriterLockDoesNotBlockIndefinitely() throws {
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let saved = try store.save(plan(), expecting: store.load())
        let fd = open(directory.appendingPathComponent("store.lock").path, O_RDWR)
        XCTAssertGreaterThanOrEqual(fd, 0); defer { close(fd) }
        XCTAssertEqual(flock(fd, LOCK_EX | LOCK_NB), 0)
        XCTAssertThrowsError(try store.save(plan(.direct), expecting: saved)) { XCTAssertEqual($0 as? RouterStoreError, .busy) }
    }
    func testCredentialEntriesAreImmutableAndPlansContainOnlyReferences() throws {
        let credential = RouterCredential(username: "PRIVATE_USER", password: "PRIVATE_PASSWORD")
        var accounts: [String] = []
        let add: ([String: Any]) -> OSStatus = { attributes in
            accounts.append(attributes[kSecAttrAccount as String] as! String)
            let value = try! JSONDecoder().decode(RouterCredential.self, from: attributes[kSecValueData as String] as! Data)
            XCTAssertEqual(value.password, credential.password)
            return errSecSuccess
        }
        let first = try RouterCredentialVault.store(credential, add: add), second = try RouterCredentialVault.store(credential, add: add)
        XCTAssertNotEqual(first, second); XCTAssertEqual(Set(accounts).count, 2)
        var value = plan(); value.proxies = [.init(id: UUID(), name: "line", kind: .http, host: "127.0.0.1", port: 1082, credentialReference: first)]
        let directory = try root(), store = RouterPlanStore(directory: directory)
        let saved = try store.save(value, expecting: store.load())
        value.proxies[0].credentialReference = second
        let updated = try store.save(value, expecting: saved)
        XCTAssertEqual(try store.restore(expecting: updated).current?.proxies[0].credentialReference, first)
        let text = try String(contentsOf: directory.appendingPathComponent("plans.json"))
        XCTAssertFalse(text.contains("PRIVATE_USER")); XCTAssertFalse(text.contains("PRIVATE_PASSWORD"))
        XCTAssertThrowsError(try RouterCredentialVault.store(credential, add: { _ in errSecAuthFailed }))
        XCTAssertThrowsError(try RouterCredentialVault.store(.init(username: "", password: "x"), add: { _ in XCTFail(); return errSecSuccess }))
    }
}
