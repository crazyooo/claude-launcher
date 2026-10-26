import XCTest
import CryptoKit
@testable import LauncherCore

final class AccountVaultTests: XCTestCase {
    private func fixture() throws -> (URL, URL) {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("vault-tests-\(UUID().uuidString)")
        let source = root.appendingPathComponent("source"), vault = root.appendingPathComponent("vault")
        for path in [source, source.appendingPathComponent(".claude"), vault] {
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        for file in AccountFields.files { try Data("{}".utf8).write(to: source.appendingPathComponent(file)) }
        return (source, vault)
    }
    func testEncryptedArchiveRoundTripPreservesUnrelatedSettings() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let settings = source.appendingPathComponent(".claude/settings.json")
        try Data(#"{"env":{"ANTHROPIC_API_KEY":"fixture-A","KEEP":"a"},"processWrapper":"original"}"#.utf8).write(to: settings)
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true })
        let archive = try await vault.capture(name: "Fixture")
        let encrypted = try Data(contentsOf: directory.appendingPathComponent(archive.id.uuidString + ".account"))
        XCTAssertFalse(String(decoding: encrypted, as: UTF8.self).contains("fixture-A"))
        try Data(#"{"env":{"ANTHROPIC_API_KEY":"fixture-B","KEEP":"b"},"processWrapper":"new","mcpServers":{"keep":{}}}"#.utf8).write(to: settings)
        try await vault.restore(id: archive.id)
        let result = try AccountFields.object(Data(contentsOf: settings))
        XCTAssertEqual((result["env"] as? [String: String])?["ANTHROPIC_API_KEY"], "fixture-A")
        XCTAssertEqual((result["env"] as? [String: String])?["KEEP"], "b")
        XCTAssertEqual(result["processWrapper"] as? String, "new"); XCTAssertNotNil(result["mcpServers"])
        XCTAssertTrue(try Data(contentsOf: directory.appendingPathComponent("transaction.sealed")).isEmpty)
    }
    func testTamperedArchiveAndWrongKeyCannotModifySource() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true })
        let archive = try await vault.capture(name: "Fixture")
        let file = directory.appendingPathComponent(archive.id.uuidString + ".account")
        let original = try Data(contentsOf: file)
        var bytes = original; bytes[bytes.count - 1] ^= 1; try bytes.write(to: file)
        do { try await vault.restore(id: archive.id); XCTFail("tampered archive accepted") } catch {}
        XCTAssertEqual(try Data(contentsOf: source.appendingPathComponent(".claude.json")), Data("{}".utf8))
        try original.write(to: file)
        let wrongKey = SymmetricKey(size: .bits256)
        let other = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in wrongKey }, clientsIdle: { true })
        do { try await other.restore(id: archive.id); XCTFail("wrong key accepted") } catch {}
    }
    func testRunningClientAndLinksAreRejected() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { false })
        do { _ = try await vault.capture(name: "blocked"); XCTFail("busy capture") } catch {}
        let original = source.appendingPathComponent(".claude.json"), moved = source.appendingPathComponent("saved.json")
        try FileManager.default.moveItem(at: original, to: moved)
        try FileManager.default.createSymbolicLink(at: original, withDestinationURL: moved)
        let idle = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true })
        do { _ = try await idle.capture(name: "link"); XCTFail("symlink accepted") } catch {}
    }
    func testMissingMarkerDoesNotAuthorizeKeyReplacement() async throws {
        let (source, directory) = try fixture()
        try Data("existing encrypted material".utf8).write(to: directory.appendingPathComponent("old.account"))
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { create in
            XCTAssertFalse(create); throw AccountVaultError.key
        }, clientsIdle: { true })
        do { _ = try await vault.capture(name: "fixture"); XCTFail("lost key replaced") } catch {}
    }
    func testCaptureRejectsMixedSourceGeneration() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        var calls = 0
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: {
            calls += 1
            if calls == 2 { try Data(#"{"userID":"changed"}"#.utf8).write(to: source.appendingPathComponent(".claude.json")) }
            return true
        })
        do { _ = try await vault.capture(name: "mixed"); XCTFail("mixed archive") } catch {}
        XCTAssertFalse(try FileManager.default.contentsOfDirectory(atPath: directory.path).contains { $0.hasSuffix(".account") })
    }
    func testInterruptedMutationCanRecoverAndRetainsBackup() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        var calls = 0, fault = false
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: {
            if fault { calls += 1; return calls < 3 }; return true
        })
        let archived = try await vault.capture(name: "A")
        let config = source.appendingPathComponent(".claude.json")
        let original = Data(#"{"userID":"B","project":"keep"}"#.utf8); try original.write(to: config)
        fault = true
        do { try await vault.restore(id: archived.id); XCTFail("injected failure not observed") } catch {}
        XCTAssertFalse(try Data(contentsOf: directory.appendingPathComponent("transaction.sealed")).isEmpty)
        fault = false; try await vault.recover()
        XCTAssertEqual(try Data(contentsOf: config), original)
        let backups = try await vault.backups(); XCTAssertEqual(backups.count, 1)
        try await vault.restoreBackup(id: backups[0])
        XCTAssertEqual(try Data(contentsOf: config), original)
        let archives = try await vault.archives(); XCTAssertEqual(archives.first?.id, archived.id)
    }
    func testObsoleteBackupDoesNotCreateBlockingJournal() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true })
        let archive = try await vault.capture(name: "A")
        try await vault.restore(id: archive.id)
        let backups = try await vault.backups()
        try Data(#"{"unrelated":"new edit"}"#.utf8).write(to: source.appendingPathComponent(".claude.json"))
        do { try await vault.restoreBackup(id: backups[0]); XCTFail("stale backup accepted") } catch {}
        XCTAssertTrue(try Data(contentsOf: directory.appendingPathComponent("transaction.sealed")).isEmpty)
        _ = try await vault.capture(name: "still usable")
    }
    func testNativeCredentialSwitchPreservesMCPAndExcludesItFromArchive() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let store = FixtureCredentialStore()
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true }, credentials: store)
        let archive = try await vault.capture(name: "native A")
        store.current = store.current.replacing(Data(#"{"claudeAiOauth":{"token":"B"},"mcpOAuth":{"token":"NEW-MCP"},"pluginSecrets":{"keep":true}}"#.utf8))
        try await vault.restore(id: archive.id)
        let current = try AccountFields.object(store.current.value)
        XCTAssertEqual((current["claudeAiOauth"] as? [String: String])?["token"], "A")
        XCTAssertEqual((current["mcpOAuth"] as? [String: String])?["token"], "NEW-MCP")
        XCTAssertNotNil(current["pluginSecrets"])
        let bytes = try Data(contentsOf: directory.appendingPathComponent(archive.id.uuidString + ".account"))
        let binding = fingerprintData(Data("\(getuid()):\(source.standardizedFileURL.path)".utf8))
        let aad = Data("ClaudeLauncherVault.v1:\(binding):\(archive.id.uuidString)".utf8)
        let plain = try AES.GCM.open(.init(combined: bytes), using: key, authenticating: aad)
        let object = try AccountFields.object(plain)
        let native = try XCTUnwrap(object["credential"] as? [String: Any])
        let fields = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(native["fields"] as? String)))
        XCTAssertNil(try AccountFields.object(fields)["mcpOAuth"])
    }
    func testNativeFailuresRollBackFilesBeforeOrAfterKeychainWrite() async throws {
        for mode in ["before", "after"] {
            let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
            let store = FixtureCredentialStore()
            let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true }, credentials: store)
            let archive = try await vault.capture(name: "native A")
            let file = source.appendingPathComponent(".claude.json"), before = Data(#"{"userID":"B"}"#.utf8)
            try before.write(to: file)
            store.current = store.current.replacing(Data(#"{"claudeAiOauth":{"token":"B"},"mcpOAuth":{"token":"keep"}}"#.utf8))
            let nativeBefore = store.current; store.failOnce = mode
            do { try await vault.restore(id: archive.id); XCTFail("fault not injected") } catch {}
            XCTAssertEqual(try Data(contentsOf: file), before); XCTAssertEqual(store.current, nativeBefore)
            XCTAssertTrue(try Data(contentsOf: directory.appendingPathComponent("transaction.sealed")).isEmpty)
        }
    }
    func testNativeModeRejectsV1ArchiveAndBackup() async throws {
        let (source, directory) = try fixture(), key = SymmetricKey(size: .bits256)
        let plain = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true })
        let archive = try await plain.capture(name: "v1"); try await plain.restore(id: archive.id)
        let backups = try await plain.backups()
        let native = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in key }, clientsIdle: { true }, credentials: FixtureCredentialStore())
        do { try await native.restore(id: archive.id); XCTFail("partial archive accepted") } catch {}
        do { try await native.restoreBackup(id: backups[0]); XCTFail("partial backup accepted") } catch {}
        let backupBytes = try Data(contentsOf: directory.appendingPathComponent("backup-\(backups[0].uuidString).sealed"))
        try backupBytes.write(to: directory.appendingPathComponent("transaction.sealed"))
        do { try await native.recover(); XCTFail("partial journal accepted") } catch {}
    }
    func testSchemaCannotOverwriteMCPOrWrapper() throws {
        XCTAssertThrowsError(try AccountFields.merge(Data("{}".utf8), with: Data(#"{"processWrapper":"bad"}"#.utf8), file: ".claude/settings.json"))
        let selected = try AccountFields.selected(Data(#"{"claudeAiOauth":{"token":"fixture"},"mcpOAuth":{"private":"keep"}}"#.utf8), file: ".claude/.credentials.json")
        XCTAssertNil(try AccountFields.object(selected)["mcpOAuth"])
    }
    func testEmptyListsAndRecoveryDoNotRequireOrCreateMasterKey() async throws {
        let (source, directory) = try fixture()
        var idle = true
        let vault = try AccountVault(sourceRoot: source, vaultRoot: directory, keyProvider: { _ in
            XCTFail("empty vault accessed key"); throw AccountVaultError.key
        }, clientsIdle: { idle })
        try await vault.recover()
        idle = false
        let archives = try await vault.archives(), backups = try await vault.backups()
        XCTAssertTrue(archives.isEmpty); XCTAssertTrue(backups.isEmpty)
    }
    func testProcessSnapshotRejectsUnknownAndActiveClientsWithoutArguments() throws {
        XCTAssertTrue(try CodeAccountConnection.processListIsIdle(" 501 /Applications/Codex.app/Contents/MacOS/Codex\n 0 /sbin/launchd\n", uid: 501))
        for path in ["claude", "/Applications/Claude.app/Contents/MacOS/Claude", "/Applications/Visual Studio Code.app/Contents/MacOS/Electron", "/Users/fixture/.local/share/claude/versions/2.0"] {
            XCTAssertFalse(try CodeAccountConnection.processListIsIdle("501 \(path)\n", uid: 501))
        }
        for text in ["", "501 /bin/zsh", "bad record\n", "0 /sbin/launchd\n", "501 /opt/homebrew/bin/node\n", "501 /usr/local/bin/bun\n"] {
            XCTAssertThrowsError(try CodeAccountConnection.processListIsIdle(text, uid: 501))
        }
    }
}


private final class FixtureCredentialStore: CodeCredentialStore {
    let binding = CodeCredentialBinding(account: "fixture", keychainPath: "/tmp/fixture.keychain")
    var current: CodeCredentialSnapshot
    var failOnce = ""
    init() {
        current = .init(binding: binding, persistentReference: Data([1, 2, 3]),
                        value: Data(#"{"claudeAiOauth":{"token":"A"},"mcpOAuth":{"token":"PRIVATE-MCP"}}"#.utf8))
    }
    func snapshot() throws -> CodeCredentialSnapshot { current }
    func update(expected: CodeCredentialSnapshot, value: Data) throws {
        guard expected == current else { throw AccountVaultError.conflict }
        let fault = failOnce; failOnce = ""
        if fault == "before" { throw AccountVaultError.key }
        current = current.replacing(value)
        if fault == "after" { throw AccountVaultError.key }
    }
}
