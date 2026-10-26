import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemStageTests: XCTestCase {
    private let identity = RouterSystemInstallationIdentity(id: UUID(), ownerUID: 501)
    private func directory() throws -> (URL, RouterSystemDirectory) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-stage-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(fd) }
        return (url, try .fixture(directoryFD: fd, owner: getuid()))
    }
    private func intent(plan: RouterPlan = .init(proxies: [], rules: [], defaultDestination: .direct), id: UUID = UUID()) throws -> RouterSystemIntent {
        let profile = RouterSystemProfile(resolver: .quad9)
        let clock = RouterSystemClock(bootID: UUID(), uptime: 1, date: Date())
        return .init(id: id, plan: plan, profile: profile, digest: try RouterSystemCompiler.digest(plan: plan, profile: profile),
            networkFingerprint: String(repeating: "a", count: 64), issued: clock,
            expiresAt: clock.date.addingTimeInterval(60), deadlineUptime: 61)
    }
    private func success(_: UUID) -> RouterProcessResult { .init(exitCode: 0, timedOut: false, settled: true) }
    private func child(_ root: RouterSystemDirectory, _ intent: RouterSystemIntent) throws -> RouterSystemDirectory {
        try root.child("stage-" + intent.id.uuidString.lowercased())
    }
    func testRetryReusesSecretAndExactConfigurationWithPrivatePermissions() throws {
        let (_, root) = try directory(), intent = try intent()
        var checks = 0, verifications = 0
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity,
            verifyCode: { verifications += 1 }, check: { _ in checks += 1; return self.success(intent.id) })
        let first = try stage.stage(intent, credentials: [:]), files = try child(root, intent)
        let secret = try files.read("controller-secret", maximum: 64)
        let configuration = try XCTUnwrap(files.read("config.json", maximum: 4 * RouterInput.maximumBytes))
        XCTAssertEqual(first, RouterSystemObservation.hash(configuration))
        XCTAssertEqual(first, try stage.stage(intent, credentials: [:]))
        XCTAssertEqual(secret, try files.read("controller-secret", maximum: 64))
        XCTAssertEqual(checks, 2); XCTAssertEqual(verifications, 8)
        XCTAssertEqual(Data(try stage.controllerSecret(intent, configurationDigest: first).utf8), secret)
        XCTAssertEqual(checks, 2) // Reading the private secret never reruns or starts the core.
        for name in ["receipt.json", "controller-secret", "config.json"] {
            var info = stat(); XCTAssertEqual(fstatat(files.fd, name, &info, AT_SYMLINK_NOFOLLOW), 0)
            XCTAssertEqual(info.st_mode & 0o777, 0o600)
        }
    }
    func testChangedCredentialsAndInstallationCannotOverwriteStage() throws {
        let (_, root) = try directory(), reference = UUID()
        let plan = RouterPlan(proxies: [.init(id: UUID(), name: "Test", kind: .http, host: "127.0.0.1", port: 1082,
                                            credentialReference: reference)], rules: [], defaultDestination: .direct)
        let intent = try intent(plan: plan)
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
        _ = try stage.stage(intent, credentials: [reference: .init(username: "user", password: "first")])
        let files = try child(root, intent), before = try files.read("config.json", maximum: 65536)
        XCTAssertThrowsError(try stage.stage(intent, credentials: [reference: .init(username: "user", password: "second")]))
        let foreign = try RouterSystemStage.fixture(directory: root, identity: .init(id: UUID(), ownerUID: 501), check: success)
        XCTAssertThrowsError(try foreign.stage(intent, credentials: [reference: .init(username: "user", password: "first")]))
        XCTAssertEqual(before, try files.read("config.json", maximum: 65536))
    }
    func testMkdirOnlyInterruptionRecoversButUnownedFilesDoNot() throws {
        for hasForeignFile in [false, true] {
            let (_, root) = try directory(), intent = try intent()
            let files = try root.createDirectory("stage-" + intent.id.uuidString.lowercased())
            if hasForeignFile { try files.create("unexpected", data: Data("preserve".utf8)) }
            let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
            if hasForeignFile {
                XCTAssertThrowsError(try stage.stage(intent, credentials: [:]))
                XCTAssertEqual(try files.read("unexpected", maximum: 100), Data("preserve".utf8))
            } else { XCTAssertNoThrow(try stage.stage(intent, credentials: [:])) }
        }
    }
    func testMissingSecretWithExistingConfigurationIsRejected() throws {
        let (url, root) = try directory(), intent = try intent()
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
        _ = try stage.stage(intent, credentials: [:])
        let files = url.appendingPathComponent("stage-" + intent.id.uuidString.lowercased())
        try FileManager.default.moveItem(at: files.appendingPathComponent("controller-secret"), to: files.appendingPathComponent("preserved-secret"))
        XCTAssertThrowsError(try stage.stage(intent, credentials: [:]))
        XCTAssertFalse(FileManager.default.fileExists(atPath: files.appendingPathComponent("controller-secret").path))
    }
    func testCoreFailurePreservesFilesAndRetryUsesSameStage() throws {
        for result in [RouterProcessResult(exitCode: 1, timedOut: false, settled: true),
                       .init(exitCode: 0, timedOut: true, settled: true), .init(exitCode: -1, timedOut: false, settled: false)] {
            let (_, root) = try directory(), intent = try intent()
            let failed = try RouterSystemStage.fixture(directory: root, identity: identity, check: { _ in result })
            XCTAssertThrowsError(try failed.stage(intent, credentials: [:]))
            let files = try child(root, intent), before = try files.read("config.json", maximum: 65536)
            let retry = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
            XCTAssertNoThrow(try retry.stage(intent, credentials: [:]))
            XCTAssertEqual(before, try files.read("config.json", maximum: 65536))
        }
    }
    func testMutationDuringCoreCheckIsRejectedEvenIfCheckSucceeds() throws {
        let (url, root) = try directory(), intent = try intent()
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: { id in
            try Data("modified".utf8).write(to: url.appendingPathComponent("stage-" + id.uuidString.lowercased()).appendingPathComponent("config.json"))
            return self.success(id)
        })
        XCTAssertThrowsError(try stage.stage(intent, credentials: [:]))
    }
    func testBlockedResolverAndMissingCredentialsDoNotCreateStage() throws {
        let (_, root) = try directory()
        let blocked = try intent(plan: .init(proxies: [], rules: [], defaultDestination: .block))
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: { _ in XCTFail("must not execute"); return self.success(blocked.id) })
        XCTAssertThrowsError(try stage.stage(blocked, credentials: [:]))
        XCTAssertNil(try root.childIfPresent("stage-" + blocked.id.uuidString.lowercased()))
        let reference = UUID()
        let credentialPlan = RouterPlan(proxies: [.init(id: UUID(), name: "Test", kind: .http, host: "127.0.0.1", port: 1082,
                                                      credentialReference: reference)], rules: [], defaultDestination: .direct)
        let missing = try intent(plan: credentialPlan)
        XCTAssertThrowsError(try stage.stage(missing, credentials: [:]))
        XCTAssertNil(try root.childIfPresent("stage-" + missing.id.uuidString.lowercased()))
    }
    func testEveryReusedFileAndDirectoryMustSynchronizeBeforeSuccess() throws {
        let (_, root) = try directory(), intent = try intent()
        let seed = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
        let digest = try seed.stage(intent, credentials: [:]), files = try child(root, intent)
        var nodes: [ino_t: String] = [:]
        for name in ["receipt.json", "controller-secret", "config.json"] {
            var info = stat(); XCTAssertEqual(fstatat(files.fd, name, &info, AT_SYMLINK_NOFOLLOW), 0)
            nodes[info.st_ino] = name
        }
        for (fd, name) in [(root.fd, "parent"), (files.fd, "stage")] {
            var info = stat(); XCTAssertEqual(fstat(fd, &info), 0); nodes[info.st_ino] = name
        }
        for target in nodes.values {
            var fail = true, synchronized: Set<String> = []
            let stage = try RouterSystemStage.fixture(directory: root, identity: identity, synchronize: { fd in
                var info = stat()
                guard fstat(fd, &info) == 0, let name = nodes[info.st_ino] else { return -1 }
                synchronized.insert(name)
                if fail && name == target { return -1 }
                return fsync(fd)
            }, check: success)
            XCTAssertThrowsError(try stage.stage(intent, credentials: [:]))
            XCTAssertTrue(synchronized.contains(target))
            fail = false; synchronized = []
            XCTAssertEqual(try stage.stage(intent, credentials: [:]), digest)
            XCTAssertEqual(synchronized, Set(nodes.values))
        }
    }
    func testReceiptOnlyDirectorySyncFailureCanResumeWithPreservedIdentity() throws {
        let (_, root) = try directory(), intent = try intent()
        var fail = true
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity,
            synchronize: { fd in fail ? -1 : fsync(fd) }, check: success)
        XCTAssertThrowsError(try stage.stage(intent, credentials: [:]))
        let files = try child(root, intent), receipt = try files.read("receipt.json", maximum: 4096)
        XCTAssertNotNil(receipt); XCTAssertNil(try files.read("controller-secret", maximum: 64))
        fail = false
        XCTAssertNoThrow(try stage.stage(intent, credentials: [:]))
        XCTAssertEqual(receipt, try files.read("receipt.json", maximum: 4096))
    }
    func testApplicationRoutingWithDefaultDirectCanStageWithoutChangingRules() throws {
        let (_, root) = try directory()
        let proxy = RouterProxy(id: UUID(), name: "Fixture", kind: .http, host: "127.0.0.1", port: 1082)
        let rule = RouterRule(id: UUID(), selector: .init(processPath: "/Applications/Example.app/Contents/MacOS/Example"), destination: .proxy(proxy.id))
        let input = try intent(plan: .init(proxies: [proxy], rules: [rule], defaultDestination: .direct))
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
        XCTAssertNoThrow(try stage.stage(input, credentials: [:]))
        let bytes = try XCTUnwrap(child(root, input).read("config.json", maximum: 65536))
        let object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
        let expected = try RouterCompiledRouting.compile(input.plan) { _ in throw RouterSystemError.invalidCredentials }
        XCTAssertEqual(object["rules"] as? [String], expected.rules)
    }
    func testVerifyReusesValidatedDigestWithoutRequestingCredentialsOrRunningCheck() throws {
        let (_, root) = try directory(), intent = try intent()
        var checks = 0, verifications = 0
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity,
            verifyCode: { verifications += 1 }, check: { _ in checks += 1; return self.success(intent.id) })
        let digest = try stage.stage(intent, credentials: [:]), before = verifications
        try stage.verify(intent, configurationDigest: digest)
        XCTAssertEqual(checks, 1); XCTAssertEqual(verifications, before + 2)
        XCTAssertThrowsError(try stage.verify(intent, configurationDigest: String(repeating: "0", count: 64)))
        let foreign = try RouterSystemStage.fixture(directory: root, identity: .init(id: UUID(), ownerUID: 501), check: success)
        XCTAssertThrowsError(try foreign.verify(intent, configurationDigest: digest))
    }
    func testVerifyRejectsTamperingBeforeAndDuringVerification() throws {
        for name in ["receipt.json", "config.json", "controller-secret"] {
            for during in [false, true] {
                let (url, root) = try directory(), intent = try intent()
                let seed = try RouterSystemStage.fixture(directory: root, identity: identity, check: success)
                let digest = try seed.stage(intent, credentials: [:])
                let target = url.appendingPathComponent("stage-" + intent.id.uuidString.lowercased()).appendingPathComponent(name)
                func mutate() throws { try Data("changed".utf8).write(to: target) }
                if !during { try mutate() }
                var calls = 0
                let stage = try RouterSystemStage.fixture(directory: root, identity: identity, verifyCode: {
                    calls += 1
                    if during && calls == 2 { try mutate() }
                }, check: { _ in XCTFail("verification must not run core"); return self.success(intent.id) })
                XCTAssertThrowsError(try stage.verify(intent, configurationDigest: digest), name)
            }
        }
    }
    func testRealPinnedCoreChecksStagedFilesWithoutNetwork() throws {
        guard let path = ProcessInfo.processInfo.environment["ROUTER_TEST_PINNED_CORE"] else {
            throw XCTSkip("Set ROUTER_TEST_PINNED_CORE for the staged core check")
        }
        let (url, root) = try directory(), intent = try intent()
        let command = try RouterSystemCommand(ownerUID: identity.ownerUID)
        let stage = try RouterSystemStage.fixture(directory: root, identity: identity, verifyCode: {
            _ = try RouterCoreRelease.verifiedBytes(URL(fileURLWithPath: path))
        }, check: { id in
            let directory = url.appendingPathComponent("stage-" + id.uuidString.lowercased())
            return try command.fixtureCapture("/usr/bin/sandbox-exec",
                ["-p", "(version 1)(allow default)(deny network*)", path, "-t", "-d", directory.path,
                 "-f", directory.appendingPathComponent("config.json").path], timeout: 15).0
        })
        let first = try stage.stage(intent, credentials: [:])
        XCTAssertEqual(try stage.stage(intent, credentials: [:]), first)
    }
}
