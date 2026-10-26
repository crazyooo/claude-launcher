import XCTest
import Security
@testable import RoutingCore

final class RouterRuntimeTests: XCTestCase {
    private let secret = String(repeating: "a", count: 64)
    private func root() -> URL {
        URL(fileURLWithPath: RouterRuntimeFiles.physicalPath(FileManager.default.temporaryDirectory)!).appendingPathComponent("router-runtime-test-" + UUID().uuidString)
    }
    private var empty: RouterPlan { .init(proxies: [], rules: [], defaultDestination: .block) }

    func testRuntimeDisablesInterceptionAndKeepsExplicitRejectRules() throws {
        let proxy = RouterProxy(id: UUID(), name: "Local", kind: .http, host: "127.0.0.1", port: 1082)
        let plan = RouterPlan(proxies: [proxy], rules: [], defaultDestination: .proxy(proxy.id))
        let result = try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: result.privateJSON) as? [String: Any])
        for port in ["port", "socks-port", "mixed-port", "redir-port", "tproxy-port"] { XCTAssertEqual(object[port] as? Int, 0) }
        XCTAssertEqual((object["tun"] as? [String: Any])?["enable"] as? Bool, false)
        XCTAssertEqual((object["dns"] as? [String: Any])?["enable"] as? Bool, false)
        XCTAssertEqual(object["external-controller"] as? String, "127.0.0.1:19491")
        XCTAssertEqual((object["rules"] as? [String])?.first, "NETWORK,UDP,REJECT")
        XCTAssertFalse(result.summary.routingVerified)
        XCTAssertFalse(result.summary.networkSettingsModified)
    }

    func testCredentialsOnlyEnterPrivateRuntimeNotReportsOrOfflinePreview() throws {
        let reference = UUID()
        let proxy = RouterProxy(id: UUID(), name: "Auth", kind: .socks5, host: "localhost", port: 1080, credentialReference: reference)
        let plan = RouterPlan(proxies: [proxy], rules: [], defaultDestination: .proxy(proxy.id))
        let result = try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret) { requested in
            XCTAssertEqual(requested, reference); return .init(username: "test-user-private", password: "test-pass-private")
        }
        XCTAssertTrue(String(decoding: result.privateJSON, as: UTF8.self).contains("test-pass-private"))
        let summary = String(decoding: try JSONEncoder().encode(result.summary), as: UTF8.self)
        XCTAssertFalse(summary.contains("test-pass-private")); XCTAssertFalse(summary.contains(secret))
        XCTAssertNil(try MihomoRoutingCompiler.preview(plan).fragment)
        XCTAssertThrowsError(try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret) { _ in
            throw NSError(domain: "test-pass-private", code: 1)
        }) { XCTAssertEqual($0 as? RouterRuntimeError, .credentialUnavailable) }
    }

    func testInvalidConfigurationFailsBeforeCredentialRead() {
        var plan = empty; plan.schemaVersion = 2
        XCTAssertThrowsError(try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret) { _ in
            XCTFail("invalid plans must not read credentials"); throw RouterCredentialError.unavailable
        })
        XCTAssertThrowsError(try RouterRuntimeCompiler.compile(empty, controllerPort: 80, secret: secret))
        XCTAssertThrowsError(try RouterRuntimeCompiler.compile(empty, controllerPort: 19491, secret: "weak"))
    }

    func testExecutablePathsUseYAMLCompatibleJSONEscapes() throws {
        let plan = RouterPlan(proxies: [], rules: [.init(id: UUID(), selector: .init(processPath: "/Applications/Example.app/Contents/MacOS/Example"), destination: .direct)], defaultDestination: .block)
        let config = try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret)
        XCTAssertFalse(String(decoding: config.privateJSON, as: UTF8.self).contains("\\/"))
    }

    func testKeychainReadIsScopedBoundedAndValidated() throws {
        let id = UUID(), credential = RouterCredential(username: "u", password: "p")
        let result = try RouterCredentialVault.read(id) { query in
            XCTAssertEqual(query[kSecAttrAccount as String] as? String, id.uuidString.lowercased())
            XCTAssertEqual(query[kSecAttrService as String] as? String, "local.claude-launcher.router-credential")
            return (errSecSuccess, try! JSONEncoder().encode(credential))
        }
        XCTAssertEqual(result.username, "u")
        for response in [(errSecItemNotFound, Data()), (errSecSuccess, Data(repeating: 32, count: 32_769)),
                         (errSecSuccess, Data("{}".utf8))] {
            XCTAssertThrowsError(try RouterCredentialVault.read(id) { _ in response })
        }
    }

    func testCoreIdentityRejectsChangedBinaryAndLinks() throws {
        let directory = root(), files = RouterRuntimeFiles(root: directory)
        try files.prepare()
        let binary = directory.appendingPathComponent("core")
        try files.writeNew(Data("fake-binary".utf8), to: binary, executable: true)
        XCTAssertThrowsError(try RouterCoreRelease.verify(binary)) { XCTAssertEqual($0 as? RouterRuntimeError, .coreDigestMismatch) }
        let link = directory.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: binary)
        XCTAssertThrowsError(try RouterCoreRelease.verify(link)) { XCTAssertEqual($0 as? RouterRuntimeError, .unsafeFile) }
    }

    func testPrivateFileRefusesOverwriteAndPublicDirectory() throws {
        let directory = root(), files = RouterRuntimeFiles(root: directory)
        try files.prepare()
        let file = directory.appendingPathComponent("private.json")
        try files.writeNew(Data("first".utf8), to: file)
        XCTAssertThrowsError(try files.writeNew(Data("second".utf8), to: file))
        XCTAssertEqual(try files.readPrivate(file), Data("first".utf8))
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        XCTAssertThrowsError(try files.prepare())
    }

    func testCheckRunsPinnedCoreWithNetworkDeniedAndNoRawOutput() throws {
        let config = try RouterRuntimeCompiler.compile(empty, controllerPort: 19491, secret: secret)
        let core = URL(fileURLWithPath: "/test/core"), directory = root()
        var verified = 0
        let report = try RouterCoreCheck.run(core: core, configuration: config, workspace: directory, loadCore: { value in
            XCTAssertEqual(value, core); verified += 1; return Data("verified-core-bytes".utf8)
        }, execute: { executable, arguments, timeout in
            XCTAssertEqual(executable, "/usr/bin/sandbox-exec")
            XCTAssertTrue(arguments[1].contains("(deny network*)"))
            XCTAssertNotEqual(arguments[2], core.path)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: arguments[2])), Data("verified-core-bytes".utf8))
            XCTAssertEqual(arguments[3], "-t"); XCTAssertEqual(timeout, 15)
            return .init(exitCode: 0, timedOut: false, settled: true)
        })
        XCTAssertEqual(verified, 1); XCTAssertTrue(report.configurationAccepted)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(report), as: UTF8.self).contains(secret))
    }

    func testCheckRejectsFailureTimeoutUnsettledAndChangedFile() throws {
        let config = try RouterRuntimeCompiler.compile(empty, controllerPort: 19491, secret: secret)
        for (result, expected) in [(RouterProcessResult(exitCode: 1, timedOut: false, settled: true), RouterRuntimeError.configurationRejected),
                                   (.init(exitCode: 0, timedOut: true, settled: true), .processTimedOut),
                                   (.init(exitCode: -1, timedOut: true, settled: false), .processUnsettled)] {
            XCTAssertThrowsError(try RouterCoreCheck.run(core: URL(fileURLWithPath: "/core"), configuration: config,
                                                        workspace: root(), loadCore: { _ in Data("core".utf8) }, execute: { _, _, _ in result })) {
                XCTAssertEqual($0 as? RouterRuntimeError, expected)
            }
        }
        XCTAssertThrowsError(try RouterCoreCheck.run(core: URL(fileURLWithPath: "/core"), configuration: config,
                                                    workspace: root(), loadCore: { _ in Data("core".utf8) }, execute: { _, args, _ in
            try Data("{}".utf8).write(to: URL(fileURLWithPath: args.last!))
            return .init(exitCode: 0, timedOut: false, settled: true)
        }))
    }

    func testSourceReplacementAfterReadCannotChangeExecutedCopy() throws {
        let directory = root(), files = RouterRuntimeFiles(root: directory)
        try files.prepare()
        let source = directory.appendingPathComponent("download")
        try files.writeNew(Data("original".utf8), to: source, executable: true)
        let config = try RouterRuntimeCompiler.compile(empty, controllerPort: 19491, secret: secret)
        _ = try RouterCoreCheck.run(core: source, configuration: config, workspace: root(), loadCore: { url in
            let bytes = try Data(contentsOf: url)
            try Data("replacement".utf8).write(to: url)
            return bytes
        }, execute: { _, args, _ in
            XCTAssertNotEqual(args[2], source.path)
            XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: args[2])), Data("original".utf8))
            return .init(exitCode: 0, timedOut: false, settled: true)
        })
    }

    func testPrivateLeafInRenameableSharedParentIsRejected() throws {
        let parent = root()
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: parent.path)
        XCTAssertThrowsError(try RouterRuntimeFiles(root: parent.appendingPathComponent("private")).prepare())
    }

    func testBoundedProcessTimesOutAndSettlesOwnedChild() throws {
        let result = try RouterRuntimeProcess.run("/bin/sleep", ["10"], timeout: 0.05)
        XCTAssertTrue(result.timedOut); XCTAssertTrue(result.settled)
        let success = try RouterRuntimeProcess.run("/usr/bin/true", [], timeout: 1)
        XCTAssertEqual(success.exitCode, 0); XCTAssertFalse(success.timedOut)
    }
}
