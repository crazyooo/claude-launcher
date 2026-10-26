import XCTest
@testable import LauncherCore

final class EnvironmentTests: XCTestCase {
    private let digest = String(repeating: "a", count: 64)
    private var settings: EnvironmentSettings {
        var result = EnvironmentSettings(); result.expectedIP = "203.0.113.43"
        result.diagnosticProxy = "http://127.0.0.1:1082"; return result
    }
    private func source(serviceStatus: String = "401", trace: String? = nil, curlCode: Int32 = 0) -> EnvironmentInspectionSource {
        .init(network: { .init(fingerprint: self.digest, readable: true) },
              systemRoute: { _ in .init(proxy: "http://127.0.0.1:8080") }, files: { _ in [] },
              readConfiguration: { _ in [:] }, command: { args in
                  .init(code: curlCode, text: args.contains("--head") ? serviceStatus : (trace ?? "ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n__STATUS__200"))
              }, supplemental: { [] })
    }
    private func inspect(_ target: EnvironmentTarget = .desktop, settings value: EnvironmentSettings? = nil,
                         environment: [String: String]? = [:], source custom: EnvironmentInspectionSource? = nil) -> EnvironmentReport {
        EnvironmentInspector.inspect(target: target, settings: value ?? settings, directory: "/mock-project",
                                     environment: environment, source: custom ?? source())
    }
    private func conclusion(_ report: EnvironmentReport, settings value: EnvironmentSettings? = nil) -> EnvironmentRecommendation {
        report.recommendation(settings: value ?? settings, currentNetwork: digest)
    }

    func testDesktopDiagnosticAndTerminalUseIndependentRoutingSources() {
        let desktop = inspect(), diagnostic = inspect(.diagnostic), cli = inspect(.cli)
        XCTAssertTrue(desktop.observations.allSatisfy { $0.transport == "http://127.0.0.1:8080" && $0.source == .systemProxySelection })
        XCTAssertTrue(diagnostic.observations.allSatisfy { $0.transport == settings.diagnosticProxy && $0.source == .explicitDiagnosticProxy })
        XCTAssertTrue(cli.observations.allSatisfy { $0.source == .systemNetworkRoute })
        XCTAssertEqual(conclusion(cli), .ready)
    }
    func testCLIWithoutProxyExplicitlyDisablesSystemHTTPProxyForCurl() {
        var mock = source()
        mock.command = { args in
            XCTAssertEqual(args[args.firstIndex(of: "--proxy")! + 1], "")
            XCTAssertEqual(args[args.firstIndex(of: "--noproxy")! + 1], "")
            XCTAssertEqual(args.first, "-q")
            return .init(code: 0, text: args.contains("--head") ? "401" : "ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n__STATUS__200")
        }
        XCTAssertEqual(conclusion(inspect(.cli, source: mock)), .ready)
    }
    func testMissingCLIContextAndPACDoNotTriggerProbe() {
        var mock = source(); mock.command = { _ in XCTFail("unresolved path must not probe"); return .init(code: -1, text: "") }
        XCTAssertEqual(conclusion(inspect(.cli, environment: nil, source: mock)), .unknown)
        mock.systemRoute = { _ in .init(error: "PAC") }
        XCTAssertEqual(conclusion(inspect(.desktop, source: mock)), .unknown)
        var noProxy = settings; noProxy.diagnosticProxy = ""
        XCTAssertEqual(conclusion(inspect(.diagnostic, settings: noProxy, source: mock), settings: noProxy), .unknown)
    }
    func testNoProxyExactSuffixWildcardAndPortHaveNoLookalikeMatches() {
        XCTAssertEqual(EnvironmentRoutes.bypass("claude.ai", host: "claude.ai"), true)
        XCTAssertEqual(EnvironmentRoutes.bypass("claude.ai", host: "sub.claude.ai"), false)
        XCTAssertEqual(EnvironmentRoutes.bypass(".claude.ai", host: "sub.claude.ai"), true)
        XCTAssertEqual(EnvironmentRoutes.bypass("*.claude.ai", host: "claude.ai"), true)
        XCTAssertEqual(EnvironmentRoutes.bypass(".claude.ai", host: "evilclaude.ai"), false)
        XCTAssertEqual(EnvironmentRoutes.bypass(".claude.ai", host: "claude.ai.evil.test"), false)
        XCTAssertEqual(EnvironmentRoutes.bypass("*", host: "api.anthropic.com"), true)
        XCTAssertEqual(EnvironmentRoutes.bypass("claude.ai:80", host: "claude.ai"), false)
        XCTAssertEqual(EnvironmentRoutes.bypass("claude.ai:443", host: "claude.ai"), true)
        for invalid in ["https://claude.ai", "10.0.0.0/8", "cl*ude.ai", "claude.ai,,", "* , https://bad"] {
            XCTAssertNil(EnvironmentRoutes.bypass(invalid, host: "claude.ai"))
        }
    }
    func testNoProxyIsAppliedPerHost() {
        let report = inspect(.cli, environment: ["HTTPS_PROXY": settings.diagnosticProxy, "NO_PROXY": "claude.ai"])
        XCTAssertEqual(report.observations.first { $0.host == "claude.ai" }?.source, .noProxyBypass)
        XCTAssertEqual(report.observations.first { $0.host == "api.anthropic.com" }?.source, .terminalConfiguration)
    }
    func testAmbiguousAndCustomCLISettingsStayUnknown() {
        let samples = [
            ["HTTPS_PROXY": "http://127.0.0.1:8080", "https_proxy": "http://127.0.0.1:8081"],
            ["NO_PROXY": "claude.ai", "no_proxy": "api.anthropic.com"],
            ["HTTPS_PROXY": "socks5h://127.0.0.1:1080"],
            ["ALL_PROXY": "http://localhost:8080"],
            ["HTTPS_PROXY": "", "https_proxy": "http://localhost:8080"],
            ["NODE_TLS_REJECT_UNAUTHORIZED": "0"], ["ANTHROPIC_BASE_URL": "https://secret.test"],
            ["CLAUDE_CONFIG_DIR": "/private/secret"], ["NODE_OPTIONS": "--require private.js"],
            ["CLAUDE_CODE_PROCESS_WRAPPER": "/private/old-wrapper"]
        ]
        var mock = source(); mock.command = { _ in XCTFail("unresolved settings must not probe"); return .init(code: -1, text: "") }
        for env in samples { XCTAssertEqual(conclusion(inspect(.cli, environment: env, source: mock)), .unknown) }
        mock.files = { _ in [URL(fileURLWithPath: "/mock-settings.json")] }
        mock.readConfiguration = { _ in ["env": ["HTTPS_PROXY": "http://127.0.0.1:9999"]] }
        XCTAssertEqual(conclusion(inspect(.cli, environment: ["HTTPS_PROXY": settings.diagnosticProxy], source: mock)), .unknown)
        mock.readConfiguration = { _ in ["env": ["HTTPS_PROXY": 123]] }
        XCTAssertEqual(conclusion(inspect(.cli, source: mock)), .unknown)
    }
    func testProxyValidationRejectsCredentialsControlsAndMalformedHost() {
        for value in ["http://user:secret@localhost:80", "http://localhost%00:80", "http://bad host:80", "http://bad..host:80", "http://127.0.0.1:80\n", "http://127.0.0.1:65536", "http://127.0.0.1:80?q=secret"] {
            XCTAssertNotNil(EnvironmentRoutes.validatedProxy(value).error)
        }
        XCTAssertNil(EnvironmentRoutes.validatedProxy("socks5h://[::1]:1080").error)
        XCTAssertNil(EnvironmentRoutes.validatedProxy("https://proxy.example:443").error)
    }
    func testUnauthorizedAndForbiddenAreNetworkSuccessAndBusinessUnknown() {
        for status in ["401", "403"] {
            let report = inspect(source: source(serviceStatus: status))
            XCTAssertEqual(report.checks.first { $0.id == "network:claude.ai" }?.result, .passed)
            XCTAssertEqual(report.checks.first { $0.id == "business:claude.ai" }?.result, .unknown)
            XCTAssertEqual(conclusion(report), .ready)
        }
    }
    func testRateLimitsServerFailuresTLSAndMalformedResponseAreDistinct() {
        for status in ["429", "503"] {
            XCTAssertEqual(conclusion(inspect(source: source(serviceStatus: status))), .attention)
            XCTAssertEqual(conclusion(inspect(source: source(trace: "error\n__STATUS__" + status))), .attention)
        }
        let tls = inspect(source: source(curlCode: 60))
        XCTAssertEqual(conclusion(tls), .attention)
        XCTAssertTrue(tls.checks.contains { $0.code == "tls_failed" })
        XCTAssertEqual(conclusion(inspect(source: source(serviceStatus: "000"))), .unknown)
        XCTAssertEqual(conclusion(inspect(source: source(trace: "<html>challenge</html>\n__STATUS__403"))), .unknown)
        XCTAssertEqual(conclusion(inspect(source: source(trace: "ip=1.2.3.4\nloc=US\ntls=TLSv1.3\n__STATUS__200"))), .attention)
    }
    func testTLSFailureAttributionSplitsResetTimeoutAndCertificate() {
        func outcome(_ code: Int32, _ text: String) -> String {
            EnvironmentInspector.transportOutcome(.init(code: code, text: text))
        }
        XCTAssertEqual(outcome(35, "\n__STATUS__000\n__CURL__35|LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to claude.ai:443 "), "tls_reset")
        XCTAssertEqual(outcome(28, "\n__STATUS__000\n__CURL__28|curl: (28) SSL connection timeout"), "tls_timeout")
        XCTAssertEqual(outcome(28, "\n__CURL__28|Failed to connect to 10.255.255.1 port 9999 after 3006 ms: Timeout was reached"), "probe_timeout")
        XCTAssertEqual(outcome(35, "\n__CURL__35|SSL certificate problem: unable to get local issuer certificate"), "tls_certificate")
        XCTAssertEqual(outcome(60, ""), "tls_failed")
        XCTAssertEqual(outcome(7, ""), "connect_failed")
        XCTAssertEqual(outcome(6, ""), "dns_failed")
        XCTAssertEqual(outcome(-1, ""), "transport_failed")
        XCTAssertEqual(EnvironmentInspector.curlError(.init(code: 35, text: "\n__CURL__35|reset ")), "reset")
        XCTAssertEqual(EnvironmentInspector.curlError(.init(code: 35, text: "")), "")
    }
    func testTunnelTLSResetReportsLineBlockingInsteadOfGenericTLSFailure() {
        let reset = "\n__STATUS__000\n__CURL__35|LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to claude.ai:443 "
        var mock = source()
        mock.command = { _ in .init(code: 35, text: reset) }
        let report = inspect(source: mock)
        let exit = report.checks.first { $0.id == "exit:claude.ai" }
        XCTAssertEqual(exit?.code, "tls_reset")
        XCTAssertTrue(exit?.detail.contains("换节点或线路") ?? false)
        XCTAssertTrue(exit?.detail.contains("SSL_ERROR_SYSCALL") ?? false)
        XCTAssertNil(report.observations.first { $0.host == "claude.ai" }?.ip)
        XCTAssertEqual(conclusion(report), .attention)
    }
    func testWriteOutTailOnSuccessKeepsTraceAndServiceParsing() {
        var mock = source()
        mock.command = { args in
            args.contains("--head")
                ? .init(code: 0, text: "\n__STATUS__401\n__CURL__0|")
                : .init(code: 0, text: "ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n__STATUS__200\n__CURL__0|")
        }
        let report = inspect(source: mock)
        XCTAssertEqual(report.checks.first { $0.id == "exit:claude.ai" }?.code, "exit_match")
        XCTAssertEqual(report.checks.first { $0.id == "network:claude.ai" }?.code, "network_ok")
        XCTAssertEqual(conclusion(report), .ready)
    }
    func testTransientJitterRetriesOnceWhileCertificateFailureDoesNot() {
        let reset = "\n__STATUS__000\n__CURL__35|LibreSSL SSL_connect: SSL_ERROR_SYSCALL in connection to claude.ai:443 "
        let certificate = "\n__STATUS__000\n__CURL__35|SSL certificate problem: unable to get local issuer certificate"
        let success = "ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n__STATUS__200\n__CURL__0|"
        final class Attempts: @unchecked Sendable {
            private let lock = NSLock(); private var values: [String: Int] = [:]
            func bump(_ key: String) -> Int { lock.lock(); defer { lock.unlock() }; values[key, default: 0] += 1; return values[key]! }
        }
        // claude.ai fails once per probe kind, then recovers; platform never fails.
        func run(with failure: String) -> (report: EnvironmentReport, count: Int) {
            let attempts = Attempts(); var count = 0; let lock = NSLock()
            var mock = source()
            mock.command = { args in
                lock.lock(); count += 1; lock.unlock()
                let head = args.contains("--head")
                guard (args.last ?? "").contains("claude.ai") else {
                    return .init(code: 0, text: head ? "\n__STATUS__401\n__CURL__0|" : success)
                }
                let key = head ? "svc" : "exit"
                return attempts.bump(key) == 1
                    ? .init(code: 35, text: failure)
                    : .init(code: 0, text: head ? "\n__STATUS__401\n__CURL__0|" : success)
            }
            return (inspect(source: mock), count)
        }
        let jitter = run(with: reset)
        XCTAssertEqual(jitter.report.checks.first { $0.id == "exit:claude.ai" }?.code, "exit_match")
        XCTAssertEqual(jitter.count, 5, "desktop: claude.ai 出口+服务各重试 1 次，platform 出口 1 次")
        let stable = run(with: certificate)
        XCTAssertEqual(stable.report.checks.first { $0.id == "exit:claude.ai" }?.code, "tls_certificate")
        XCTAssertEqual(stable.count, 3, "确定性失败不重试：claude.ai 出口+服务各 1 次，platform 出口 1 次")
    }
    func testBlankBaselineRemainsUnknownAndNotificationsDoNotInvalidate() {
        var value = settings; value.expectedIP = ""
        XCTAssertEqual(conclusion(inspect(settings: value), settings: value), .unknown)
        var changed = settings; changed.notifications.toggle()
        XCTAssertEqual(conclusion(inspect(), settings: changed), .ready)
    }
    func testEnvironmentChangesDuringProbeInvalidate() {
        var count = 0, mock = source()
        mock.network = { count += 1; return .init(fingerprint: count == 1 ? self.digest : String(repeating: "b", count: 64), readable: true) }
        XCTAssertEqual(conclusion(inspect(source: mock)), .attention)
        var reads = 0; mock = source(); mock.files = { _ in [URL(fileURLWithPath: "/mock.json")] }
        mock.readConfiguration = { _ in reads += 1; return ["env": ["HTTPS_PROXY": reads == 1 ? "http://localhost:8000" : "http://localhost:9000"]] }
        XCTAssertEqual(conclusion(inspect(.cli, source: mock)), .attention)
    }
    func testAgeClockRollbackAndIncompleteEvidenceCannotPass() {
        let report = inspect()
        XCTAssertEqual(report.recommendation(settings: settings, currentNetwork: digest, now: report.startedAt.addingTimeInterval(301)), .stale)
        XCTAssertEqual(report.recommendation(settings: settings, currentNetwork: digest, now: report.startedAt.addingTimeInterval(-1)), .stale)
        XCTAssertEqual(report.recommendation(settings: settings, currentNetwork: String(repeating: "b", count: 64)), .stale)
        for checks in [Array(report.checks.dropFirst()), report.checks + [report.checks[0]]] {
            let invalid = EnvironmentReport(target: report.target, startedAt: report.startedAt, completedAt: report.completedAt,
                networkFingerprint: report.networkFingerprint, configurationFingerprint: report.configurationFingerprint,
                context: report.context, checks: checks, observations: report.observations)
            XCTAssertEqual(conclusion(invalid), .unknown)
        }
    }
    func testReportPersistsOnlyRedactedCLIContextAndRejectsWrongTarget() throws {
        let root = try temporaryDirectory(), file = root.appendingPathComponent("cli.json")
        let report = inspect(.cli, environment: ["ANTHROPIC_API_KEY": "secret-token-sentinel", "UNRELATED": "private-value"])
        try EnvironmentReportStore.saveCLI(report, at: file)
        let data = try Data(contentsOf: file), text = String(decoding: data, as: UTF8.self)
        for value in ["secret-token-sentinel", "private-value", "/mock-project", "ANTHROPIC_API_KEY"] { XCTAssertFalse(text.contains(value)) }
        XCTAssertEqual(try EnvironmentReportStore.latestCLI(at: file)?.id, report.id)
        XCTAssertThrowsError(try EnvironmentReportStore.saveCLI(inspect(), at: file))
        try Data("{}".utf8).write(to: file)
        XCTAssertThrowsError(try EnvironmentReportStore.latestCLI(at: file))
    }
    private func temporaryDirectory() throws -> URL {
        let url = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("environment-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    func testStorageDirectoryHintSurvivesFirstCreationButSymlinksAreRejected() throws {
        let root = try temporaryDirectory()
        let child = URL(fileURLWithPath: root.appendingPathComponent("new-directory").path, isDirectory: false)
        try EnvironmentStorage.ensureDirectory(child)
        try EnvironmentStorage.ensureDirectory(child)
        let file = child.appendingPathComponent("record.json")
        try EnvironmentStorage.writeBytes(Data("{}".utf8), to: file)
        XCTAssertEqual(try EnvironmentStorage.readBytes(file), Data("{}".utf8))
        let link = root.appendingPathComponent("linked")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: child)
        XCTAssertThrowsError(try EnvironmentStorage.ensureDirectory(link))
        XCTAssertThrowsError(try EnvironmentStorage.readBytes(link.appendingPathComponent("record.json")))
    }
    func testSettingsMissingDefaultsMigrationAndAtomicPermissions() throws {
        let root = try temporaryDirectory(), file = root.appendingPathComponent("environment.json"), legacy = root.appendingPathComponent("legacy.json")
        let initial = try EnvironmentSettings.read(at: file, legacy: legacy)
        XCTAssertEqual(initial.expectedIP, "203.0.113.43")
        XCTAssertFalse(FileManager.default.fileExists(atPath: file.path))
        try initial.save(at: file, legacy: legacy)
        XCTAssertEqual(try EnvironmentSettings.readIfPresent(at: file), initial)
        XCTAssertEqual((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue, 0o600)
        let other = root.appendingPathComponent("migrated.json")
        var old = PreflightSettings(); old.expectedIP = "1.2.3.4"; old.notifications = false
        try JSONEncoder().encode(old).write(to: legacy)
        let migrated = try EnvironmentSettings.read(at: other, legacy: legacy)
        XCTAssertEqual(migrated.expectedIP, "1.2.3.4"); XCTAssertFalse(migrated.notifications)
    }
    func testMalformedSettingsAndDanglingLinksNeverBecomeDefaults() throws {
        let root = try temporaryDirectory(), file = root.appendingPathComponent("environment.json"), legacy = root.appendingPathComponent("legacy.json")
        try Data("bad".utf8).write(to: file)
        XCTAssertThrowsError(try EnvironmentSettings.read(at: file, legacy: legacy))
        XCTAssertEqual(try Data(contentsOf: file), Data("bad".utf8))
        let link = root.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: root.appendingPathComponent("missing.json"))
        XCTAssertThrowsError(try EnvironmentSettings.read(at: link, legacy: legacy))
        try Data("broken legacy".utf8).write(to: legacy)
        XCTAssertThrowsError(try EnvironmentSettings.read(at: root.appendingPathComponent("absent.json"), legacy: legacy))
        let future = root.appendingPathComponent("future.json")
        try Data("{\"version\":2,\"expectedIP\":\"1.2.3.4\",\"diagnosticProxy\":\"\"}".utf8).write(to: future)
        XCTAssertThrowsError(try EnvironmentSettings.read(at: future, legacy: legacy))
    }
    func testConcurrentSettingsAndLegacyChangesDoNotOverwrite() throws {
        let root = try temporaryDirectory(), file = root.appendingPathComponent("environment.json"), legacy = root.appendingPathComponent("legacy.json")
        let old = try EnvironmentSettings.read(at: file, legacy: legacy)
        try old.save(at: file, legacy: legacy)
        var a = try EnvironmentSettings.readIfPresent(at: file)!, b = a
        a.expectedIP = "1.2.3.4"; b.expectedIP = "5.6.7.8"
        try a.save(at: file, legacy: legacy)
        XCTAssertThrowsError(try b.save(at: file, legacy: legacy))
        XCTAssertEqual(try EnvironmentSettings.readIfPresent(at: file)?.expectedIP, "1.2.3.4")
        let absent = root.appendingPathComponent("migration.json")
        let beforeLegacy = try EnvironmentSettings.read(at: absent, legacy: legacy)
        var changed = PreflightSettings(); changed.expectedIP = "9.8.7.6"
        try JSONEncoder().encode(changed).write(to: legacy)
        XCTAssertThrowsError(try beforeLegacy.save(at: absent, legacy: legacy))
        XCTAssertFalse(FileManager.default.fileExists(atPath: absent.path))
    }
}
