import XCTest
@testable import LauncherCore

final class SelectedProxyDiagnosticTests: XCTestCase {
    private func config(_ kind: SelectedProxyConfiguration.Kind = .http, auth: Bool = false,
                        expected: String = "203.0.113.8", host: String = "127.0.0.1", port: Int = 1082) -> SelectedProxyConfiguration {
        .init(id: UUID(), revision: UUID(), credentialReference: auth ? UUID() : nil,
              kind: kind, host: host, port: port, expectedIP: expected)
    }
    private func response(_ text: String, exit: Int32? = 0, complete: Bool = true,
                          settled: Bool = true, cancelled: Bool = false, timeout: Bool = false) -> BoundedProcess.Diagnostic {
        .init(data: Data(text.utf8), exitCode: exit, complete: complete, settled: settled, cancelled: cancelled, timedOut: timeout)
    }
    private let trace = "ip=203.0.113.8\nloc=US\ntls=TLSv1.3\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__200:200"

    func testCredentialEscapingIsOnlyInStdinAndProxyNeverFallsBackToDirect() throws {
        for kind in [SelectedProxyConfiguration.Kind.http, .socks5] {
            let secret = SelectedProxySecret(username: "user\\\"name", password: "p:a\\ss\"word")
            let call = try SelectedProxyDiagnostic.invocation(config(kind, auth: true), secret: secret, host: "claude.ai", timeout: 8)
            XCTAssertEqual(Array(call.arguments.prefix(3)), ["-q", "--config", "-"])
            XCTAssertFalse(call.arguments.joined().contains(secret.username))
            XCTAssertFalse(call.arguments.joined().contains(secret.password))
            XCTAssertEqual(String(decoding: call.input, as: UTF8.self), "proxy-user = \"user\\\\\\\"name:p:a\\\\ss\\\"word\"\n")
            XCTAssertEqual(call.arguments[try XCTUnwrap(call.arguments.firstIndex(of: "--noproxy")) + 1], "")
            XCTAssertEqual(call.arguments[try XCTUnwrap(call.arguments.firstIndex(of: "--proxy")) + 1],
                           kind == .http ? "http://127.0.0.1:1082" : "socks5h://127.0.0.1:1082")
            XCTAssertFalse(call.arguments.contains("--location")); XCTAssertFalse(call.arguments.contains("--insecure"))
            XCTAssertTrue(call.arguments.contains(kind == .http ? "--proxy-basic" : "--socks5-basic"))
        }
    }
    func testCredentialInjectionProtocolLimitsAndInvalidTargetsAreRejected() throws {
        for bad in ["\nurl=https://evil.invalid", "bad\r", "bad\t", "bad\0"] {
            for secret in [SelectedProxySecret(username: bad, password: "ok"), .init(username: "ok", password: bad)] {
                XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config(auth: true), secret: secret, host: "claude.ai", timeout: 1))
            }
        }
        for secret in [SelectedProxySecret(username: "u:name", password: "ok"),
                       .init(username: String(repeating: "é", count: 128), password: "ok"),
                       .init(username: "ok", password: String(repeating: "x", count: 256))] {
            XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config(.socks5, auth: true), secret: secret, host: "claude.ai", timeout: 1))
        }
        XCTAssertNoThrow(try SelectedProxyDiagnostic.invocation(config(.socks5, auth: true),
            secret: .init(username: "ok", password: String(repeating: "x", count: 255)), host: "claude.ai", timeout: 1))
        for host in ["user@host", "evil/path", "[::1]", "::1%lo0", "host\nother", ""] {
            XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config(host: host), secret: nil, host: "claude.ai", timeout: 1))
        }
        XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config(), secret: nil, host: "arbitrary.invalid", timeout: 1))
        XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config(auth: true), secret: nil, host: "claude.ai", timeout: 1))
    }
    func testProxyAuthenticationTargetDenialTLSAndSOCKSFailuresStayDistinct() {
        let cases: [(Int32, String, SelectedProxyConfiguration.Kind, String)] = [
            (56, "\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__000:407", .http, "proxy_auth_required"),
            (56, "\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__000:400", .http, "proxy_request_rejected"),
            (97, "\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__000:000", .socks5, "socks_negotiation_failed"),
            (0, "denied\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__403:200", .http, "target_access_denied"),
            (0, "denied\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__401:200", .http, "target_access_denied"),
            (0, "moved\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__302:200", .http, "redirect_not_followed"),
            (0, "slow\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__429:200", .http, "service_rate_limited"),
            (60, "\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__000:200", .http, "tls_failed"),
            (28, "", .http, "probe_timeout"), (7, "", .http, "connect_failed"),
            (5, "", .socks5, "dns_failed"), (0, "html\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__200:200", .http, "exit_unavailable")]
        for (exit, text, kind, expected) in cases {
            let parsed = SelectedProxyDiagnostic.parse(response(text, exit: exit), host: "claude.ai", config: config(kind))
            XCTAssertEqual(parsed.code, expected); XCTAssertNil(parsed.ip)
        }
    }
    func testExitEvidenceRequiresCompleteOutputSettlementAndCONNECT() {
        let c = config()
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(trace), host: "claude.ai", config: c).code, "exit_match")
        for raw in [response(trace, complete: false), response(trace, settled: false), response(trace, cancelled: true),
                    response(trace, timeout: true), response(trace + "unexpected"),
                    response(trace.replacingOccurrences(of: "200:200", with: "200:000")),
                    response("ip=203.0.113.8\n" + trace), response(String(repeating: "x", count: 17000) + trace)] {
            XCTAssertNotEqual(SelectedProxyDiagnostic.parse(raw, host: "claude.ai", config: c).code, "exit_match")
        }
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(trace), host: "claude.ai", config: config(expected: "")).code, "baseline_missing")
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(trace), host: "claude.ai", config: config(expected: "203.0.113.9")).code, "exit_mismatch")
    }
    private func frame(_ error: String = "", body: String = "", statuses: String = "000:000") -> String {
        body + "\n__ROUTER_DIAG_ERROR__" + error + "\n__ROUTER_DIAG__" + statuses
    }
    func testExactSOCKSFailureTemplatesAreProjectedWithoutRawText() {
        for host in SelectedProxyDiagnostic.hosts {
            let cases = [
                ("No authentication method was acceptable.", "socks_method_rejected"),
                ("User was rejected by the SOCKS5 server (1 1).", "socks_auth_rejected"),
                ("Can't complete SOCKS5 connection to \(host). (2)", "socks_connect_rules_rejected"),
                ("Can't complete SOCKS5 connection to \(host). (1)", "socks_connect_failed")]
            for (error, expected) in cases {
                let value = SelectedProxyDiagnostic.parse(response(frame(error), exit: 97), host: host, config: config(.socks5))
                XCTAssertEqual(value.code, expected); XCTAssertEqual(value.result, .failed)
                XCTAssertNil(value.ip); XCTAssertFalse(value.detail.contains(error))
            }
        }
        let call = try! SelectedProxyDiagnostic.invocation(config(.socks5), secret: nil, host: "claude.ai", timeout: 1)
        let writeOut = call.arguments[call.arguments.firstIndex(of: "--write-out")! + 1]
        XCTAssertEqual(writeOut, "\n__ROUTER_DIAG_ERROR__%{errormsg}\n__ROUTER_DIAG__%{http_code}:%{http_connect}")
    }
    func testSOCKSSubclassificationRequiresExactCompleteContext() {
        let exact = "No authentication method was acceptable."
        let variants = [exact + " ", exact + "\n", String(exact.dropLast()),
                        "User was rejected by the SOCKS5 server (1 2).",
                        "Can't complete SOCKS5 connection to claude.ai. (3)",
                        "Can't complete SOCKS5 connection to different.invalid. (2)",
                        "TEST_PRIVATE_USER:TEST_PRIVATE_PASSWORD", String(repeating: "x", count: 17000)]
        for error in variants {
            let value = SelectedProxyDiagnostic.parse(response(frame(error), exit: 97), host: "claude.ai", config: config(.socks5))
            XCTAssertEqual(value.code, "socks_negotiation_failed")
            XCTAssertFalse(value.detail.contains("TEST_PRIVATE")); XCTAssertFalse(value.code.contains("TEST_PRIVATE")); XCTAssertNil(value.ip)
        }
        for raw in [response(frame(exact), exit: 97, complete: false),
                    response(frame(exact, body: "body"), exit: 97),
                    response(frame(exact, statuses: "200:000"), exit: 97),
                    response(frame(exact, statuses: "000:200"), exit: 97),
                    response(frame(exact, statuses: "000:000") + "unexpected", exit: 97)] {
            XCTAssertEqual(SelectedProxyDiagnostic.parse(raw, host: "claude.ai", config: config(.socks5)).code, "socks_negotiation_failed")
        }
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(frame(exact), exit: 97), host: "unknown.invalid", config: config(.socks5)).code, "socks_negotiation_failed")
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(frame(exact), exit: 97), host: "claude.ai", config: config()).code, "socks_negotiation_failed")
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(frame(exact), exit: 7), host: "claude.ai", config: config(.socks5)).code, "connect_failed")
    }
    func testSuccessRequiresEmptyErrorAndUnambiguousMetadata() {
        let body = "ip=203.0.113.8\nloc=US\ntls=TLSv1.3"
        for text in [body + "\n__ROUTER_DIAG__200:200", frame("TEST_PRIVATE_PASSWORD", body: body, statuses: "200:200"),
                     frame(body: body + "\n__ROUTER_DIAG_ERROR__", statuses: "200:200"),
                     frame(body: body + "\n__ROUTER_DIAG__000:000", statuses: "200:200"),
                     frame(body: body, statuses: "200:200") + "\n__ROUTER_DIAG__200:200"] {
            let value = SelectedProxyDiagnostic.parse(response(text), host: "claude.ai", config: config())
            XCTAssertNotEqual(value.code, "exit_match"); XCTAssertFalse(value.detail.contains("TEST_PRIVATE_PASSWORD"))
        }
        XCTAssertEqual(SelectedProxyDiagnostic.parse(response(frame(body: body, statuses: "200:200")), host: "claude.ai", config: config()).code, "exit_match")
    }
    func testSuccessRequiresProxyStatusConsistentWithSelectedProtocol() {
        let body = "ip=203.0.113.8\nloc=US\ntls=TLSv1.3"
        let rows: [(SelectedProxyConfiguration.Kind, String, String)] = [
            (.socks5, "200:000", "exit_match"), (.socks5, "200:200", "proxy_path_unverified"),
            (.socks5, "200:407", "proxy_path_unverified"), (.http, "200:200", "exit_match"),
            (.http, "200:000", "proxy_path_unverified"), (.http, "200:407", "proxy_auth_required")]
        for (kind, statuses, expected) in rows {
            let value = SelectedProxyDiagnostic.parse(response(frame(body: body, statuses: statuses)), host: "claude.ai", config: config(kind))
            XCTAssertEqual(value.code, expected)
            if expected != "exit_match" { XCTAssertNil(value.ip) }
        }
    }
    func testOldCaptureDiscardsNonzeroOutputButDiagnosticEngineKeepsBoundedMetadata() {
        let args = ["-I", "-c", "import sys; sys.stdout.write('metadata'); sys.exit(56)"]
        let old = BoundedProcess.capture(executable: "/usr/bin/python3", arguments: args, timeout: 2)
        XCTAssertFalse(old.complete); XCTAssertTrue(old.data.isEmpty); XCTAssertTrue(old.settled)
        let new = BoundedProcess.run(executable: "/usr/bin/python3", arguments: args, timeout: 2,
                                    input: nil, maximumInput: 16384, cancelled: { false })
        XCTAssertTrue(new.complete); XCTAssertTrue(new.settled); XCTAssertEqual(new.exitCode, 56)
        XCTAssertEqual(new.data, Data("metadata".utf8))
    }
    func testCancellationTimeoutSignalsAndOutputOverflowSettleOwnedChild() {
        let token = SelectedProxyCancellation()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.1) { token.cancel() }
        let stopped = BoundedProcess.run(executable: "/bin/sleep", arguments: ["10"], timeout: 2,
                                        input: nil, maximumInput: 16384, cancelled: { token.cancelled })
        XCTAssertTrue(stopped.cancelled); XCTAssertTrue(stopped.settled); XCTAssertFalse(stopped.complete)
        let precancelled = BoundedProcess.run(executable: "/usr/bin/true", arguments: [], timeout: 1,
                                             input: nil, maximumInput: 16384, cancelled: { true })
        XCTAssertTrue(precancelled.cancelled); XCTAssertNil(precancelled.exitCode)
        let timeout = BoundedProcess.run(executable: "/bin/sleep", arguments: ["10"], timeout: 0.05,
                                        input: nil, maximumInput: 16384, cancelled: { false })
        XCTAssertTrue(timeout.timedOut); XCTAssertTrue(timeout.settled); XCTAssertFalse(timeout.complete)
        for script in ["import os, signal; os.kill(os.getpid(), signal.SIGTERM)", "print('x'*20000)"] {
            let raw = BoundedProcess.run(executable: "/usr/bin/python3", arguments: ["-I", "-c", script], timeout: 2,
                                        input: nil, maximumInput: 16384, cancelled: { false })
            XCTAssertTrue(raw.settled)
            XCTAssertTrue(!raw.complete || raw.exitCode == nil)
        }
    }
    func testStdinIsBoundedAndActualChildReceivesExactBytes() {
        let input = Data(String(repeating: "\\\"字", count: 600).utf8)
        let value = BoundedProcess.run(executable: "/usr/bin/python3", arguments: ["-I", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                                      timeout: 2, input: input, maximumInput: 16384, cancelled: { false })
        XCTAssertTrue(value.complete); XCTAssertEqual(value.data, input)
        let rejected = BoundedProcess.run(executable: "/usr/bin/true", arguments: [], timeout: 1,
                                         input: Data(repeating: 65, count: 16385), maximumInput: 16384, cancelled: { false })
        XCTAssertFalse(rejected.complete); XCTAssertNil(rejected.exitCode)
    }
    func testNonUTF8OutputCannotBecomeExitEvidence() {
        let raw = BoundedProcess.Diagnostic(data: Data([0xff]) + Data(trace.utf8), exitCode: 0,
            complete: true, settled: true, cancelled: false, timedOut: false)
        let value = SelectedProxyDiagnostic.parse(raw, host: "claude.ai", config: config())
        XCTAssertEqual(value.code, "response_incomplete"); XCTAssertNil(value.ip)
    }
    func testPostspawnCancellationDoesNotWriteCredentialStdin() throws {
        let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("line-postspawn-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let ready = directory.appendingPathComponent("ready"), count = directory.appendingPathComponent("count")
        let script = """
        import pathlib, signal, sys
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        pathlib.Path(sys.argv[1]).write_text('ready')
        data = sys.stdin.buffer.read()
        pathlib.Path(sys.argv[2]).write_text(str(len(data)))
        """
        var checks = 0
        let value = BoundedProcess.run(executable: "/usr/bin/python3", arguments: ["-I", "-c", script, ready.path, count.path],
            timeout: 3, input: Data("TEST_CREDENTIAL".utf8), maximumInput: 16384, cancelled: {
                checks += 1
                if checks == 1 { return false }
                if checks == 2 {
                    let deadline = ProcessInfo.processInfo.systemUptime + 1
                    while !FileManager.default.fileExists(atPath: ready.path), ProcessInfo.processInfo.systemUptime < deadline {
                        Thread.sleep(forTimeInterval: 0.005)
                    }
                }
                return true
            })
        XCTAssertTrue(FileManager.default.fileExists(atPath: ready.path))
        XCTAssertTrue(value.cancelled); XCTAssertTrue(value.settled); XCTAssertFalse(value.complete)
        XCTAssertTrue(value.data.isEmpty); XCTAssertEqual(try String(contentsOf: count), "0")
    }
    private final class Runner: @unchecked Sendable {
        let lock = NSLock()
        var calls = 0
        var now: Double = 1
        var unsettled = false
        func run(_ call: SelectedProxyDiagnostic.Invocation, _ cancelled: () -> Bool) -> BoundedProcess.Diagnostic {
            lock.lock(); defer { lock.unlock() }
            calls += 1; now += 3
            return .init(data: Data("ip=203.0.113.8\nloc=US\ntls=TLSv1.3\n__ROUTER_DIAG_ERROR__\n__ROUTER_DIAG__200:200".utf8),
                         exitCode: 0, complete: true, settled: !unsettled, cancelled: cancelled(), timedOut: false)
        }
        func clock() -> Double { lock.lock(); defer { lock.unlock() }; return now }
    }
    func testSharedAbsoluteDeadlineAndUnsettledStopSubsequentTargets() async {
        let r = Runner()
        let result = await SelectedProxyDiagnostic.inspect(config(), secret: nil, cancellation: .init(), until: 5,
                                                           run: { r.run($0, $1) }, uptime: { r.clock() })
        XCTAssertEqual(r.calls, 2); XCTAssertEqual(result.last?.code, "probe_timeout")
        let stalled = Runner(); stalled.unsettled = true
        let values = await SelectedProxyDiagnostic.inspect(config(), secret: nil, cancellation: .init(), until: 25,
                                                           run: { stalled.run($0, $1) }, uptime: { stalled.clock() })
        XCTAssertEqual(stalled.calls, 1); XCTAssertEqual(values.first?.code, "process_unsettled")
    }
}
