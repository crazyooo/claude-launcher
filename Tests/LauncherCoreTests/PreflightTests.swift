import XCTest
import CFNetwork
@testable import LauncherCore

final class PreflightTests: XCTestCase {
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    func report(target: CheckTarget = .desktop, override: [String: CheckResult] = [:], extra: [NetworkCheck] = []) -> PreflightReport {
        let ids = ["baseline", "client", "transport", "unchanged", "service"] + target.hosts.map { "exit:" + $0 } + (target == .vscode ? ["plugin-gate", "code-network", "uniform-proxy"] : [])
        return .init(target: target, startedAt: now, completedAt: now, context: "current",
                     checks: ids.map { .init($0, $0, override[$0] ?? .passed, $0) } + extra, observations: [])
    }
    func testGateRequiresCompleteFreshUnchangedEvidence() {
        XCTAssertTrue(report().permits(context: "current", now: now))
        for id in ["baseline", "client", "transport", "unchanged", "service", "exit:claude.ai"] {
            XCTAssertFalse(report(override: [id: .failed]).permits(context: "current", now: now))
            XCTAssertFalse(report(override: [id: .unknown]).permits(context: "current", now: now))
        }
        XCTAssertFalse(report().permits(context: "other", now: now))
        XCTAssertFalse(report().permits(context: "current", now: now.addingTimeInterval(31)))
        XCTAssertFalse(report().permits(context: "current", now: now.addingTimeInterval(-1)))
        let empty = PreflightReport(target: .desktop, startedAt: now, completedAt: now, context: "current", checks: [], observations: [])
        XCTAssertFalse(empty.permits(context: "current", now: now))
        XCTAssertFalse(report(extra: [.init("service", "duplicate", .passed, "")]).permits(context: "current", now: now))
    }
    func testDiagnosticsDoNotBecomeProtectionClaimsOrBlockGate() {
        XCTAssertTrue(report(extra: [.init("actual-route", "实际连接", .unknown, required: false, "未观测")]).permits(context: "current", now: now))
        XCTAssertFalse(report(target: .vscode, override: ["plugin-gate": .unknown]).permits(context: "current", now: now))
    }
    func testTraceRejectsRedirectChallengeMissingTLSAndDuplicateFields() {
        let valid = "ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n"
        XCTAssertEqual(TraceResponse.parse(valid, status: 200)?.ip, "203.0.113.43")
        for status in [301, 401, 403, 429, 500] { XCTAssertNil(TraceResponse.parse(valid, status: status)) }
        XCTAssertNil(TraceResponse.parse(valid + "ip=192.0.2.1\n", status: 200))
        XCTAssertNil(TraceResponse.parse("<html>challenge</html>", status: 200))
        XCTAssertNil(TraceResponse.parse("ip=203.0.113.43\nloc=US\n", status: 200))
    }
    func testBaselineNeverLearnsUnexpectedIPv4OrIPv6() throws {
        var s = PreflightSettings(); s.expectedIP = "203.0.113.43"; try s.validate()
        XCTAssertTrue(s.matches("203.0.113.43")); XCTAssertFalse(s.matches("192.0.2.1")); XCTAssertFalse(s.matches("2001:db8::1"))
        s.expectedIPv6 = "2001:db8::1"; XCTAssertThrowsError(try s.validate())
        XCTAssertFalse(s.matches("2001:db8:0:0:0:0:0:1")); XCTAssertFalse(s.matches("203.0.113.43"))
        s.expectedIP = ""; XCTAssertThrowsError(try s.validate())
    }
    func testProxyParserRejectsCredentialsAndCanonicalizesIPv6() {
        XCTAssertEqual(ProbeTransport.explicit("http://[::1]:1082").proxy, "http://[::1]:1082")
        XCTAssertEqual(ProbeTransport.explicit("http://127.0.0.1:1082").proxy, "http://127.0.0.1:1082")
        for bad in ["http://name:password@localhost:1082", "http://localhost:0", "http://localhost:1082/path", "file:///tmp/proxy", "http://localhost:1082?token=x"] {
            XCTAssertNotNil(ProbeTransport.explicit(bad).error)
        }
    }
    func testCodeEnvironmentPreservesUnrelatedValuesAndRejectsSOCKS() throws {
        let env = try ClientInspection.codeEnvironment(["PATH":"keep", "CUSTOM":"keep", "HTTP_PROXY":"old", "ALL_PROXY":"old"], transport: .init(proxy: "http://127.0.0.1:1082"))
        XCTAssertEqual(env["PATH"], "keep"); XCTAssertEqual(env["CUSTOM"], "keep")
        XCTAssertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:1082"); XCTAssertNil(env["ALL_PROXY"])
        XCTAssertThrowsError(try ClientInspection.codeEnvironment([:], transport: .init(proxy: "socks5h://127.0.0.1:1082")))
        XCTAssertNotEqual(ClientInspection.environmentFingerprint([:]), ClientInspection.environmentFingerprint(["NODE_OPTIONS":"--require changed.js"]))
    }
    func testJSONCDoesNotStripURLStrings() throws {
        let source = "{ // comment\n \"http.proxy\": \"http://127.0.0.1:1082\", /* block */ \"array\": [1,2,], }"
        let parsed = try JSONSerialization.jsonObject(with: Data(JSONComments.strip(source).utf8)) as! [String: Any]
        XCTAssertEqual(parsed["http.proxy"] as? String, "http://127.0.0.1:1082")
        XCTAssertEqual(parsed["array"] as? [Int], [1,2])
    }
    func testRejectsArbitraryExecutableWithoutLaunching() {
        XCTAssertFalse(ClientInspection.validateWrappedBinary("/bin/echo"))
        XCTAssertFalse(ClientInspection.validateWrappedBinary("/Applications/Claude.app/Contents/MacOS/Claude"))
    }
    func testSystemHTTPSProxyMeansHTTPConnectAndPACDoesNotFallback() {
        let p = ProbeTransport.systemEntry([kCFProxyTypeKey as String: kCFProxyTypeHTTPS,
                                           kCFProxyHostNameKey as String:"127.0.0.1", kCFProxyPortNumberKey as String:1082])
        XCTAssertEqual(p.proxy,"http://127.0.0.1:1082")
        XCTAssertNotNil(ProbeTransport.systemEntry([kCFProxyTypeKey as String:kCFProxyTypeAutoConfigurationURL]).error)
    }
    func testProbeHandlesExitDriftTimeoutTLSAndChallengeWithoutLeakingBody() {
        var s = PreflightSettings(); s.expectedIP = "203.0.113.43"
        let transport = ProbeTransport(proxy:"http://127.0.0.1:1082")
        func run(_ code: Int32, _ body: String) -> DomainObservation {
            NetworkInspector.probeResult(host:"claude.ai", transport:transport, settings:s) { args in
                XCTAssertEqual(args.first,"-q"); XCTAssertTrue(args.contains("--noproxy")); XCTAssertFalse(args.contains("--insecure")); XCTAssertFalse(args.contains("--location"))
                return CommandOutput(code:code,text:body)
            }
        }
        XCTAssertEqual(run(0,"ip=203.0.113.43\nloc=US\ntls=TLSv1.3\n\n__STATUS__200").check.result,.passed)
        XCTAssertEqual(run(0,"ip=192.0.2.9\nloc=US\ntls=TLSv1.3\n\n__STATUS__200").check.result,.failed)
        for code: Int32 in [7,28,60] { XCTAssertEqual(run(code,"private-response-must-not-be-logged").check.result,.failed) }
        let challenge=run(0,"private-response-must-not-be-logged\n__STATUS__403")
        XCTAssertEqual(challenge.check.result,.unknown);XCTAssertFalse(challenge.check.detail.contains("private-response"))
        let unknown = NetworkInspector.probeResult(host:"claude.ai",transport:.init(error:"unknown"),settings:s) { _ in XCTFail("must not send probe");return .init(code:0,text:"") }
        XCTAssertEqual(unknown.check.result,.unknown)
    }
    func testBatchSharesOnlyMatchingProbesWithinOneRound() {
        let batch = NetworkProbeBatch(); let lock = NSLock(); var calls = 0
        DispatchQueue.concurrentPerform(iterations: 6) { _ in
            let value = batch.service(key: "api|proxy-a") {
                lock.lock(); calls += 1; lock.unlock()
                Thread.sleep(forTimeInterval: 0.01)
                return .init("service", "HTTPS", .passed, "fixture")
            }
            XCTAssertEqual(value.result,.passed)
        }
        XCTAssertEqual(calls,1)
        _ = batch.service(key:"api|proxy-b") { calls += 1; return .init("service","HTTPS",.failed,"other route") }
        XCTAssertEqual(calls,2)
        _ = NetworkProbeBatch().service(key:"api|proxy-a") { calls += 1;return .init("service","HTTPS",.passed,"new round") }
        XCTAssertEqual(calls,3)
        _ = batch.service(key:"network-1|api|proxy-a") { calls += 1;return .init("service","HTTPS",.passed,"old network") }
        let changed = batch.service(key:"network-2|api|proxy-a") { calls += 1;return .init("service","HTTPS",.failed,"changed network") }
        XCTAssertEqual(calls,5);XCTAssertEqual(changed.result,.failed)
    }
}
