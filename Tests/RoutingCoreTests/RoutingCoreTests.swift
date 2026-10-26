import XCTest
import Darwin
@testable import RoutingCore

final class RoutingCoreTests: XCTestCase {
    private let proxyID = UUID(uuidString: "11111111-1111-4111-8111-111111111111")!
    private let ruleID = UUID(uuidString: "22222222-2222-4222-8222-222222222222")!
    private let browser = "/Applications/Example Browser.app/Contents/MacOS/Browser"
    private func plan(kind: RouterProxy.Kind = .http, udp: Bool = false) -> RouterPlan {
        .init(proxies: [.init(id: proxyID, name: "固定出口", kind: kind, host: "127.0.0.1", port: 1082, udp: udp)],
              rules: [.init(id: ruleID, selector: .init(domain: .init(kind: .suffix, value: "claude.ai")), destination: .proxy(proxyID))],
              defaultDestination: .direct)
    }
    private func data(_ plan: RouterPlan) throws -> Data { try JSONEncoder().encode(plan) }
    private func codes(_ plan: RouterPlan) -> [String] { RouterValidation.issues(in: plan).map(\.code) }

    func testRoundtripAndFutureVersionRejected() throws {
        XCTAssertEqual(try RouterInput.plan(data(plan())), plan())
        var changed = plan(); changed.schemaVersion = 2
        XCTAssertEqual(codes(changed), ["unsupported_schema"])
        XCTAssertNil(try MihomoRoutingCompiler.preview(changed).fragment)
    }

    func testIDsAndDestinationsAreValidatedBeforeDictionaryConstruction() throws {
        var value = plan(); value.proxies.append(value.proxies[0]); value.rules.append(value.rules[0])
        XCTAssertTrue(codes(value).contains("duplicate_id"))
        XCTAssertNil(try MihomoRoutingCompiler.preview(value).fragment)
        value = plan(); value.defaultDestination = .proxy(UUID())
        XCTAssertTrue(codes(value).contains("missing_proxy"))
        value.defaultDestination = .init(kind: .direct, proxyID: proxyID)
        XCTAssertTrue(codes(value).contains("unexpected_proxy_id"))
        value = plan(); value.rules[0].destination = .init(kind: .proxy)
        XCTAssertTrue(codes(value).contains("missing_proxy"))
    }

    func testDomainInjectionURLsAndSuffixBoundary() throws {
        for domain in ["https://claude.ai", "claude.ai/path", "*.claude.ai", "claude.ai,REJECT", "claude.ai)", "claude.ai\n", "", "a..b", "127.0.0.1"] {
            var value = plan(); value.rules[0].selector.domain?.value = domain
            XCTAssertTrue(codes(value).contains("invalid_domain"), domain)
        }
        for domain in ["claude.ai", "api.claude.ai", "CLAUDE.AI"] {
            XCTAssertEqual(try RouterExplainer.explain(plan(), flow: .init(domain: domain, transport: .tcp)).destination, .proxy(proxyID))
        }
        XCTAssertEqual(try RouterExplainer.explain(plan(), flow: .init(domain: "evilclaude.ai", transport: .tcp)).destination, .direct)
        var value = plan(); value.rules[0].selector.domain?.kind = .exact
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(domain: "api.claude.ai", transport: .tcp)).destination, .direct)
    }

    func testHostPortAndProtocolValidation() {
        for host in ["127.0.0.1", "::1", "proxy.example.com"] {
            var value = plan(); value.proxies[0].host = host; XCTAssertEqual(codes(value), [])
        }
        for host in ["http://127.0.0.1", "u:password@localhost", "[::1]:1082", "a/b", "x\u{0}y", " fe80::1"] {
            var value = plan(); value.proxies[0].host = host; XCTAssertTrue(codes(value).contains("invalid_host"))
        }
        for port in [0, 65536, -1] {
            var value = plan(); value.proxies[0].port = port; XCTAssertTrue(codes(value).contains("invalid_port"))
        }
        XCTAssertTrue(codes(plan(udp: true)).contains("http_udp_unsupported"))
    }

    func testLiteralProcessPathsAndCompoundRule() throws {
        var value = plan(); value.rules[0].selector.processPath = browser
        let rules = try XCTUnwrap(MihomoRoutingCompiler.preview(value).fragment).rules
        XCTAssertEqual(rules[0], "AND,((PROCESS-PATH,\(browser)),(DOMAIN-SUFFIX,claude.ai),(NETWORK,UDP)),REJECT")
        XCTAssertEqual(rules[1], "AND,((PROCESS-PATH,\(browser)),(DOMAIN-SUFFIX,claude.ai)),route_\(proxyID.uuidString.lowercased())")
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(processPath: browser.lowercased(), domain: "claude.ai", transport: .tcp)).destination, .proxy(proxyID))
        for path in ["Browser", "/Applications/Browser.app", "/tmp/*", "/tmp/a,b", "/tmp/a(b)", "/tmp/../b", "/tmp//b", "/tmp/a\n", "/tmp/中文"] {
            value.rules[0].selector.processPath = path
            XCTAssertTrue(codes(value).contains("invalid_process_path"), path)
        }
    }

    func testUnknownEarlierIdentityCannotFallThroughToLaterRuleOrDefault() throws {
        var value = plan()
        value.rules.insert(.init(id: UUID(), selector: .init(processPath: browser), destination: .block), at: 0)
        let unknown = try RouterExplainer.explain(value, flow: .init(domain: "claude.ai", transport: .tcp))
        XCTAssertEqual(unknown.status, "undetermined"); XCTAssertNil(unknown.destination)
        XCTAssertEqual(unknown.ruleID, value.rules[0].id)
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(processPath: "/usr/bin/other", domain: "claude.ai", transport: .tcp)).destination, .proxy(proxyID))
        value.rules[0].selector.domain = .init(kind: .exact, value: "example.com")
        // Known false AND unknown is false, so the second rule may be evaluated.
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(domain: "claude.ai", transport: .tcp)).destination, .proxy(proxyID))
        XCTAssertEqual(try RouterExplainer.explain(plan(), flow: .init(transport: .tcp)).status, "undetermined")
    }

    func testUDPBlockingIsScopedAndNeverUsesFallbackGroup() throws {
        for value in [plan(), plan(kind: .socks5)] {
            let fragment = try XCTUnwrap(MihomoRoutingCompiler.preview(value).fragment)
            XCTAssertEqual(fragment.rules.first, "AND,((DOMAIN-SUFFIX,claude.ai),(NETWORK,UDP)),REJECT")
            XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(domain: "claude.ai", transport: .udp)).destination, .block)
            XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(domain: "example.com", transport: .udp)).destination, .direct)
        }
        var value = plan(kind: .socks5, udp: true)
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(domain: "claude.ai", transport: .udp)).destination, .proxy(proxyID))
        XCTAssertEqual(try XCTUnwrap(MihomoRoutingCompiler.preview(value).fragment).rules.count, 2)
        value = plan(); value.rules = []; value.defaultDestination = .proxy(proxyID)
        XCTAssertEqual(try XCTUnwrap(MihomoRoutingCompiler.preview(value).fragment).rules.first, "NETWORK,UDP,REJECT")
        XCTAssertEqual(try RouterExplainer.explain(value, flow: .init(transport: .udp)).destination, .block)
    }

    func testDuplicateAndShadowedSelectors() {
        var value = plan()
        value.rules.append(.init(id: UUID(), selector: value.rules[0].selector, destination: .block))
        XCTAssertTrue(codes(value).contains("duplicate_selector"))
        value.rules[1].selector.domain = .init(kind: .exact, value: "api.claude.ai")
        XCTAssertTrue(codes(value).contains("shadowed_by_earlier_rule"))
        value.rules.reverse()
        XCTAssertEqual(codes(value), [])
    }

    func testDisplayNamesCannotInjectRulesAndIDsRemainStable() throws {
        let original = try XCTUnwrap(MihomoRoutingCompiler.preview(plan()).fragment)
        var value = plan(); value.proxies[0].name = "DIRECT,REJECT,(test)"
        let renamed = try XCTUnwrap(MihomoRoutingCompiler.preview(value).fragment)
        XCTAssertEqual(original.rules, renamed.rules)
        XCTAssertEqual(original.proxies[0].name, renamed.proxies[0].name)
    }

    func testCredentialsBlockFragmentAndAreNeverExported() throws {
        var value = plan(); let secretReference = UUID(); value.proxies[0].credentialReference = secretReference
        let preview = try MihomoRoutingCompiler.preview(value)
        XCTAssertNil(preview.fragment)
        XCTAssertTrue(preview.issues.contains { $0.code == "credential_resolution_not_implemented" })
        let encoded = String(decoding: try JSONEncoder().encode(preview), as: UTF8.self)
        XCTAssertFalse(encoded.contains(secretReference.uuidString))
        XCTAssertFalse(preview.deployable); XCTAssertFalse(preview.runtimeVerified); XCTAssertFalse(preview.networkModified)
    }

    func testStrictUnknownFieldAndMissingFieldHandling() throws {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data(plan())) as? [String: Any])
        object["password"] = "SECRET_DO_NOT_ECHO"
        XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "password")
        var rules = object["rules"] as! [[String: Any]]
        rules[0]["selector"] = ["domain": ["kind": "suffix", "value": "claude.ai"], "processPth": browser]
        object["rules"] = rules
        XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: object)))
        object.removeValue(forKey: "defaultDestination")
        XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: object)))
        XCTAssertThrowsError(try RouterInput.flow(Data("{\"transport\":\"tcp\",\"domain\":\"https://claude.ai\"}".utf8)))
    }

    func testLimitsAndMalformedInput() throws {
        XCTAssertThrowsError(try RouterInput.plan(Data(repeating: 32, count: RouterInput.maximumBytes + 1)))
        XCTAssertThrowsError(try RouterInput.plan(Data("{\"token\":\"secret\"".utf8)))
        var value = plan(); value.rules = Array(repeating: value.rules[0], count: 513)
        XCTAssertEqual(codes(value), ["item_limit_exceeded"])
        XCTAssertThrowsError(try RouterInput.plan(data(value)))
    }

    func testRequiredTypesAndEnumValuesAreNotCoerced() throws {
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: data(plan())) as? [String: Any])
        for invalid: Any in [true, "1", NSNull(), 1.5] {
            var value = original; value["schemaVersion"] = invalid
            XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: value)))
        }
        for invalid: Any in [true, "1082", NSNull(), 1082.5] {
            var value = original; var proxies = value["proxies"] as! [[String: Any]]
            proxies[0]["port"] = invalid; value["proxies"] = proxies
            XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: value)))
        }
        var value = original; value["defaultDestination"] = ["kind": "fallback"]
        XCTAssertThrowsError(try RouterInput.plan(JSONSerialization.data(withJSONObject: value)))
        XCTAssertThrowsError(try RouterInput.flow(Data("{\"transport\":\"quic\"}".utf8)))
    }

    func testCommandUsesOnlyRequestedInputsAndSanitizesErrors() throws {
        var reads: [String] = []
        let value = try data(plan())
        let validated = RouterCommand.run(["validate", "input"], readFile: { reads.append($0); return value })
        XCTAssertEqual(validated.exitCode, 0); XCTAssertEqual(reads, ["input"])
        XCTAssertEqual(RouterCommand.run(["apply", "input"], readFile: { _ in XCTFail("must not read"); return value }).exitCode, 64)
        let malformed = RouterCommand.run(["preview", "SECRET_FILENAME"], readFile: { _ in Data("SECRET_CONTENT".utf8) })
        XCTAssertEqual(malformed.exitCode, 65)
        XCTAssertFalse(String(decoding: malformed.data, as: UTF8.self).contains("SECRET"))
        let unknown = RouterCommand.run(["explain", "input", "flow"], readFile: { $0 == "input" ? value : Data("{\"transport\":\"tcp\"}".utf8) })
        XCTAssertEqual(unknown.exitCode, 3)
    }

    func testLocalReaderRejectsDevicesDirectoriesSymlinksAndFIFO() throws {
        // Keep test artifacts for recovery; no destructive cleanup.
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("router-input-tests-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let file = directory.appendingPathComponent("plan.json")
        let bytes = try data(plan()); try bytes.write(to: file)
        XCTAssertEqual(try RouterInput.read(file.path), bytes)
        let link = directory.appendingPathComponent("link.json")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        let fifo = directory.appendingPathComponent("fifo")
        XCTAssertEqual(mkfifo(fifo.path, 0o600), 0)
        for path in [directory.path, link.path, fifo.path, "/dev/null", "/dev/zero"] {
            XCTAssertThrowsError(try RouterInput.read(path), path)
        }
        let oversized = directory.appendingPathComponent("oversized")
        try Data(repeating: 0, count: RouterInput.maximumBytes + 1).write(to: oversized)
        XCTAssertThrowsError(try RouterInput.read(oversized.path))
    }
}
