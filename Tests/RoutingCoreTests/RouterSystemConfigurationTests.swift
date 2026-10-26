import XCTest
@testable import RoutingCore

final class RouterSystemConfigurationTests: XCTestCase {
    private let secret = String(repeating: "d", count: 64)
    private var plan: RouterPlan { .init(proxies: [], rules: [], defaultDestination: .direct) }
    func testTypedDualStackConfigurationAndResolverBinding() throws {
        var digests = Set<String>()
        for choice in [RouterSystemProfile.Resolver.cloudflare, .quad9] {
            let config = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: choice), secret: secret, credentials: [:])
            let object = try XCTUnwrap(JSONSerialization.jsonObject(with: config.privateJSON) as? [String: Any])
            XCTAssertEqual(object["ipv6"] as? Bool, true)
            let dns = try XCTUnwrap(object["dns"] as? [String: Any])
            let tun = try XCTUnwrap(object["tun"] as? [String: Any])
            XCTAssertEqual(dns["ipv6"] as? Bool, true); XCTAssertEqual(dns["respect-rules"] as? Bool, true)
            XCTAssertEqual(dns["fake-ip-range6"] as? String, RouterSystemCompiler.fakeIPv6)
            XCTAssertEqual(tun["inet6-address"] as? [String], [RouterSystemCompiler.tunIPv6])
            XCTAssertEqual(tun["auto-route"] as? Bool, true)
            XCTAssertNil(dns["listen"])
            XCTAssertNotNil(dns["proxy-server-nameserver"])
            for port in ["port", "socks-port", "mixed-port", "redir-port", "tproxy-port"] { XCTAssertEqual(object[port] as? Int, 0) }
            XCTAssertEqual(config.summary.resolverRoute, "resolver_route_planned_not_verified")
            XCTAssertEqual(config.summary.bootstrapRoute, "direct_control_plane_planned")
            XCTAssertEqual(config.summary.proxyHostnameResolverRoute, "direct_control_plane_planned")
            digests.insert(config.summary.planDigest)
            let publicJSON = String(decoding: try JSONEncoder().encode(config.summary), as: UTF8.self)
            XCTAssertFalse(publicJSON.contains(secret)); XCTAssertFalse(config.summary.routingVerified)
        }
        XCTAssertEqual(digests.count, 2)
    }
    func testPlainResolverUsesUDPLiteralsWithoutHostnameBootstrap() throws {
        let config = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: .plain), secret: secret, credentials: [:])
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: config.privateJSON) as? [String: Any])
        let dns = try XCTUnwrap(object["dns"] as? [String: Any])
        XCTAssertEqual(dns["nameserver"] as? [String], ["223.5.5.5", "119.29.29.29"])
        XCTAssertEqual(dns["proxy-server-nameserver"] as? [String], ["223.5.5.5", "119.29.29.29"])
        XCTAssertEqual(dns["default-nameserver"] as? [String], ["223.5.5.5", "119.29.29.29"])
        XCTAssertEqual(config.summary.resolverDomain, "223.5.5.5")
        XCTAssertEqual(config.summary.resolverRoute, "resolver_route_planned_not_verified")
        // The digest binds the profile: the plain archetype differs from both DoH ones.
        let cloudflare = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:])
        let quad9 = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: .quad9), secret: secret, credentials: [:])
        XCTAssertEqual(Set([config.summary.planDigest, cloudflare.summary.planDigest, quad9.summary.planDigest]).count, 3)
        // Coverage: 2 servers × 2 queries as direct udp/53 literal hops, no bootstrap stage.
        let required = try RouterControlPlaneCoverage.requirements(plan: plan, profile: .init(resolver: .plain))
        XCTAssertEqual(required.count, 4); XCTAssertEqual(Set(required.map(\.id)).count, 4)
        for item in required {
            XCTAssertEqual(item.id.role, .mainResolver); XCTAssertEqual(item.id.transport, .udp)
            XCTAssertEqual(item.port, 53); XCTAssertNil(item.httpsPath)
            XCTAssertEqual(item.resolverHost, item.id.bootstrapAddress)
            XCTAssertEqual(item.resolverAddress, item.id.bootstrapAddress)
            XCTAssertNil(item.questionName)
            XCTAssertEqual(item.responseRequirement, .controlledQueryRecipeMissing)
            XCTAssertEqual(item.expectedDestination, .direct)
        }
        XCTAssertEqual(Set(required.map { $0.id.bootstrapAddress ?? "" }), ["223.5.5.5", "119.29.29.29"])
    }
    func testPlainProxyHostnameCoverageStaysUDPLiteral() throws {
        var input = plan
        input.proxies = [.init(id: UUID(), name: "p", kind: .socks5, host: "proxy.example.net", port: 1080,
                               udp: false, credentialReference: UUID())]
        let required = try RouterControlPlaneCoverage.requirements(plan: input, profile: .init(resolver: .plain))
        let proxyCases = required.filter { $0.id.role == .proxyHostnameResolver }
        XCTAssertEqual(proxyCases.count, 4)
        for item in proxyCases {
            XCTAssertEqual(item.questionName, "proxy.example.net")
            XCTAssertEqual(item.id.transport, .udp); XCTAssertEqual(item.port, 53)
            XCTAssertEqual(item.expectedDestination, .direct)
            XCTAssertEqual(item.responseRequirement, .matchingQuestionAndUpstreamAnswerRequired)
        }
        XCTAssertEqual(Set(proxyCases.map { $0.id.proxyID?.uuidString ?? "" }).count, 1)
    }
    func testCompilerReportsBlockedCoreDNSWithoutInjectingBypass() throws {
        var input = plan; input.defaultDestination = .block
        let config = try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:])
        XCTAssertEqual(config.summary.resolverRoute, "resolver_route_blocked")
        let object = try JSONSerialization.jsonObject(with: config.privateJSON) as! [String: Any]
        XCTAssertEqual(object["rules"] as? [String], ["MATCH,REJECT"])
        input.rules = [.init(id: UUID(), selector: .init(processPath: "/Applications/Example.app/Contents/MacOS/Example"), destination: .direct)]
        XCTAssertEqual(try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:]).summary.resolverRoute, "resolver_route_blocked")
        XCTAssertEqual(try RouterExplainer.explain(input, flow: .init(domain: "cloudflare-dns.com", transport: .tcp)).status, "undetermined")
    }
    func testCoreDNSBypassesOnlyNonmatchingProcessSelectorsInDiagnosis() throws {
        let path = "/Applications/Example.app/Contents/MacOS/Example"
        for selector in [RouterSelector(processPath: path),
                         .init(processPath: path, domain: .init(kind: .exact, value: "cloudflare-dns.com"))] {
            var input = plan
            input.rules = [.init(id: UUID(), selector: selector, destination: .block)]
            let config = try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:])
            XCTAssertEqual(config.summary.resolverRoute, "resolver_route_planned_not_verified")
            XCTAssertEqual(try RouterExplainer.explain(input, flow: .init(domain: "cloudflare-dns.com", transport: .tcp)).status, "undetermined")
            let actual = try JSONSerialization.jsonObject(with: config.privateJSON) as! [String: Any]
            let expected = try RouterCompiledRouting.compile(input) { _ in throw RouterSystemError.invalidCredentials }
            XCTAssertEqual(actual["rules"] as? [String], expected.rules)
        }
    }
    func testCoreDNSDomainExceptionRetainsOrderingAndSelectedResolver() throws {
        var input = plan; input.defaultDestination = .block
        input.rules = [
            .init(id: UUID(), selector: .init(processPath: "/Applications/Example.app/Contents/MacOS/Example"), destination: .block),
            .init(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "cloudflare-dns.com")), destination: .direct)]
        XCTAssertEqual(try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:]).summary.resolverRoute, "resolver_route_planned_not_verified")
        XCTAssertEqual(try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .quad9), secret: secret, credentials: [:]).summary.resolverRoute, "resolver_route_blocked")
        input.rules[1].destination = .block
        XCTAssertEqual(try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .cloudflare), secret: secret, credentials: [:]).summary.resolverRoute, "resolver_route_blocked")
    }
    func testControlModeKeepsOriginalNetworkFieldsAndSameRules() throws {
        let control = try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: secret)
        let system = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: .quad9), secret: secret, credentials: [:])
        let a = try JSONSerialization.jsonObject(with: control.privateJSON) as! [String: Any]
        let b = try JSONSerialization.jsonObject(with: system.privateJSON) as! [String: Any]
        XCTAssertNil(a["ipv6"])
        XCTAssertEqual((a["tun"] as? [String: Any])?["enable"] as? Bool, false)
        XCTAssertEqual((a["dns"] as? [String: Any])?["enable"] as? Bool, false)
        XCTAssertEqual(a["rules"] as? [String], b["rules"] as? [String])
    }
    func testCredentialsExactSetAndPrivateOnly() throws {
        let reference = UUID(), value = RouterCredential(username: "private-user", password: "private-pass")
        var input = plan
        input.proxies = [.init(id: UUID(), name: "Test", kind: .http, host: "127.0.0.1", port: 1082, credentialReference: reference)]
        for credentials in [[:], [UUID(): value], [reference: value, UUID(): value]] {
            XCTAssertThrowsError(try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .quad9), secret: secret, credentials: credentials))
        }
        let config = try RouterSystemCompiler.compile(plan: input, profile: .init(resolver: .quad9), secret: secret, credentials: [reference: value])
        XCTAssertTrue(String(decoding: config.privateJSON, as: UTF8.self).contains(value.password))
        XCTAssertFalse(String(decoding: try JSONEncoder().encode(config.summary), as: UTF8.self).contains("private-"))
    }
    func testRealPinnedCoreChecksBothResolversWithNetworkDenied() throws {
        guard let path = ProcessInfo.processInfo.environment["ROUTER_TEST_PINNED_CORE"] else {
            throw XCTSkip("Set ROUTER_TEST_PINNED_CORE to explicitly run offline pinned-core validation")
        }
        let base = try XCTUnwrap(RouterRuntimeFiles.physicalPath(FileManager.default.temporaryDirectory))
        for choice in [RouterSystemProfile.Resolver.cloudflare, .quad9] {
            let config = try RouterSystemCompiler.compile(plan: plan, profile: .init(resolver: choice), secret: secret, credentials: [:])
            let report = try RouterCoreCheck.runSystem(core: URL(fileURLWithPath: path), configuration: config,
                workspace: URL(fileURLWithPath: base).appendingPathComponent("system-config-check-" + UUID().uuidString))
            XCTAssertTrue(report.configurationAccepted); XCTAssertTrue(report.validationNetworkDenied)
            XCTAssertFalse(report.routingVerified); XCTAssertFalse(report.networkSettingsModified)
        }
    }
}
