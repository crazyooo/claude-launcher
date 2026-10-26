import XCTest
@testable import LauncherCore
final class CoreTests: XCTestCase {
    func testLegacyConfigRequiresNewConsent() throws {
        let old = #"{"protocolName":"http","host":"127.0.0.1","port":1082,"gatewayPort":18761,"probePort":18762,"expectedIP":"203.0.113.43","confirmed":true,"authentication":false}"#
        let config = try JSONDecoder().decode(Configuration.self, from: Data(old.utf8))
        XCTAssertNil(config.officialDesktopConsent)
        XCTAssertFalse(OfficialDesktopPolicy.allows(config, Snapshot()))
    }
    func testOrdinaryLaunchEvidenceAndConsent() {
        var config = Configuration(); config.confirmed = true; config.expectedIP = "192.0.2.1"
        config.officialDesktopConsent = OfficialDesktopConsent()
        var state = Snapshot(); state.configDigest = config.digest
        state.gatewayReady = true; state.desktopMode = "connection-checked-official"
        state.recordProxyCheck(ip: config.expectedIP, at: Date(), config: config)
        XCTAssertTrue(OfficialDesktopPolicy.allows(config, state))
        var changed = config; changed.officialDesktopConsent = nil
        XCTAssertFalse(OfficialDesktopPolicy.allows(changed, state))
        changed = config; changed.officialDesktopConsent?.revision = 2
        XCTAssertFalse(OfficialDesktopPolicy.allows(changed, state))
        changed = config; changed.port = 1083
        XCTAssertFalse(OfficialDesktopPolicy.allows(changed, state))
        for offset in [-31.0, 5.0] {
            var expired = state; expired.proxyCheck?.sampledAt = Date().addingTimeInterval(offset)
            XCTAssertFalse(OfficialDesktopPolicy.allows(config, expired))
        }
        for status in ["checking", "check-busy", "proxy", "blocked"] {
            var invalid = state; invalid.state = status
            XCTAssertFalse(OfficialDesktopPolicy.allows(config, invalid))
        }
        state.observedIP = "192.0.2.2"
        XCTAssertFalse(OfficialDesktopPolicy.allows(config, state))
        state.recordProxyCheck(ip: config.expectedIP, at: Date(), config: config)
        state.gatewayReady = false
        XCTAssertFalse(OfficialDesktopPolicy.allows(config, state))
    }
    func testOrdinaryCheckPreservesProtectedPermissions() {
        var config = Configuration(); config.expectedIP = "192.0.2.1"
        for allowed in [false, true] {
            var state = Snapshot(); state.networkAllowed = allowed
            state.cliCompatible = allowed; state.sessions = 1
            state.recordProxyCheck(ip: config.expectedIP, at: Date(), config: config)
            XCTAssertEqual(state.networkAllowed, allowed)
            XCTAssertEqual(state.cliCompatible, allowed)
            XCTAssertFalse(state.desktopCompatible)
            XCTAssertEqual(state.state, allowed ? "running" : "connection-ready")
        }
    }
    func request(_ value: String) throws -> ProxyRequest { try ProxyRequest.parse(Data(value.utf8)) }
    func testRejectHeaderInjectionAndAmbiguousTargets() {
        for target in ["evil%0d%0aX-Injected%3ayes:443", "user@host:443", "host/path:443", "host:0", "host:65536", "-bad.com:443", "evil%2520host:443"] {
            XCTAssertThrowsError(try Target.parse(target), target)
        }
        XCTAssertEqual(try Target.parse("[::1]:443").host,"::1")
        XCTAssertEqual(try Target.parse("api.anthropic.com:443").port,443)
    }
    func testPlainHTTPRewrite() throws {
        let req = try request("POST http://example.com/a%20b?q=1 HTTP/1.1\r\nHost: wrong\r\nProxy-Authorization: secret\r\nContent-Length: 3\r\n\r\n")
        let text = String(data:req.forwarded,encoding:.utf8)!
        XCTAssertTrue(text.contains("POST /a%20b?q=1 HTTP/1.1")); XCTAssertTrue(text.contains("Host: example.com:80"))
        XCTAssertFalse(text.contains("secret")); XCTAssertFalse(text.contains("wrong")); XCTAssertTrue(text.contains("Connection: close"))
    }
    func testRejectSmuggling() {
        for fields in ["Content-Length: 1\r\nContent-Length: 2", "Content-Length: 1\r\nTransfer-Encoding: chunked", "Connection: content-length\r\nContent-Length: 1", "Transfer-Encoding: gzip", " folded: bad"] {
            XCTAssertThrowsError(try request("POST http://example.com/ HTTP/1.1\r\n\(fields)\r\n\r\n"))
        }
    }
    func testEnvironmentAndAcceptance() {
        let environment = Isolation.environment(["PATH":"keep","TOKEN":"untouched","no_proxy":"*","HTTPS_PROXY":"old"],port:18761)
        XCTAssertEqual(environment["TOKEN"],"untouched"); XCTAssertEqual(environment["no_proxy"],"")
        XCTAssertEqual(environment["HTTPS_PROXY"],environment["https_proxy"])
        XCTAssertFalse(Acceptance(fingerprint:"a",checks:["ipv4"]).permits("a"))
        XCTAssertTrue(Acceptance(fingerprint:"a",checks:Acceptance.required).permits("a"))
        XCTAssertFalse(Acceptance(fingerprint:"a",checks:Acceptance.required).permits("b"))
    }
    func testConfigurationAndIP() {
        var config = Configuration(); XCTAssertThrowsError(try config.validate())
        config.confirmed = true; config.expectedIP = "2001:db8::1"; XCTAssertThrowsError(try config.validate())
        config.expectedIP = "192.0.2.1"; XCTAssertNoThrow(try config.validate())
        config.port = config.gatewayPort; XCTAssertThrowsError(try config.validate())
        XCTAssertEqual(normalizedIP("2001:0db8::1"),"2001:db8::1")
        XCTAssertNil(normalizedIP("1.2.3.999"))
    }
}
