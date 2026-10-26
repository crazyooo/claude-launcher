import XCTest
@testable import LauncherCore

final class IPv4PolicyTests: XCTestCase {
    func testIPv4NormalizationRejectsMappedAndTruncatedInput() {
        XCTAssertEqual(normalizedIPv4(" 203.0.113.43\n"), "203.0.113.43")
        for input in ["::1", "::ffff:203.0.113.43", "[::ffff:203.0.113.43]",
                      "203.0.113.43\u{0}suffix", "127.1", "2130706433", "0x7f000001", "192.0.2.999"] {
            XCTAssertNil(normalizedIPv4(input), input)
        }
        XCTAssertEqual(normalizedIP("2001:0db8::1"), "2001:db8::1")
    }

    func testOldIPv6ConfigurationsAreDecodedButRejected() throws {
        var connector = ConnectorConfiguration()
        connector.expectedIPv6 = "2001:db8::1"
        let old = try JSONDecoder().decode(ConnectorConfiguration.self, from: JSONEncoder().encode(connector))
        XCTAssertEqual(old.expectedIPv6, connector.expectedIPv6)
        XCTAssertThrowsError(try old.validate())
        for ip in ["203.0.113.43", "2001:db8::1"] { XCTAssertFalse(old.matches(ip)) }
        connector.expectedIPv6 = ""
        XCTAssertNoThrow(try connector.validate())
        XCTAssertTrue(connector.matches("203.0.113.43"))
        XCTAssertFalse(connector.matches("::ffff:203.0.113.43"))

        var settings = PreflightSettings(); settings.expectedIP = "203.0.113.43"
        settings.expectedIPv6 = "2001:db8::1"
        let decoded = try JSONDecoder().decode(PreflightSettings.self, from: JSONEncoder().encode(settings))
        XCTAssertThrowsError(try decoded.validate())
        XCTAssertFalse(decoded.matches("203.0.113.43"))
    }

    func testBothUpstreamsAndBackupDraftRejectIPv6() {
        for host in ["::1", "[::1]", "::ffff:127.0.0.1", "localhost"] {
            var connector = ConnectorConfiguration(); connector.upstreamHost = host
            XCTAssertThrowsError(try connector.validate(), host)
            var legacy = Configuration(); legacy.host = host
            legacy.confirmed = true; legacy.expectedIP = "203.0.113.43"
            XCTAssertThrowsError(try legacy.validate(), host)
            var draft = ShadowrocketDraft(); draft.host = host
            XCTAssertThrowsError(try draft.validated(), host)
        }
        var draft = ShadowrocketDraft(); draft.expectedIP = "2001:db8::1"
        XCTAssertThrowsError(try draft.validated())
        XCTAssertNoThrow(try ShadowrocketDraft().validated())
    }

    func testProxyRejectsIPv6BeforeForwardingButRetainsDomainSupport() throws {
        for host in ["[::1]", "[2001:db8::1]", "[::ffff:127.0.0.1]",
                     "[::ffff:7f00:1]", "[fe80::1%25lo0]", "%5B::1%5D"] {
            for line in ["CONNECT \(host):443", "GET http://\(host):80/a"] {
                XCTAssertThrowsError(try ProxyRequest.parse(Data("\(line) HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8)), line)
            }
        }
        for host in ["127.0.0.1", "claude.ai"] {
            XCTAssertNoThrow(try ProxyRequest.parse(Data("CONNECT \(host):443 HTTP/1.1\r\n\r\n".utf8)))
        }
        // Generic parsing remains usable by diagnostics; it grants no forwarding permission.
        XCTAssertEqual(try Target.parse("[::1]:443").host, "::1")
    }

    func testGrantCannotAuthorizeAnExplicitIPv6Target() throws {
        var grant = ConnectorGrant(); grant.heartbeat(100)
        let id = UUID(), token = String(repeating: "b", count: 64)
        XCTAssertTrue(grant.begin(id: id, token: token, manual: true, now: 100))
        let auth = "Basic " + Data("probe:\(token)".utf8).base64EncodedString()
        for host in ConnectorConfiguration.hosts {
            XCTAssertEqual(grant.authorize(target: try Target.parse("\(host):443"), connect: true, auth: auth, now: 100), true)
        }
        XCTAssertTrue(grant.revoke(id: id, now: 100))
        XCTAssertTrue(grant.commit(id: id, manual: true, now: 100))
        XCTAssertNil(grant.authorize(target: try Target.parse("[::ffff:127.0.0.1]:443"), connect: true, auth: nil, now: 100))
        XCTAssertEqual(grant.authorize(target: try Target.parse("claude.ai:443"), connect: true, auth: nil, now: 100), false)
    }

    func testOldPolicyEvidenceFingerprintsAreInvalidated() throws {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        let connector = ConnectorConfiguration()
        XCTAssertNotEqual(connector.digest, fingerprintData(try encoder.encode(connector)))
        let legacy = Configuration()
        XCTAssertNotEqual(legacy.digest, fingerprintData(try encoder.encode(legacy)))
        let preflight = PreflightSettings()
        XCTAssertNotEqual(preflight.fingerprint, fingerprintData(try encoder.encode(preflight)))
    }
}
