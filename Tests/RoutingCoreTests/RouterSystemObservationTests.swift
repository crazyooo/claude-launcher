import XCTest
@testable import RoutingCore

final class RouterSystemObservationTests: XCTestCase {
    let v4 = "Routing tables\nInternet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGScg en0\n1 198.18.0.1 UGSc utun4\n2/7 198.18.0.1 UGSc utun4\n"
    let v6 = "Routing tables\nInternet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::%utun0 UGcIg utun0\nfe80::%utun0/64 link#18 UcI utun0\n"
    func sample(changed: Bool = false, failed: Bool = false, proxy: [String: Any] = [:]) -> RouterSystemObservation {
        var reads = 0
        return RouterSystemObservation.collect(run: { command, args, _ in
            if failed { throw RouterRuntimeError.processTimedOut }
            if command == "/bin/launchctl" { return (.init(exitCode: 113, timedOut: false, settled: true), Data()) }
            let value: String
            if command == "/usr/sbin/netstat" {
                if args.last == "inet" {
                    reads += 1
                    value = changed && reads == 2 ? self.v4.replacingOccurrences(of: "utun4", with: "utun5") : self.v4
                } else { value = self.v6 }
            } else { value = "Available network connection services in the current set (*=enabled):\n* (Disconnected) ignored VPN\n" }
            return (.init(exitCode: 0, timedOut: false, settled: true), Data(value.utf8))
        }, proxies: { proxy })
    }
    func testSplitRoutesDetectedWithoutTreatingScopedIPv6AsCapture() throws {
        let result = sample()
        XCTAssertTrue(result.complete)
        XCTAssertEqual(result.tunnelCaptureInterfaces, ["utun4"])
        XCTAssertEqual(result.scopedTunnelInterfaces, ["utun0"])
        XCTAssertEqual(result.defaultIPv4Interfaces, ["en0"])
        XCTAssertEqual(result.connectedVPN, false)
        XCTAssertTrue(RouterSystemPreview(observation: result).blockers.contains("existing_tunnel_routes_require_resolution"))
    }
    func testSystemProxyAndPACAreConflictsWithoutExportingValues() throws {
        let result = sample(proxy: ["HTTPEnable": 1, "HTTPProxy": "secret-endpoint", "ProxyAutoConfigEnable": 1, "ProxyAutoConfigURLString": "https://private/?token=secret"])
        XCTAssertEqual(result.applicationProxyEnabled, true); XCTAssertEqual(result.automaticProxyEnabled, true)
        let preview = RouterSystemPreview(observation: result)
        XCTAssertTrue(preview.blockers.contains("application_proxy_changes_process_attribution"))
        let encoded = String(decoding: try JSONEncoder().encode(preview), as: UTF8.self)
        XCTAssertFalse(encoded.contains("secret")); XCTAssertFalse(encoded.contains("https://"))
        XCTAssertFalse(preview.canApply); XCTAssertFalse(preview.networkModified)
    }
    func testChangingAndUnavailableObservationsCannotBecomeComplete() {
        let changed = sample(changed: true)
        XCTAssertFalse(changed.complete); XCTAssertTrue(changed.unknowns.contains("network_changed_during_observation"))
        let failed = sample(failed: true)
        XCTAssertFalse(failed.complete); XCTAssertNil(failed.connectedVPN); XCTAssertNil(failed.userCoreJobPresent)
    }
    func testMalformedParsersRemainUnknown() {
        XCTAssertThrowsError(try RouterSystemObservation.RouteTable.parse("Internet:\nDestination Gateway Netif\n", family: "inet"))
        XCTAssertThrowsError(try RouterSystemObservation.parseVPN("unexpected"))
        XCTAssertThrowsError(try RouterSystemObservation.ProxySnapshot.parse(["HTTPEnable": "1"]))
        XCTAssertThrowsError(try RouterSystemObservation.ProxySnapshot.parse(["HTTPEnable": 2]))
        XCTAssertThrowsError(try RouterSystemObservation.parseVPN("Available network connection services\n* (Unknown) VPN"))
    }
    func testMulticastOnlyTunnelRouteDoesNotImplyGlobalCapture() throws {
        let text = "Internet:\nDestination Gateway Flags Netif Expire\n239.0/8 link#18 U utun7\n224/4 link#18 U utun7\ndefault 192.0.2.1 UG en0\n"
        XCTAssertEqual(try RouterSystemObservation.RouteTable.parse(text, family: "inet").capture, [])
    }
    func testVPNDisplayNameCannotOverrideLeadingStatus() throws {
        XCTAssertFalse(try RouterSystemObservation.parseVPN("Available network connection services\n* (Disconnected) ID VPN \"Office (Connected)\""))
        XCTAssertTrue(try RouterSystemObservation.parseVPN("Available network connection services\n* (Connected) ID VPN \"Office (Disconnected)\""))
    }
    func testScopedAndSupplementalProxyFlagsAreIncluded() throws {
        let result = try RouterSystemObservation.ProxySnapshot.parse(["__SCOPED__": ["en0": ["SOCKSEnable": 1]], "__SUPPLEMENTAL__": [["ProxyAutoConfigEnable": 1]]])
        XCTAssertTrue(result.explicit); XCTAssertTrue(result.automatic)
    }
    func testRootObservationTargetsApprovedGUIUser() {
        var targets: [String] = []
        _ = RouterSystemObservation.collect(ownerUID: 502, run: { command, arguments, _ in
            if command == "/bin/launchctl" {
                targets.append(arguments.last!)
                return (.init(exitCode: 113, timedOut: false, settled: true), Data())
            }
            let text = command == "/usr/sbin/netstat" ? (arguments.last == "inet" ? self.v4 : self.v6) : "Available network connection services\n"
            return (.init(exitCode: 0, timedOut: false, settled: true), Data(text.utf8))
        }, proxies: { [:] })
        XCTAssertEqual(targets, Array(repeating: "gui/502/" + RouterCoreRelease.label, count: 2))
    }
    private func routes(_ extra: String, family: String = "inet") throws -> RouterSystemObservation.RouteTable {
        let header = family == "inet" ? "Internet:\nDestination Gateway Flags Netif Expire\ndefault 192.0.2.1 UGScg en0\n" :
            "Internet6:\nDestination Gateway Flags Netif Expire\ndefault fe80::1 UGc en0\n"
        return try .parse(header + extra, family: family)
    }
    func testDynamicNeighborCacheDoesNotInvalidateTopologyButRawEvidenceIsRetained() throws {
        for (family, first, second) in [
            ("inet", "192.0.2.10 aa:bb:cc:dd:ee:01 UHLWI en0 120\n", "192.0.2.11 aa:bb:cc:dd:ee:02 UHLW en0 80\n"),
            ("inet6", "fe80::2%en0 aa:bb:cc:dd:ee:01 UHLWIi en0 120\n", "fe80::3%en0 aa:bb:cc:dd:ee:02 UHLWI en0 80\n")] {
            let a = try routes(first, family: family), b = try routes(second, family: family)
            XCTAssertEqual(a, b); XCTAssertEqual(a.canonical, b.canonical)
            XCTAssertNotEqual(a.rows, b.rows); XCTAssertEqual(a.rows.last?.last, "120")
        }
    }
    func testRealRoutesAndUnfamiliarFlagsRemainInFingerprint() throws {
        let baseline = try routes("")
        for line in ["203.0.113.9 192.0.2.1 UGHW en0\n", "192.0.2.9 aa:bb:cc:dd:ee:03 UHLS en0\n",
                     "198.18/16 link#4 UHLW en0\n", "default link#4 UHLW en0\n", "192.0.2.9 link#4 ULW en0\n",
                     "192.0.2.9 link#4 UHLWB en0\n", "192.0.2.9 link#4 UHLWR en0\n", "192.0.2.9 link#4 UHLWZ en0\n"] {
            XCTAssertNotEqual(try routes(line).canonical, baseline.canonical, line)
        }
    }
    func testFilteredNeighborsStillContributeTunnelCaptureAndScopedEvidence() throws {
        let baseline = try routes("")
        let capture = try routes("203.0.113.9 link#20 UHLW utun9\n")
        XCTAssertEqual(capture.capture, ["utun9"]); XCTAssertNotEqual(capture, baseline)
        let scoped = try routes("203.0.113.9 link#21 UHLWI utun10\n")
        XCTAssertEqual(scoped.capture, []); XCTAssertEqual(scoped.scoped, ["utun10"])
        XCTAssertNotEqual(scoped, baseline); XCTAssertEqual(capture.defaults, ["en0"])
    }
}
