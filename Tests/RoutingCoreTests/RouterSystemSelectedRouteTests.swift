import XCTest
@testable import RoutingCore

final class RouterSystemSelectedRouteTests: XCTestCase {
    private typealias Route = RouterSystemSelectedRoute
    private func output(ipv6: Bool = false) -> String {
        """
           route to: \(ipv6 ? "2606:4700:4700::1111" : "1.1.1.1")
        destination: \(ipv6 ? "::" : "0.0.0.0")
               mask: \(ipv6 ? "8000::" : "128.0.0.0")
            gateway: \(ipv6 ? "fdfe:dcba:9876::1" : "198.18.0.1")
          interface: utun5
              flags: <UP,GATEWAY,DONE,STATIC>
         recvpipe sendpipe ssthresh rtt,msec rttvar hopcount mtu expire
                0 0 0 0 0 0 9000 0
        """
    }
    func testFixedTargetsAndScopedGatewaySelection() throws {
        XCTAssertTrue(try Route.parse(output(), family: .ipv4).selects("utun5"))
        XCTAssertTrue(try Route.parse(output(ipv6: true), family: .ipv6).selects("utun5"))
        let scoped = output(ipv6: true).replacingOccurrences(of: "fdfe:dcba:9876::1", with: "fe80::1%utun5")
        XCTAssertTrue(try Route.parse(scoped, family: .ipv6).selects("utun5"))
        XCTAssertFalse(try Route.parse(scoped.replacingOccurrences(of: "%utun5", with: "%en0"), family: .ipv6).selects("utun5"))
        XCTAssertFalse(try Route.parse(scoped.replacingOccurrences(of: "%utun5", with: "%15"), family: .ipv6).selects("utun5"))
        XCTAssertNoThrow(try Route.parse(output(ipv6: true).replacingOccurrences(of: "2606:4700:4700::1111", with: "2606:4700:4700:0:0:0:0:1111"), family: .ipv6))
    }
    func testRouteRejectionAndVolatileMetrics() throws {
        let base = try Route.parse(output(), family: .ipv4)
        XCTAssertEqual(base, try Route.parse(output().replacingOccurrences(of: "9000 0", with: "1500 10"), family: .ipv4))
        for flags in ["<UP,GATEWAY,REJECT>", "<UP,GATEWAY,BLACKHOLE>", "<UP>", "<GATEWAY>"] {
            XCTAssertFalse(try Route.parse(output().replacingOccurrences(of: "<UP,GATEWAY,DONE,STATIC>", with: flags), family: .ipv4).selects("utun5"))
        }
        XCTAssertFalse(base.selects("en0"))
        for invalid in [output() + "\ninterface: utun5", output().replacingOccurrences(of: "1.1.1.1", with: "8.8.8.8"),
                        output().replacingOccurrences(of: "utun5", with: "utun5\0"),
                        output().replacingOccurrences(of: "9000 0", with: "bogus 0"),
                        output().replacingOccurrences(of: "198.18.0.1", with: "link#12"),
                        output().replacingOccurrences(of: "<UP,GATEWAY,DONE,STATIC>", with: "<UP,UP,GATEWAY>")] {
            XCTAssertThrowsError(try Route.parse(invalid, family: .ipv4))
        }
    }
    func testActualReadonlyRouteQueries() throws {
        guard ProcessInfo.processInfo.environment["ROUTER_TEST_HOST_ROUTES"] == "1" else {
            throw XCTSkip("Opt-in host integration: requires current IPv4 and IPv6 routes; never changes them")
        }
        let command = try RouterSystemCommand(ownerUID: getuid())
        let ipv4 = try Route.collect(.ipv4, command: command)
        XCTAssertFalse(ipv4.interface.isEmpty)
        // This host has an IPv6 route; querying it never connects to the target.
        let ipv6 = try Route.collect(.ipv6, command: command)
        XCTAssertFalse(ipv6.interface.isEmpty)
    }
}
