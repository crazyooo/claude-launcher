import XCTest
import Darwin
import SystemConfiguration
@testable import RoutingCore

final class RouterSystemSnapshotTests: XCTestCase {
    private func dns(_ fields: String = "  nameserver[0] : 192.0.2.53", flags: String = "") -> String {
        "DNS configuration\nresolver #1\n" + fields + "\n  flags : " + flags + "\n  reach : 0x00000002 (Reachable)\n"
    }
    func testOptionalDestinationSentinelDoesNotRelaxRequiredAddresses() throws {
        var empty = sockaddr()
        try withUnsafePointer(to: &empty) { pointer in
            XCTAssertNil(try RouterSystemInterfaceSnapshot.optionalDestination(pointer, family: AF_INET6))
            XCTAssertThrowsError(try RouterSystemInterfaceSnapshot.numeric(pointer, family: AF_INET6, mask: false))
            XCTAssertThrowsError(try RouterSystemInterfaceSnapshot.numeric(pointer, family: AF_INET6, mask: true))
        }
        for (length, family): (UInt8, UInt8) in [(0, UInt8(AF_INET6)), (2, 0)] {
            empty.sa_len = length; empty.sa_family = family
            try withUnsafePointer(to: &empty) { pointer in
                XCTAssertThrowsError(try RouterSystemInterfaceSnapshot.optionalDestination(pointer, family: AF_INET6))
            }
        }
        XCTAssertNil(try RouterSystemInterfaceSnapshot.optionalDestination(nil, family: AF_INET6))
    }
    func testFullDestinationAndTruncatedMasksUseOnlyDeclaredBytes() throws {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        XCTAssertEqual(inet_pton(AF_INET, "192.0.2.1", &address.sin_addr), 1)
        try withUnsafePointer(to: &address) { pointer in
            try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                XCTAssertEqual(try RouterSystemInterfaceSnapshot.optionalDestination($0, family: AF_INET), "192.0.2.1")
                XCTAssertThrowsError(try RouterSystemInterfaceSnapshot.optionalDestination($0, family: AF_INET6))
            }
        }
        for (length, expected) in [(5, "255.0.0.0"), (7, "255.255.255.0")] {
            address.sin_len = UInt8(length); address.sin_family = 0
            XCTAssertEqual(inet_pton(AF_INET, "255.255.255.255", &address.sin_addr), 1)
            try withUnsafePointer(to: &address) { pointer in
                try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    XCTAssertEqual(try RouterSystemInterfaceSnapshot.numeric($0, family: AF_INET, mask: true), expected)
                    XCTAssertThrowsError(try RouterSystemInterfaceSnapshot.numeric($0, family: AF_INET, mask: false))
                }
            }
        }
    }
    func testAddressSchemaRejectsControlCharactersAfterDecode() throws {
        for value in ["127.0.0.1\0unexpected", "127.0.0.1\n", "127.0.0.1\t"] {
            let invalid = RouterSystemInterfaceSnapshot.Interface(name: "en0", index: 4, flags: 1, mtu: 1500,
                addresses: [.init(family: AF_INET, address: value, netmask: nil, destination: nil)])
            let decoded = try JSONDecoder().decode(RouterSystemInterfaceSnapshot.Interface.self, from: JSONEncoder().encode(invalid))
            XCTAssertThrowsError(try decoded.validate())
        }
        XCTAssertFalse(RouterSystemInterfaceSnapshot.numericText("::1\0unexpected", family: AF_INET6))
        XCTAssertTrue(RouterSystemInterfaceSnapshot.numericText("fe80::1%en0", family: AF_INET6))
    }
    func testDNSArrayAndInterfaceIndicesAreBoundedAndContiguous() throws {
        for (prefix, value) in [("nameserver", "192.0.2.53"), ("search domain", "example.test"), ("sortaddr", "192.0.2.0/255.255.255.0")] {
            for index in ["999999999999999999999999", "4294967296", "256", "-1", "00", "1"] {
                XCTAssertThrowsError(try RouterSystemDNS.parse(dns("  \(prefix)[\(index)] : \(value)")))
            }
            XCTAssertNoThrow(try RouterSystemDNS.parse(dns("  \(prefix)[0] : \(value)")))
        }
        for index in ["0", "4294967296", "999999999999999999999999", "01", "-1"] {
            XCTAssertThrowsError(try RouterSystemDNS.parse(dns("  if_index : \(index) (en0)")))
        }
        XCTAssertNoThrow(try RouterSystemDNS.parse(dns("  if_index : 4294967295 (?)")))
        XCTAssertNoThrow(try RouterSystemDNS.parse(dns("  nameserver[0] : 192.0.2.53\n  nameserver[1] : 192.0.2.54")))
    }
    func testResolverSectionsAndEmptyConfigurationRemainDistinct() throws {
        let text = dns(flags: "Supplemental") +
            "DNS configuration (for scoped queries)\nresolver #1\n  if_index : 4 (en0)\n  flags : Scoped, Request A records\n  reach : 0x00000000\n" +
            "DNS configuration (for service-specific queries)\nresolver #1\n  service_identifier : 10\n  flags : Service-specific\n  reach : 0x00000002\n"
        XCTAssertEqual(try RouterSystemDNS.parse(text).resolvers.map(\.category), ["supplemental", "scoped", "serviceSpecific"])
        XCTAssertEqual(try RouterSystemDNS.parse(dns()).resolvers.first?.category, "default")
        XCTAssertNotEqual(try RouterSystemDNS.parse("DNS configuration\n").canonical,
                          try RouterSystemDNS.parse("No DNS configuration available\n").canonical)
        for invalid in ["DNS configuration\nDNS configuration (for scoped queries)\n",
                        dns().replacingOccurrences(of: "  flags : \n", with: ""),
                        dns().replacingOccurrences(of: "  reach : 0x00000002 (Reachable)\n", with: ""),
                        dns("  mystery : value"), dns("  nameserver[0] : 192.0.2.53\n  nameserver[0] : 192.0.2.54"),
                        dns(flags: "Scoped")] {
            XCTAssertThrowsError(try RouterSystemDNS.parse(invalid))
        }
        let changedReach = dns().replacingOccurrences(of: "0x00000002 (Reachable)", with: "0x00000000")
        XCTAssertEqual(try RouterSystemDNS.parse(dns()).canonical, try RouterSystemDNS.parse(changedReach).canonical)
        XCTAssertNotEqual(try RouterSystemDNS.parse(dns()).raw, try RouterSystemDNS.parse(changedReach).raw)
        XCTAssertNotEqual(try RouterSystemDNS.parse(dns()).canonical, try RouterSystemDNS.parse(dns("  nameserver[0] : 192.0.2.54")).canonical)
    }
    func testBaselineRejectsChangingEnvironmentButIgnoresNeighborCacheNoise() throws {
        for variation in ["stable", "neighbor", "dns", "interface", "route", "fingerprint", "clock", "incomplete"] {
            let f = try RouterSystemDispatchFixture()
            var round = 0, clockCalls = 0
            let collect = {
                try RouterSystemBaselineSnapshot.collect(read: { command in
                    let text: String
                    switch command {
                    case .dnsState: text = variation == "dns" && round == 2 ? f.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54") : f.dns
                    case .routesIPv4:
                        text = f.v4 + (variation == "neighbor" ? "192.0.2.\(round) link#4 UHLW en0 100\n" :
                            (variation == "route" && round == 2 ? "203.0.113/24 192.0.2.1 UGSc en0\n" : ""))
                    case .routesIPv6: text = f.v6
                    default: throw RouterSystemError.invalidRequest
                    }
                    return (.init(exitCode: 0, timedOut: false, settled: true), Data(text.utf8))
                }, interfaces: {
                    if variation == "interface" && round == 2 {
                        return [.init(name: "en0", index: 4, flags: UInt32(IFF_UP), mtu: 1400, addresses: f.devices[0].addresses)]
                    }
                    return f.devices
                }, network: {
                    round += 1
                    return .init(checkedAt: f.clock.date,
                        fingerprint: String(repeating: variation == "fingerprint" && round == 2 ? "b" : "a", count: 64),
                        complete: variation != "incomplete", defaultIPv4Interfaces: ["en0"], defaultIPv6Interfaces: ["en0"],
                        tunnelCaptureInterfaces: [], scopedTunnelInterfaces: [], applicationProxyEnabled: false,
                        automaticProxyEnabled: false, connectedVPN: false, userCoreJobPresent: false, unknowns: [])
                }, clock: {
                    clockCalls += 1
                    if variation == "clock" && clockCalls == 4 { f.uptime -= 1 }
                    return f.clock
                })
            }
            if ["stable", "neighbor"].contains(variation) { XCTAssertNoThrow(try collect(), variation) }
            else { XCTAssertThrowsError(try collect(), variation) }
        }
    }
    func testBaselineCommandFailuresCannotBecomeValidEvidence() throws {
        let f = try RouterSystemDispatchFixture()
        for (result, data) in [(RouterProcessResult(exitCode: 1, timedOut: false, settled: true), Data(f.v4.utf8)),
                              (.init(exitCode: 0, timedOut: true, settled: true), Data(f.v4.utf8)),
                              (.init(exitCode: 0, timedOut: false, settled: false), Data(f.v4.utf8)),
                              (.init(exitCode: 0, timedOut: false, settled: true), Data([0xff])),
                              (.init(exitCode: 0, timedOut: false, settled: true), Data(repeating: 32, count: 65_537))] {
            XCTAssertThrowsError(try RouterSystemBaselineSnapshot.collect(read: { _ in (result, data) },
                interfaces: { f.devices }, network: { RouterSystemObservationTests().sample() }, clock: { f.clock }))
        }
    }
    /// Actual macOS reads only: getifaddrs/ioctl, netstat, scutil and launchctl print.
    func testLiveReadOnlyBaselineIncludesValidatedLoopbackAndDNS() throws {
        let command = try RouterSystemCommand(ownerUID: getuid())
        let snapshot = try RouterSystemBaselineSnapshot.collect(command: command, network: {
            RouterSystemObservation.collect(run: command.captureObservation, proxies: {
                guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { throw RouterSystemError.operationUnsettled }
                return values
            })
        })
        try snapshot.validate()
        let loopback = try XCTUnwrap(snapshot.interfaces.first { $0.name == "lo0" })
        XCTAssertGreaterThan(loopback.mtu, 0)
        XCTAssertEqual(loopback.index, if_nametoindex("lo0"))
        XCTAssertTrue(loopback.addresses.contains { $0.address == "127.0.0.1" })
        XCTAssertFalse(try RouterSystemDNS.parse(snapshot.dns).canonical.isEmpty)
    }
}
