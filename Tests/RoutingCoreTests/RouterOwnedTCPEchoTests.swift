import XCTest
import Darwin
@testable import RoutingCore

final class RouterOwnedTCPEchoTests: XCTestCase {
    func testActualIPv4AndIPv6PayloadAndServerObservedPeer() throws {
        for family in [AF_INET, AF_INET6] {
            let server = try RouterLoopbackEchoFixture(family: family)
            defer { server.stop() }
            let probe = try RouterOwnedTCPProbe.loopbackFixture(endpoint: server.target,
                until: ProcessInfo.processInfo.systemUptime + 3)
            defer { probe.close() }
            let before = try probe.sample(until: ProcessInfo.processInfo.systemUptime + 5)
            let nonce = UUID()
            let echo = try probe.exchangeLoopbackFixture(nonce: nonce, until: ProcessInfo.processInfo.systemUptime + 5)
            XCTAssertEqual(try probe.sample(until: ProcessInfo.processInfo.systemUptime + 3), before)
            XCTAssertEqual(echo.reply.nonce, nonce)
            XCTAssertEqual(RouterTrafficAddress.bytes(echo.reply.serverReportedPeerIP), before.tuple.local.bytes)
            XCTAssertFalse(echo.peerAuthenticated); XCTAssertFalse(echo.egressVerified)
            probe.close()
            let serverResult = try server.finish()
            XCTAssertEqual(serverResult.0, nonce)
            XCTAssertEqual(serverResult.1, echo.reply.serverReportedPeerIP)
        }
    }

    func testExternalAndInstalledProbeEntryRejectedWithoutConnecting() throws {
        for address in ["203.0.113.1", "::1%en0"] {
            XCTAssertThrowsError(try RouterOwnedTCPProbe.loopbackFixture(
                endpoint: .init(address: address, port: 443), until: ProcessInfo.processInfo.systemUptime + 1)) {
                XCTAssertEqual($0 as? RouterOwnedProbeError, .invalidTarget)
            }
        }
        XCTAssertThrowsError(try RouterOwnedTCPProbe.installed(
            address: "127.0.0.1", port: 1, until: ProcessInfo.processInfo.systemUptime + 1))
    }
}
