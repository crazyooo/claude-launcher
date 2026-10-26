import XCTest
@testable import RoutingCore

final class RouterSystemResolverHealthTests: XCTestCase {
    func testRequireReachableAcceptsFirstLiveBootstrap() throws {
        var probed: [String] = []
        try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .plain), timeout: 1) { address, port, _ in
            probed.append("\(address):\(port)")
            return address == "119.29.29.29"
        }
        XCTAssertEqual(probed, ["223.5.5.5:53", "119.29.29.29:53"])
    }

    func testRequireReachableRefusesWhenAllBootstrapDead() {
        XCTAssertThrowsError(
            try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .plain), timeout: 1) { _, _, _ in false }
        ) { error in
            XCTAssertEqual(error as? RouterSystemError, .networkConflict)
        }
        XCTAssertThrowsError(
            try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .cloudflare), timeout: 1) { _, _, _ in false }
        ) { error in
            XCTAssertEqual(error as? RouterSystemError, .networkConflict)
        }
    }

    func testRequireReachableRejectsInvalidTimeout() {
        XCTAssertThrowsError(
            try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .plain), timeout: 0) { _, _, _ in true }
        )
        XCTAssertThrowsError(
            try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .plain), timeout: 9) { _, _, _ in true }
        )
    }

    func testRequireReachableProbesCloudflareBootstrap() throws {
        var probed: [String] = []
        try RouterSystemResolverHealth.requireReachable(profile: .init(resolver: .cloudflare), timeout: 1) { address, port, _ in
            probed.append("\(address):\(port)")
            return true
        }
        XCTAssertEqual(probed.first, "1.1.1.1:53")
    }
}
