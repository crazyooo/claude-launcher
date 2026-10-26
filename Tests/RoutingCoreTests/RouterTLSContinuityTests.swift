import XCTest
import Darwin
import Network
@testable import RoutingCore

final class RouterTLSContinuityTests: XCTestCase {
    private typealias Owner = RouterTLSConnection
    private typealias Observer = RouterSystemOutboundSocket
    private func clock(_ boot: UUID, uptime: Double = 10, wall: Double = 1010) -> RouterSystemClock {
        .init(bootID: boot, uptime: uptime, date: Date(timeIntervalSince1970: wall))
    }

    func testCaptureBindsInitialIdentityAndSubsequentSocketAndTLSVersion() throws {
        let boot = UUID()
        let at = clock(boot)
        func identity(kind: Int = -1) -> RouterSystemKernelObservation.ProcessSnapshot {
            .init(work: .init(bootID: kind == 0 ? UUID() : boot, pid: getpid() + (kind == 1 ? 1 : 0),
                             birthSeconds: kind == 2 ? 901 : 900, birthMicroseconds: kind == 3 ? 1 : 0),
                  uid: getuid() + (kind == 4 ? 1 : 0), realUID: getuid() + (kind == 5 ? 1 : 0),
                  parentPID: 1, processGroup: getpid())
        }
        let initial = identity()
        let originalTuple = try Observer.Tuple(local: .init(address: "127.0.0.1", port: 40000),
                                               peer: .init(address: "127.0.0.1", port: 40001))
        func evidence(kind: Int = -1, fd: Int32 = 42, generation: UInt64 = 8,
                      tuple: Observer.Tuple? = nil, path: String = "/test/tls-owner",
                      source: Observer.Source = .fixture) -> Observer.Evidence {
            .init(source: source, process: .init(identity: identity(kind: kind), path: path),
                  socket: .init(descriptor: fd, generation: generation, tuple: tuple ?? originalTuple),
                  interval: .init(start: at, end: at))
        }
        let baseline = Owner.Sample(source: .fixture, trust: .fixtureAnchor, serverName: "tls-fixture.invalid",
                                    protocolVersion: 0x0304, connectStartedAt: at, socket: evidence())
        func check(_ value: Observer.Evidence, version: UInt16 = 0x0304,
                   stable: Bool = true, first: Bool = false) throws {
            try Owner.requireContinuity(value, initialProcess: initial, baseline: first ? nil : baseline,
                                        source: .fixture, protocolVersion: version, pathUnchanged: stable)
        }
        XCTAssertNoThrow(try check(evidence()))
        XCTAssertNoThrow(try check(evidence(), first: true))
        for first in [true, false] {
            for kind in 0..<6 {
                XCTAssertThrowsError(try check(evidence(kind: kind), first: first)) {
                    XCTAssertEqual($0 as? Owner.Failure, .identityChanged)
                }
            }
            XCTAssertThrowsError(try check(evidence(source: .installedHelper), first: first))
        }
        for value in [evidence(fd: 43), evidence(generation: 9), evidence(path: "/changed/image")] {
            XCTAssertThrowsError(try check(value)) { XCTAssertEqual($0 as? Owner.Failure, .identityChanged) }
        }
        for index in 0..<4 {
            let tuple = try Observer.Tuple(
                local: .init(address: index == 0 ? "127.0.0.2" : "127.0.0.1", port: index == 1 ? 40002 : 40000),
                peer: .init(address: index == 2 ? "127.0.0.2" : "127.0.0.1", port: index == 3 ? 40003 : 40001))
            XCTAssertThrowsError(try check(evidence(tuple: tuple)))
        }
        XCTAssertThrowsError(try check(evidence(), version: 0x0303)) {
            XCTAssertEqual($0 as? Owner.Failure, .identityChanged)
        }
        XCTAssertThrowsError(try check(evidence(), version: 0x0302)) {
            XCTAssertEqual($0 as? Owner.Failure, .unsupportedTLS)
        }
        XCTAssertThrowsError(try check(evidence(), stable: false)) {
            XCTAssertEqual($0 as? Owner.Failure, .pathChanged)
        }
    }

    func testLateReversedOrDifferentBootSamplesCannotPass() throws {
        let boot = UUID()
        let start = clock(boot)
        XCTAssertNoThrow(try Owner.requireFresh(start, clock(boot, uptime: 10.5, wall: 1010.5), 15))
        for end in [clock(boot, uptime: 15, wall: 1015), clock(boot, uptime: 16, wall: 1016),
                    clock(boot, uptime: 9.9, wall: 1010.1), clock(boot, uptime: 10.1, wall: 1009.9),
                    clock(UUID(), uptime: 10.1, wall: 1010.1), clock(boot, uptime: 14.9, wall: 1016)] {
            XCTAssertThrowsError(try Owner.requireFresh(start, end, 15)) {
                XCTAssertEqual($0 as? Owner.Failure, .timedOut)
            }
        }
        XCTAssertThrowsError(try Owner.requireFresh(start, clock(boot, uptime: 11, wall: 1011), 11))
        XCTAssertThrowsError(try Owner.requireFresh(start, clock(boot, uptime: 14.5, wall: 1015.5), 60))
    }

    func testCancelledCaptureCannotReturnEvidence() async {
        let boot = UUID()
        let start = clock(boot)
        let result = await Task { () -> Owner.Failure? in
            withUnsafeCurrentTask { $0?.cancel() }
            do { try Owner.requireFresh(start, start, 15); return nil }
            catch { return error as? Owner.Failure }
        }.value
        XCTAssertEqual(result, .cancelled)
    }

    func testEffectiveEndpointsRequireNumericUnscopedAddresses() throws {
        for text in ["127.0.0.1", "::1", "2001:db8::1"] {
            let value = NWEndpoint.hostPort(host: .init(text), port: .https)
            XCTAssertEqual(try Owner.endpoint(value, local: false), try Owner.Endpoint(address: text, port: 443))
        }
        let invalid: [NWEndpoint?] = [nil,
            .hostPort(host: .init("still-a-name.invalid"), port: .https),
            .hostPort(host: .init("127.0.0.1"), port: .any),
            .service(name: "fixture", type: "_tls._tcp", domain: "local.", interface: nil),
            .hostPort(host: .ipv6(try XCTUnwrap(IPv6Address("::ffff:127.0.0.1"))), port: .https),
            .hostPort(host: .init("fe80::1"), port: .https),
            .hostPort(host: .init("fe80::1%lo0"), port: .https),
            .hostPort(host: .init("::"), port: .https)]
        for value in invalid {
            XCTAssertThrowsError(try Owner.endpoint(value, local: false), "\(String(describing: value))")
        }
        // Host(String) normalizes mapped text to IPv4; the effective type is already IPv4.
        let normalized = NWEndpoint.hostPort(host: .init("::ffff:127.0.0.1"), port: .https)
        XCTAssertEqual(try Owner.endpoint(normalized, local: false),
                       try Owner.Endpoint(address: "127.0.0.1", port: 443))
        let synthetic = NWEndpoint.hostPort(host: .init("198.18.0.1"), port: .https)
        XCTAssertEqual(try Owner.endpoint(synthetic, local: true).address, "198.18.0.1")
        XCTAssertThrowsError(try Owner.endpoint(synthetic, local: false))
    }
}
