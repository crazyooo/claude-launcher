import XCTest
import Darwin
@testable import RoutingCore

final class RouterOwnedTCPProbeTests: XCTestCase {
    private final class Harness {
        let boot = UUID()
        var now: Double = 10
        var wallOffset: Double = 1000
        var closes = 0, processes = 0, tuples = 0
        var path = "/test/probe", fail = ""
        var deadlineSeen: Double?
        var clock: RouterSystemClock { .init(bootID: boot, uptime: now, date: Date(timeIntervalSince1970: now + wallOffset)) }
        var effects: RouterOwnedTCPProbe.Effects {
            .init(clock: { self.clock }, process: {
                self.processes += 1
                if self.fail == "process" && self.processes > 1 { self.path = "/changed/image" }
                return .init(identity: .init(work: .init(bootID: self.boot, pid: 999, birthSeconds: 900, birthMicroseconds: 0),
                    uid: 501, realUID: 501, parentPID: 1, processGroup: 999), path: self.path)
            }, create: { _ in 42 }, configure: { _, _ in
                if self.fail == "configure" { throw RouterOwnedProbeError.unavailable }
            }, connect: { _, _, deadline in
                self.deadlineSeen = deadline
                if self.fail == "connect" { throw RouterOwnedProbeError.refused }
                if self.fail == "timeout" { self.now = deadline }
            }, tuple: { _ in
                self.tuples += 1
                return try .init(local: .init(address: "192.0.2.2", port: 45000),
                                 peer: .init(address: self.fail == "peer" ? "203.0.113.2" : "203.0.113.1", port: 443))
            }, close: { fd in XCTAssertEqual(fd, 42); self.closes += 1 })
        }
        func open() throws -> RouterOwnedTCPProbe {
            try .fixture(endpoint: .init(address: "203.0.113.1", port: 443), until: 2000, effects: effects)
        }
    }

    func testOwnsOneDescriptorAcrossOpenSampleAndIdempotentClose() throws {
        let h = Harness()
        var probe: RouterOwnedTCPProbe? = try h.open()
        XCTAssertEqual(h.deadlineSeen, 13)
        XCTAssertEqual(h.closes, 0)
        XCTAssertTrue(try XCTUnwrap(probe).fixture)
        XCTAssertEqual(try probe?.sample(until: 60).process.path, "/test/probe")
        probe?.close(); probe?.close()
        XCTAssertThrowsError(try probe?.sample(until: 60)) { XCTAssertEqual($0 as? RouterOwnedProbeError, .closed) }
        probe = nil
        XCTAssertEqual(h.closes, 1)
    }
    func testEveryOpeningFailureClosesOnceAndNeverRetries() throws {
        for failure in ["configure", "connect", "timeout", "peer", "process"] {
            let h = Harness(); h.fail = failure
            XCTAssertThrowsError(try h.open(), failure)
            XCTAssertEqual(h.closes, 1, failure)
        }
        let h = Harness()
        var probe: RouterOwnedTCPProbe? = try h.open()
        h.path = "/changed/image"
        XCTAssertThrowsError(try probe?.sample(until: 60))
        probe = nil
        XCTAssertEqual(h.closes, 1)
    }
    func testReadyTimestampExcludesConnectionAndIdentityChecks() throws {
        let h = Harness()
        var effects = h.effects
        let originalConfigure = effects.configure
        effects.configure = { descriptor, family in
            try originalConfigure(descriptor, family)
            h.now += 0.25
        }
        let originalConnect = effects.connect
        let originalTuple = effects.tuple
        let originalProcess = effects.process
        effects.connect = { descriptor, target, deadline in
            try originalConnect(descriptor, target, deadline)
            h.now += 0.5
        }
        effects.tuple = { descriptor in
            let observed = try originalTuple(descriptor)
            h.now += 0.25
            return observed
        }
        effects.process = {
            let observed = try originalProcess()
            if h.processes == 2 { h.now += 0.25 }
            return observed
        }
        let probe = try RouterOwnedTCPProbe.fixture(
            endpoint: .init(address: "203.0.113.1", port: 443), until: 2000, effects: effects)
        defer { probe.close() }
        XCTAssertEqual(probe.connectStartedAt.uptime, 10.25)
        XCTAssertEqual(probe.openedAt.uptime, 11.25)
        XCTAssertEqual(probe.openedAt.date, Date(timeIntervalSince1970: 1011.25))
        XCTAssertEqual(h.deadlineSeen, 13)
        XCTAssertEqual(h.closes, 0)
        // A time after operation start can still precede the verified held interval.
        h.now = 11
        XCTAssertThrowsError(try probe.sample(until: 60)) {
            XCTAssertEqual($0 as? RouterOwnedProbeError, .timedOut)
        }
        probe.close()
        XCTAssertEqual(h.closes, 1)
    }
    func testFinalIdentityCheckStillUsesOriginalConnectDeadline() throws {
        let h = Harness()
        var effects = h.effects
        let originalProcess = effects.process
        effects.process = {
            let observed = try originalProcess()
            if h.processes == 2 { h.now = 13 }
            return observed
        }
        XCTAssertThrowsError(try RouterOwnedTCPProbe.fixture(
            endpoint: .init(address: "203.0.113.1", port: 443), until: 2000, effects: effects)) {
            XCTAssertEqual($0 as? RouterOwnedProbeError, .timedOut)
        }
        XCTAssertEqual(h.deadlineSeen, 13)
        XCTAssertEqual(h.closes, 1)
    }
    func testConnectCannotReverseEitherClockAfterConfiguration() throws {
        for wallOnly in [false, true] {
            let h = Harness()
            var effects = h.effects
            effects.configure = { _, _ in h.now += 1 }
            effects.connect = { _, _, _ in
                if wallOnly { h.now += 0.25; h.wallOffset -= 0.5 }
                else { h.now -= 0.25 }
            }
            XCTAssertThrowsError(try RouterOwnedTCPProbe.fixture(
                endpoint: .init(address: "203.0.113.1", port: 443), until: 2000, effects: effects)) {
                XCTAssertEqual($0 as? RouterOwnedProbeError, .timedOut)
            }
            XCTAssertEqual(h.closes, 1)
        }
    }
    func testEndpointValidationAndAddressByteOrder() throws {
        for address in ["hostname.example", "0.0.0.0", "224.0.0.1", "255.255.255.255", "198.18.0.7",
                        "169.254.1.1", "::", "::ffff:192.0.2.1", "::192.0.2.1", "fe80::1", "ff02::1", "fdfe:dcba:9876::2"] {
            XCTAssertThrowsError(try RouterOwnedTCPProbe.Endpoint(address: address, port: 443), address)
        }
        XCTAssertThrowsError(try RouterOwnedTCPProbe.Endpoint(address: "192.0.2.1", port: 0))
        XCTAssertEqual(try RouterOwnedTCPProbe.Endpoint(address: "2001:db8::1", port: 443),
                       try RouterOwnedTCPProbe.Endpoint(address: "2001:0db8:0:0:0:0:0:1", port: 443))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(45000).bigEndian; address.sin_addr.s_addr = inet_addr("198.18.0.1")
        var storage = sockaddr_storage()
        withUnsafeMutableBytes(of: &storage) { target in withUnsafeBytes(of: address) { target.copyBytes(from: $0) } }
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(try RouterOwnedTCPProbe.decodeAddress(storage, length: size, local: true).port, 45000)
        XCTAssertThrowsError(try RouterOwnedTCPProbe.decodeAddress(storage, length: size))
        XCTAssertThrowsError(try RouterOwnedTCPProbe.decodeAddress(storage, length: size - 1, local: true))
        storage.ss_family = sa_family_t(AF_UNIX)
        XCTAssertThrowsError(try RouterOwnedTCPProbe.decodeAddress(storage, length: size, local: true))
    }
    func testConnectPollRetriesOnlyEINTRWithinOriginalDeadline() throws {
        var now = 10.0, polls = 0, errors = 0
        try RouterOwnedTCPProbe.waitForConnect(deadline: 13, uptime: { now }, poll: { timeout in
            XCTAssertLessThanOrEqual(timeout, 3000)
            polls += 1; now += 0.5
            return polls == 1 ? (-1, EINTR, 0) : (1, 0, Int16(POLLOUT))
        }, socketError: { errors += 1; return 0 })
        XCTAssertEqual(polls, 2); XCTAssertEqual(errors, 1)
        XCTAssertThrowsError(try RouterOwnedTCPProbe.waitForConnect(deadline: 13, uptime: { 10 },
            poll: { _ in (1, 0, Int16(POLLERR)) }, socketError: { ECONNREFUSED })) {
            XCTAssertEqual($0 as? RouterOwnedProbeError, .refused)
        }
        now = 10; polls = 0
        XCTAssertThrowsError(try RouterOwnedTCPProbe.waitForConnect(deadline: 13, uptime: { now }, poll: { _ in
            polls += 1; now += 1; return (-1, EINTR, 0)
        }, socketError: { XCTFail("expired loop must not read SO_ERROR"); return 0 }))
        XCTAssertEqual(polls, 3)
        for event in [Int16(POLLNVAL), 0] {
            XCTAssertThrowsError(try RouterOwnedTCPProbe.waitForConnect(deadline: 13, uptime: { 10 },
                poll: { _ in (1, 0, event) }, socketError: { 0 }))
        }
    }
    func testClockBootWallAndUptimeRemainBounded() throws {
        let h = Harness(), began = h.clock
        for now in [RouterSystemClock(bootID: UUID(), uptime: 11, date: began.date.addingTimeInterval(1)),
                    .init(bootID: h.boot, uptime: 9, date: began.date.addingTimeInterval(-1)),
                    .init(bootID: h.boot, uptime: 11, date: began.date.addingTimeInterval(10)),
                    .init(bootID: h.boot, uptime: 70, date: began.date.addingTimeInterval(60))] {
            XCTAssertThrowsError(try RouterOwnedTCPProbe.requireFresh(start: began, now: now, deadline: 70))
        }
    }
    func testRealSelfLoopbackIPv4AndIPv6WithoutPayload() throws {
        for family in [AF_INET, AF_INET6] {
            let listener = socket(family, SOCK_STREAM, IPPROTO_TCP)
            XCTAssertGreaterThanOrEqual(listener, 0)
            guard listener >= 0 else { continue }
            defer { _ = Darwin.close(listener) }
            var storage = sockaddr_storage()
            let length: socklen_t
            if family == AF_INET {
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
                address.sin_addr.s_addr = inet_addr("127.0.0.1")
                length = socklen_t(MemoryLayout<sockaddr_in>.size)
                withUnsafeMutableBytes(of: &storage) { target in withUnsafeBytes(of: address) { target.copyBytes(from: $0) } }
            } else {
                var address = sockaddr_in6()
                address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size); address.sin6_family = sa_family_t(AF_INET6)
                XCTAssertEqual(inet_pton(AF_INET6, "::1", &address.sin6_addr), 1)
                length = socklen_t(MemoryLayout<sockaddr_in6>.size)
                withUnsafeMutableBytes(of: &storage) { target in withUnsafeBytes(of: address) { target.copyBytes(from: $0) } }
            }
            let bound = withUnsafePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, length) }
            }
            guard bound == 0 else { XCTFail("loopback bind failed"); throw RouterOwnedProbeError.unavailable }
            guard listen(listener, 1) == 0 else { XCTFail("loopback listen failed"); throw RouterOwnedProbeError.unavailable }
            var boundLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
            let named = withUnsafeMutablePointer(to: &storage) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &boundLength) }
            }
            guard named == 0 else { XCTFail("loopback name unavailable"); throw RouterOwnedProbeError.unavailable }
            let target = try RouterOwnedTCPProbe.decodeAddress(storage, length: boundLength)
            let probe = try RouterOwnedTCPProbe.loopbackFixture(endpoint: target,
                until: ProcessInfo.processInfo.systemUptime + 3)
            defer { probe.close() }
            let snapshot = try probe.sample(until: ProcessInfo.processInfo.systemUptime + 3)
            XCTAssertEqual(snapshot.tuple.peer, target)
            XCTAssertEqual(snapshot.process.identity.work.pid, getpid())
            XCTAssertEqual(snapshot.process.identity.uid, getuid())
            XCTAssertTrue(snapshot.tuple.local.isLoopback)
            XCTAssertTrue(snapshot.process.path.hasPrefix("/"))
            XCTAssertTrue(probe.fixture)
        }
    }
}
