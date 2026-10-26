import XCTest
import Darwin
import Network
@testable import RoutingCore

private func outboundRow(family: Int32 = AF_INET) -> socket_fdinfo {
    var info = socket_fdinfo()
    info.psi.soi_type = SOCK_STREAM; info.psi.soi_protocol = IPPROTO_TCP
    info.psi.soi_kind = Int32(SOCKINFO_TCP); info.psi.soi_family = family
    info.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_ESTABLISHED
    info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(family == AF_INET ? INI_IPV4 : INI_IPV6)
    info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt = 50
    info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = Int32(UInt16(45000).bigEndian)
    info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = Int32(UInt16(443).bigEndian)
    if family == AF_INET {
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr = inet_addr("192.0.2.2")
        info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr = inet_addr("203.0.113.1")
    } else {
        inet_pton(AF_INET6, "2001:db8::2", &info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_6)
        inet_pton(AF_INET6, "2001:db8::1", &info.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6)
    }
    return info
}

final class RouterSystemOutboundSocketTests: XCTestCase {
    private typealias Observer = RouterSystemOutboundSocket
    private let size = Int32(MemoryLayout<socket_fdinfo>.stride)

    private final class Harness {
        let boot = UUID()
        var clockBoot: UUID?
        var processBoot: UUID?
        var now = 10.0, wallOffset = 1000.0
        var row = outboundRow(), bytes = Int32(MemoryLayout<socket_fdinfo>.stride)
        var path = "/test/outbound", pid = getpid(), uid = getuid(), realUID = getuid()
        var birth: UInt64 = 900, microseconds: UInt64 = 0
        var processes = 0, lists = 0, sockets = 0
        var entries: [proc_fdinfo] = {
            var entry = proc_fdinfo(); entry.proc_fd = 42; entry.proc_fdtype = UInt32(PROX_FDTYPE_SOCKET)
            return [entry]
        }()
        var listHook: ((Int) throws -> Void)?
        var processHook: ((Int) throws -> Void)?
        var socketHook: ((Int32) throws -> Void)?
        var clock: RouterSystemClock {
            .init(bootID: clockBoot ?? boot, uptime: now, date: Date(timeIntervalSince1970: now + wallOffset))
        }
        var readers: Observer.Readers {
            .init(clock: { self.clock }, process: {
                self.processes += 1; try self.processHook?(self.processes)
                return .init(identity: .init(work: .init(bootID: self.processBoot ?? self.boot, pid: self.pid,
                    birthSeconds: self.birth, birthMicroseconds: self.microseconds),
                    uid: self.uid, realUID: self.realUID, parentPID: 1, processGroup: self.pid), path: self.path)
            }, descriptors: {
                self.lists += 1; try self.listHook?(self.lists); return self.entries
            }, socket: { fd in
                self.sockets += 1; try self.socketHook?(fd); return (self.row, self.bytes)
            })
        }
        func tuple() throws -> Observer.Tuple {
            try .init(local: .init(address: "192.0.2.2", port: 45000),
                      peer: .init(address: "203.0.113.1", port: 443))
        }
        func run(deadline: Double = 60) throws -> Observer.Observation {
            Observer.fixture(tuple: try tuple(), until: deadline, readers: readers)
        }
    }
    private func evidence(_ observation: Observer.Observation, file: StaticString = #filePath,
                          line: UInt = #line) throws -> Observer.Evidence {
        guard case .observed(let evidence) = observation else {
            XCTFail("Expected observed, got \(observation)", file: file, line: line)
            throw RouterSystemError.ownershipUnknown
        }
        return evidence
    }
    private func unknown(_ observation: Observer.Observation, _ reason: Observer.Unknown,
                         file: StaticString = #filePath, line: UInt = #line) {
        guard case .unknown(let actual) = observation else {
            return XCTFail("Expected unknown", file: file, line: line)
        }
        XCTAssertEqual(actual, reason, file: file, line: line)
    }

    func testIPv4IPv6DecoderUsesFullTupleAndNetworkOrderPorts() throws {
        for family in [AF_INET, AF_INET6] {
            let row = outboundRow(family: family)
            let value = try XCTUnwrap(Observer.decode(row, bytes: size, descriptor: 42))
            XCTAssertEqual(value.descriptor, 42); XCTAssertEqual(value.generation, 50)
            XCTAssertEqual(value.tuple.local.port, 45000); XCTAssertEqual(value.tuple.peer.port, 443)
            XCTAssertEqual(value.tuple.local.address, family == AF_INET ? "192.0.2.2" : "2001:db8::2")
            XCTAssertEqual(value.tuple.peer.address, family == AF_INET ? "203.0.113.1" : "2001:db8::1")
        }
        var row = outboundRow()
        row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr = inet_addr("198.18.0.1")
        XCTAssertEqual(try Observer.decode(row, bytes: size, descriptor: 1)?.tuple.local.address, "198.18.0.1")
    }
    func testNonTCPAndNonEstablishedDoNotMatch() throws {
        let changes: [(inout socket_fdinfo) -> Void] = [
            { $0.psi.soi_family = AF_UNIX }, { $0.psi.soi_type = SOCK_DGRAM },
            { $0.psi.soi_protocol = IPPROTO_UDP }, { $0.psi.soi_kind = Int32(SOCKINFO_IN) }
        ] + [TSI_S_LISTEN, TSI_S_SYN_SENT, TSI_S_SYN_RECEIVED, TSI_S__CLOSE_WAIT, TSI_S_CLOSED].map { state in
            { $0.psi.soi_proto.pri_tcp.tcpsi_state = state }
        }
        for change in changes {
            var row = outboundRow(); change(&row)
            XCTAssertNil(try Observer.decode(row, bytes: size, descriptor: 42))
        }
    }
    func testMalformedKernelRowsAreNotSilentlySkipped() throws {
        for bytes in [Int32(-1), 0, size - 1, size + 1] {
            XCTAssertThrowsError(try Observer.decode(outboundRow(), bytes: bytes, descriptor: 42))
        }
        XCTAssertThrowsError(try Observer.decode(outboundRow(), bytes: size, descriptor: -1))
        let changes: [(inout socket_fdinfo) -> Void] = [
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt = 0 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(INI_IPV4 | INI_IPV6) },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = 0 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = -1 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = 65536 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = 0 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = 65536 },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr = 0 }
        ]
        for change in changes {
            var row = outboundRow(); change(&row)
            XCTAssertThrowsError(try Observer.decode(row, bytes: size, descriptor: 42))
        }
        for ip in ["::ffff:192.0.2.1", "::192.0.2.1", "::", "fe80::1", "ff02::1"] {
            var row = outboundRow(family: AF_INET6)
            XCTAssertEqual(inet_pton(AF_INET6, ip, &row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_6), 1)
            XCTAssertThrowsError(try Observer.decode(row, bytes: size, descriptor: 42), ip)
        }
        var dual = outboundRow(family: AF_INET6)
        dual.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(INI_IPV4 | INI_IPV6)
        XCTAssertThrowsError(try Observer.decode(dual, bytes: size, descriptor: 42))
    }
    func testTwoConsistentScansProduceOnlyFixtureEvidence() throws {
        let h = Harness()
        let observed = try evidence(h.run())
        XCTAssertEqual(h.lists, 2); XCTAssertEqual(h.sockets, 2); XCTAssertEqual(h.processes, 3)
        XCTAssertEqual(observed.socket.tuple, try h.tuple())
        XCTAssertEqual(observed.source, .fixture)
        XCTAssertFalse(observed.collectorAuthenticated); XCTAssertFalse(observed.canPromoteAccepted)
        unknown(Observer.installedSelf(tuple: try h.tuple(), until: 60), .unavailable)
    }
    func testIdentityAndPathChangeDiscardsBothScans() throws {
        for after in [2, 3] {
            for kind in 0..<6 {
                let h = Harness()
                h.processHook = { count in
                    guard count == after else { return }
                    switch kind {
                    case 0: h.pid += 1
                    case 1: h.birth += 1
                    case 2: h.microseconds += 1
                    case 3: h.uid += 1
                    case 4: h.realUID += 1
                    default: h.path = "/changed/image"
                    }
                }
                unknown(try h.run(), .changed)
            }
        }
    }
    func testInitialIdentityMustBeCurrentProcessAndValid() throws {
        for kind in 0..<6 {
            let h = Harness()
            switch kind {
            case 0: h.pid += 1
            case 1: h.uid += 1
            case 2: h.realUID += 1
            case 3: h.birth = 2000
            case 4: h.microseconds = 1_000_000
            default: h.path = "relative"
            }
            unknown(try h.run(), .incomplete)
            XCTAssertEqual(h.lists, 0)
        }
    }
    func testFDGenerationAndTupleMustRemainStable() throws {
        for kind in 0..<6 {
            let h = Harness()
            h.listHook = { count in
                guard count == 2 else { return }
                switch kind {
                case 0: h.entries[0].proc_fd += 1
                case 1: h.row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt += 1
                case 2: h.row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = Int32(UInt16(45001).bigEndian)
                case 3: h.row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport = Int32(UInt16(444).bigEndian)
                case 4: h.row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr = inet_addr("192.0.2.3")
                default: h.row.psi.soi_proto.pri_tcp.tcpsi_ini.insi_faddr.ina_46.i46a_addr4.s_addr = inet_addr("203.0.113.2")
                }
            }
            unknown(try h.run(), .changed)
        }
    }
    func testMissingAmbiguousAndIncompleteStayUnknown() throws {
        let missing = Harness()
        missing.row.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_CLOSED
        unknown(try missing.run(), .notObserved)
        let ambiguous = Harness()
        var alias = ambiguous.entries[0]; alias.proc_fd = 43
        ambiguous.entries.append(alias)
        unknown(try ambiguous.run(), .ambiguous)
        for kind in 0..<5 {
            let h = Harness()
            switch kind {
            case 0: h.entries = []
            case 1: h.entries.append(h.entries[0])
            case 2: h.entries[0].proc_fd = -1
            case 3: h.entries = Array(repeating: h.entries[0], count: 8192)
            default: h.bytes = 0
            }
            unknown(try h.run(), .incomplete)
        }
        let h = Harness()
        var unrelated = h.entries[0]; unrelated.proc_fd = 44; h.entries.append(unrelated)
        h.socketHook = { fd in if fd == 44 { throw RouterSystemError.ownershipUnknown } }
        unknown(try h.run(), .incomplete)
    }
    func testOriginalDeadlineAndConsecutiveClocksRemainBounded() throws {
        for deadline in [11.0, 60.0] {
            let h = Harness()
            h.listHook = { _ in h.now = min(deadline, 15) }
            unknown(try h.run(deadline: deadline), .timedOut)
        }
        for wallOnly in [false, true] {
            let h = Harness()
            h.listHook = { count in
                if count == 1 { h.now += 1 }
                else if wallOnly { h.wallOffset -= 0.25 }
                else { h.now -= 0.25 }
            }
            unknown(try h.run(), .timedOut)
        }
        let h = Harness()
        unknown(try h.run(deadline: .nan), .incomplete)
        unknown(try h.run(deadline: 10), .timedOut)
    }
    func testCancellationDoesNotRetryScanning() async throws {
        let h = Harness()
        let observed = await Task {
            h.listHook = { _ in withUnsafeCurrentTask { $0?.cancel() } }
            return try h.run()
        }.result
        unknown(try observed.get(), .cancelled)
        XCTAssertEqual(h.lists, 1); XCTAssertEqual(h.sockets, 0)
    }
    func testBootCannotChangeOrDifferFromProcess() throws {
        let mismatch = Harness(); mismatch.processBoot = UUID()
        unknown(try mismatch.run(), .incomplete)
        for clockChanged in [false, true] {
            let h = Harness()
            h.listHook = { count in
                guard count == 2 else { return }
                if clockChanged { h.clockBoot = UUID() } else { h.processBoot = UUID() }
            }
            unknown(try h.run(), clockChanged ? .timedOut : .changed)
        }
    }
    func testFinalIdentityReadCannotHideDeadlineOrCancellation() async throws {
        let expired = Harness()
        expired.processHook = { count in if count == 3 { expired.now = 15 } }
        unknown(try expired.run(), .timedOut)
        XCTAssertEqual(expired.lists, 2)
        let h = Harness()
        let observed = await Task {
            h.processHook = { count in if count == 3 { withUnsafeCurrentTask { $0?.cancel() } } }
            return try h.run()
        }.result
        unknown(try observed.get(), .cancelled)
        XCTAssertEqual(h.lists, 2); XCTAssertEqual(h.processes, 3)
    }

    func testActualPOSIXIPv4IPv6SocketObservationDoesNotOwnDescriptor() throws {
        for family in [AF_INET, AF_INET6] {
            let server = try RouterLoopbackEchoFixture(family: family)
            defer { server.stop() }
            let probe = try RouterOwnedTCPProbe.loopbackFixture(endpoint: server.target,
                until: ProcessInfo.processInfo.systemUptime + 3)
            defer { probe.close() }
            let sample = try probe.sample(until: ProcessInfo.processInfo.systemUptime + 3)
            let first = try evidence(Observer.fixtureSelf(tuple: sample.tuple, until: ProcessInfo.processInfo.systemUptime + 3))
            let second = try evidence(Observer.fixtureSelf(tuple: sample.tuple, until: ProcessInfo.processInfo.systemUptime + 3))
            XCTAssertEqual(first.socket, second.socket)
            XCTAssertEqual(first.process.identity, sample.process.identity)
            XCTAssertEqual(first.process.path, sample.process.path)
            XCTAssertGreaterThan(first.socket.generation, 0)
            // A subsequent exchange still works: the observer did not close or consume the FD.
            _ = try probe.exchangeLoopbackFixture(nonce: UUID(), until: ProcessInfo.processInfo.systemUptime + 3)
            probe.close(); _ = try server.finish()
            unknown(Observer.fixtureSelf(tuple: sample.tuple, until: ProcessInfo.processInfo.systemUptime + 3), .notObserved)
        }
    }

    func testNetworkFrameworkIPv4IPv6EffectiveEndpointsMatchKernelSocket() throws {
        for family in [AF_INET, AF_INET6] {
            let server = try RouterLoopbackEchoFixture(family: family)
            defer { server.stop() }
            let connection = NWConnection(host: .init(server.target.address),
                port: try XCTUnwrap(.init(rawValue: server.target.port)), using: .tcp)
            let ready = DispatchSemaphore(value: 0), cancelled = DispatchSemaphore(value: 0)
            let queue = DispatchQueue(label: "router-outbound-loopback-test")
            let lock = NSLock()
            var didBecomeReady = false, didFinishStart = false
            connection.stateUpdateHandler = { state in
                lock.lock(); defer { lock.unlock() }
                if case .ready = state, !didFinishStart {
                    didFinishStart = true; didBecomeReady = true; ready.signal()
                }
                if case .failed = state, !didFinishStart {
                    didFinishStart = true; ready.signal()
                }
                if case .cancelled = state { cancelled.signal() }
            }
            connection.start(queue: queue)
            defer { connection.forceCancel() }
            XCTAssertEqual(ready.wait(timeout: .now() + 3), .success)
            lock.lock(); let connected = didBecomeReady; lock.unlock()
            guard connected else { return XCTFail("loopback NWConnection did not become ready") }
            func endpoint(_ value: NWEndpoint?) throws -> RouterOwnedTCPProbe.Endpoint {
                guard case .hostPort(let host, let port) = try XCTUnwrap(value) else {
                    throw RouterOwnedProbeError.invalidTarget
                }
                let address: String
                switch host {
                case .ipv4(let value): address = value.debugDescription
                case .ipv6(let value): address = value.debugDescription
                default: throw RouterOwnedProbeError.invalidTarget
                }
                guard !address.contains("%") else { throw RouterOwnedProbeError.invalidTarget }
                return try .init(address: address, port: port.rawValue)
            }
            let path = try XCTUnwrap(connection.currentPath)
            let tuple = try Observer.Tuple(local: endpoint(path.localEndpoint), peer: endpoint(path.remoteEndpoint))
            XCTAssertEqual(tuple.peer, server.target)
            let first = try evidence(Observer.fixtureSelf(tuple: tuple, until: ProcessInfo.processInfo.systemUptime + 3))
            let second = try evidence(Observer.fixtureSelf(tuple: tuple, until: ProcessInfo.processInfo.systemUptime + 3))
            XCTAssertEqual(first.socket, second.socket)
            XCTAssertEqual(first.process.identity.work.pid, getpid())
            XCTAssertFalse(first.collectorAuthenticated)
            connection.cancel()
            XCTAssertEqual(cancelled.wait(timeout: .now() + 3), .success)
            // This test intentionally sends no frame; peer EOF verifies bounded cleanup.
            XCTAssertThrowsError(try server.finish()) { XCTAssertEqual($0 as? RouterTCPEchoError, .eof) }
        }
    }
}
