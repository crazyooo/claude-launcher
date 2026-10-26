import XCTest
import Darwin
@testable import LauncherCore

final class SelectedProxyPathTests: XCTestCase {
    private func route(_ interface: String, target: String = "203.0.113.8", destination: String = "203.0.113.8",
                       gateway: String = "192.0.2.1", flags: String = "<UP,GATEWAY,DONE,STATIC>", mask: String? = nil) -> String {
        let maskLine = mask.map { "       mask: \($0)\n" } ?? ""
        return """
           route to: \(target)
        destination: \(destination)
        \(maskLine)    gateway: \(gateway)
          interface: \(interface)
              flags: \(flags)
         recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
               0         0         0         0         0         0      1500         0

        """
    }
    func testConstantAndBindConfirmationDoNotTreatMismatchAsSuccess() {
        XCTAssertEqual(Int(IP_BOUND_IF), 25)
        XCTAssertTrue(SelectedProxyPath.confirmed(requested: 15, observed: 15))
        XCTAssertFalse(SelectedProxyPath.confirmed(requested: 0, observed: 0))
        XCTAssertFalse(SelectedProxyPath.confirmed(requested: 15, observed: 7))
        XCTAssertFalse(SelectedProxyPath.confirmed(requested: 15, observed: nil))
    }
    func testRouteParserAcceptsTunnelCoverageAndRejectsAmbiguousText() {
        let tunnel = route("utun8", target: "203.0.113.43", destination: "32.0.0.0", gateway: "198.18.0.1",
                           flags: "<UP,GATEWAY,DONE,STATIC,PRCLONING>", mask: "224.0.0.0")
        let parsed = SelectedProxyPath.parseRoute(tunnel, expecting: "203.0.113.43")
        XCTAssertEqual(parsed?.interface, "utun8")
        XCTAssertEqual(parsed?.kind, "tunnel")
        XCTAssertEqual(parsed?.gateway, "198.18.0.1")
        XCTAssertNil(SelectedProxyPath.parseRoute(tunnel, expecting: "203.0.113.9"))
        XCTAssertNil(SelectedProxyPath.parseRoute(tunnel.replacingOccurrences(of: "interface: utun8", with: "interface: utun8\ninterface: en0"), expecting: "203.0.113.43"))
        XCTAssertNil(SelectedProxyPath.parseRoute("route to: default\n", expecting: "default"))
        let scoped = route("en0", target: "default", destination: "default", flags: "<UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>")
        XCTAssertEqual(SelectedProxyPath.parseRoute(scoped, expecting: "default")?.kind, "physical")
        XCTAssertNil(SelectedProxyPath.parseRoute(scoped.replacingOccurrences(of: "destination: default", with: "destination: 10.0.0.0"), expecting: "default"))
    }
    func testCandidatesRequireGlobalIPv4AndMatchingScopedDefault() {
        let en0 = route("en0", target: "default", destination: "default")
        let devices = [
            SelectedProxyPath.Device(name: "utun8", index: 28, flags: UInt32(IFF_UP), addresses: ["198.18.0.1"]),
            SelectedProxyPath.Device(name: "en0", index: 15, flags: UInt32(IFF_UP), addresses: ["192.0.2.20", "169.254.1.1"]),
            SelectedProxyPath.Device(name: "en1", index: 10, flags: UInt32(IFF_UP), addresses: ["192.0.2.30"]),
            SelectedProxyPath.Device(name: "en2", index: 11, flags: 0, addresses: ["192.0.2.40"]),
            SelectedProxyPath.Device(name: "en3", index: 12, flags: UInt32(IFF_UP), addresses: ["169.254.8.8"])
        ]
        let selected = SelectedProxyPath.candidates(devices) { $0 == "en0" ? en0 : nil }
        XCTAssertEqual(selected.map(\.name), ["en0"])
        XCTAssertEqual(selected.first?.address, "192.0.2.20")
        let rejected = SelectedProxyPath.candidates(devices) { name in
            name == "en0" ? en0.replacingOccurrences(of: "interface: en0", with: "interface: utun8") : nil
        }
        XCTAssertTrue(rejected.isEmpty)
    }
    func testCoexistenceStaysFailClosedAndComparisonIsNotAcceptance() {
        for kind in ["tunnel", nil, "physical", "other"] {
            let value = SelectedProxyPath.coexistence(routeKind: kind)
            XCTAssertEqual(value.defaultDiagnostic, "systemRoute")
            XCTAssertFalse(value.acceptance)
        }
        XCTAssertEqual(SelectedProxyPath.coexistence(routeKind: "tunnel").ownTun, "blockedWhileForeignCapture")
        XCTAssertEqual(SelectedProxyPath.coexistence(routeKind: nil).ownTun, "unknown")
        XCTAssertEqual(SelectedProxyPath.coexistence(routeKind: "physical").ownTun, "requireClearUnchanged")
        let text = SelectedProxyPath.explain(route: SelectedProxyPath.parseRoute(
            route("utun8", target: "203.0.113.43", destination: "32.0.0.0", gateway: "198.18.0.1", mask: "224.0.0.0"),
            expecting: "203.0.113.43"))
        XCTAssertTrue(text.contains("隧道"))
        XCTAssertTrue(text.contains("系统路由"))
        XCTAssertFalse(text.contains("检查通过"))
        XCTAssertTrue(SelectedProxyPath.explain(route: nil).contains("不能据此认为没有隧道"))
    }
    func testGreetingClassificationAndProjectNeverPromotesBindFailure() {
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(Data([5, 2])), "method_username")
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(Data([5, 0])), "method_none")
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(Data([5, 255])), "method_rejected")
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(Data()), "no_reply")
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(nil), "no_reply")
        XCTAssertEqual(SelectedProxyPath.classifyGreeting(Data([5, 1])), "unrecognized")
        let success = SelectedProxyObservation(host: "claude.ai", code: "exit_match", ip: "203.0.113.8")
        let blocked = SelectedProxyDiagnostic.project("interface_bind_unconfirmed", success)
        XCTAssertEqual(blocked.code, "interface_bind_unconfirmed")
        XCTAssertEqual(blocked.scope, "physicalInterface")
        XCTAssertNotEqual(blocked.result, .passed)
        let compared = SelectedProxyDiagnostic.project("ok", success)
        XCTAssertEqual(compared.code, "physical_exit_match")
        XCTAssertEqual(compared.scope, "physicalInterface")
        XCTAssertNotEqual(compared.result, .passed)
        XCTAssertFalse(compared.detail.contains("检查通过"))
    }
    func testDefaultInvocationDoesNotGainAnInterfaceAndLoopbackOverrideStaysLocal() throws {
        let config = SelectedProxyConfiguration(id: UUID(), revision: UUID(), credentialReference: nil,
                                               kind: .socks5, host: "203.0.113.8", port: 1080, expectedIP: "203.0.113.9")
        let call = try SelectedProxyDiagnostic.invocation(config, secret: nil, host: "claude.ai", timeout: 4)
        XCTAssertFalse(call.arguments.contains("--interface"))
        XCTAssertTrue(call.arguments.contains("socks5h://203.0.113.8:1080"))
        let local = try SelectedProxyDiagnostic.invocation(config, secret: nil, host: "claude.ai", timeout: 4,
                                                          localProxy: "socks5h://127.0.0.1:43123")
        XCTAssertFalse(local.arguments.contains("--interface"))
        XCTAssertTrue(local.arguments.contains("socks5h://127.0.0.1:43123"))
        XCTAssertFalse(local.arguments.contains("203.0.113.8"))
        XCTAssertThrowsError(try SelectedProxyDiagnostic.invocation(config, secret: nil, host: "claude.ai", timeout: 4,
                                                                   localProxy: "socks5h://203.0.113.8:1080"))
    }
    func testKernelBindRoundTripAndFailedBindDoesNotConnect() throws {
        let index = "lo0".withCString { if_nametoindex($0) }
        XCTAssertGreaterThan(index, 0)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        XCTAssertGreaterThanOrEqual(fd, 0)
        defer { close(fd) }
        var value = Int32(index)
        XCTAssertEqual(setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &value, socklen_t(MemoryLayout<Int32>.size)), 0)
        var observed: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        XCTAssertEqual(getsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &observed, &length), 0)
        XCTAssertEqual(UInt32(observed), index)
        let refused = SelectedProxyPath.handshake(host: "127.0.0.1", port: 9, name: "lo0", index: index, timeout: 0.2)
        XCTAssertEqual(refused.physicalCode, "interface_unavailable")
        XCTAssertFalse(refused.summary.contains("检查通过"))
        let server = try LoopbackServer()
        defer { server.stop() }
        let missed = SelectedProxyPath.exchange(host: "127.0.0.1", port: server.port, index: 2_000_000_000, timeout: 0.4)
        XCTAssertEqual(missed, "interface_bind_unconfirmed")
        XCTAssertEqual(server.accepted, 0)
        let matched = SelectedProxyPath.exchange(host: "127.0.0.1", port: server.port, index: index, timeout: 2)
        XCTAssertEqual(matched, "method_username")
        XCTAssertEqual(server.firstBytes, Data([5, 2, 0, 2]))
        XCTAssertEqual(server.accepted, 1)
        let blocked = SelectedProxyPath.forward(index: 2_000_000_000, proxyHost: "127.0.0.1", proxyPort: server.port, timeout: 1) { port in
            let client = socket(AF_INET, SOCK_STREAM, 0)
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = UInt16(port).bigEndian
            _ = inet_pton(AF_INET, "127.0.0.1", &address.sin_addr)
            _ = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(client, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
            close(client)
        }
        XCTAssertEqual(blocked, "interface_bind_unconfirmed")
        XCTAssertEqual(server.accepted, 1)
        let config = SelectedProxyConfiguration(id: UUID(), revision: UUID(), credentialReference: nil,
                                               kind: .socks5, host: "127.0.0.1", port: server.port, expectedIP: "")
        let carried = SelectedProxyPath.forward(index: index, proxyHost: "127.0.0.1", proxyPort: server.port, timeout: 3) { port in
            let call = try! SelectedProxyDiagnostic.invocation(config, secret: nil, host: "claude.ai", timeout: 2,
                                                              localProxy: "socks5h://127.0.0.1:\(port)")
            _ = BoundedProcess.diagnostic(arguments: call.arguments, timeout: 2, input: call.input, cancelled: { false })
        }
        XCTAssertEqual(carried, "ok")
        XCTAssertEqual(server.accepted, 2)
        XCTAssertEqual(server.firstBytes, Data([5, 2, 0, 2]))
    }
    func testLiveRouteSampleStaysUnacceptedAndDoesNotInventAnInterface() {
        let report = SelectedProxyPath.report("203.0.113.43")
        XCTAssertEqual(report.defaultDiagnostic, "systemRoute")
        XCTAssertFalse(report.comparisonIsAcceptance)
        XCTAssertFalse(report.summary.contains("检查通过"))
        XCTAssertTrue(report.candidates.allSatisfy { SelectedProxyPath.physicalName($0.name) && $0.index > 0 })
        XCTAssertNotEqual(report.routeKind, "unknown", report.summary)
        switch report.routeKind {
        case "tunnel": XCTAssertEqual(report.ownTunEnablement, "blockedWhileForeignCapture")
        default: XCTAssertEqual(report.ownTunEnablement, "requireClearUnchanged")
        }
    }
}

private final class LoopbackServer: @unchecked Sendable {
    let port: Int
    private let fd: Int32
    private let lock = NSLock()
    private var connections = 0
    private var bytes = Data()
    private var stopped = false
    var accepted: Int { lock.lock(); defer { lock.unlock() }; return connections }
    var firstBytes: Data { lock.lock(); defer { lock.unlock() }; return bytes }
    func stop() {
        lock.lock(); stopped = true; lock.unlock()
        close(fd)
        let deadline = Date().addingTimeInterval(1)
        while Date() < deadline {
            lock.lock(); let done = stopped && connections >= 0 && !running; lock.unlock()
            if done { return }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }
    private var running = true
    init() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.ECONNREFUSED) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        XCTAssertEqual(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr), 1)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard bound == 0, listen(fd, 4) == 0 else { close(fd); throw POSIXError(.EADDRNOTAVAIL) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        var named = sockaddr_in()
        let ok = withUnsafeMutablePointer(to: &named) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } == 0
        }
        guard ok else { close(fd); throw POSIXError(.EADDRNOTAVAIL) }
        self.fd = fd
        port = Int(UInt16(bigEndian: named.sin_port))
        Thread.detachNewThread { [self] in
            while true {
                var peer = sockaddr_in()
                var size = socklen_t(MemoryLayout<sockaddr_in>.size)
                let client = withUnsafeMutablePointer(to: &peer) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { accept(self.fd, $0, &size) }
                }
                if client < 0 { break }
                var buffer = [UInt8](repeating: 0, count: 4)
                let count = read(client, &buffer, 4)
                let reply: [UInt8] = [5, 2]
                _ = Darwin.write(client, reply, reply.count)
                close(client)
                lock.lock()
                connections += 1
                if bytes.isEmpty, count > 0 { bytes = Data(buffer.prefix(count)) }
                lock.unlock()
            }
            lock.lock(); running = false; lock.unlock()
        }
    }
}
