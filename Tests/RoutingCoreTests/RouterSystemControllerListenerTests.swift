import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemControllerListenerTests: XCTestCase {
    private typealias Listener = RouterSystemControllerListener
    private let size = Int32(MemoryLayout<socket_fdinfo>.stride)
    private func listening() -> socket_fdinfo {
        var value = socket_fdinfo()
        value.psi.soi_family = AF_INET; value.psi.soi_type = SOCK_STREAM
        value.psi.soi_protocol = IPPROTO_TCP; value.psi.soi_kind = Int32(SOCKINFO_TCP)
        value.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_LISTEN
        value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(INI_IPV4)
        value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = Int32(UInt16(19492).bigEndian)
        value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr = inet_addr("127.0.0.1")
        value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt = 42
        return value
    }
    func testOnlyExactIPv4TCPListenerMatches() throws {
        let valid = listening()
        XCTAssertEqual(try Listener.decodeSocket(valid, bytes: size, descriptor: 9, port: 19492),
                       .init(descriptor: 9, generation: 42))
        let changes: [(inout socket_fdinfo) -> Void] = [
            { $0.psi.soi_family = AF_INET6 }, { $0.psi.soi_type = SOCK_DGRAM },
            { $0.psi.soi_protocol = IPPROTO_UDP }, { $0.psi.soi_kind = Int32(SOCKINFO_IN) },
            { $0.psi.soi_proto.pri_tcp.tcpsi_state = TSI_S_ESTABLISHED },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_vflag = UInt8(INI_IPV4 | INI_IPV6) },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = Int32(UInt16(19493).bigEndian) },
            { $0.psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr = 0 }
        ]
        for change in changes {
            var value = valid; change(&value)
            XCTAssertNil(try Listener.decodeSocket(value, bytes: size, descriptor: 9, port: 19492))
        }
    }
    func testIncompleteSocketAndGenerationEvidenceThrows() {
        for count in [Int32(-1), 0, size - 1, size + 1] {
            XCTAssertThrowsError(try Listener.decodeSocket(listening(), bytes: count, descriptor: 9, port: 19492))
        }
        var value = listening(); value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_gencnt = 0
        XCTAssertThrowsError(try Listener.decodeSocket(value, bytes: size, descriptor: 9, port: 19492))
        for port: Int32 in [-1, 65536] {
            value = listening(); value.psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport = port
            XCTAssertThrowsError(try Listener.decodeSocket(value, bytes: size, descriptor: 9, port: 19492))
        }
    }
    func testFDEnumerationRejectsTruncationAndDuplicateDescriptors() throws {
        var entries = [proc_fdinfo](repeating: .init(), count: 3)
        entries[0].proc_fd = 3; entries[1].proc_fd = 5
        let stride = Int32(MemoryLayout<proc_fdinfo>.stride)
        XCTAssertEqual(try Listener.decodeDescriptors(entries, bytes: 2 * stride).map(\.proc_fd), [3, 5])
        for count in [Int32(-1), 0, stride - 1, stride * 3, stride * 4] {
            XCTAssertThrowsError(try Listener.decodeDescriptors(entries, bytes: count))
        }
        entries[1].proc_fd = 3
        XCTAssertThrowsError(try Listener.decodeDescriptors(entries, bytes: stride * 2))
        entries[1].proc_fd = -1
        XCTAssertThrowsError(try Listener.decodeDescriptors(entries, bytes: stride * 2))
    }
    func testRealEphemeralSelfListenerWithoutExternalConnections() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return XCTFail("socket failed") }
        var held = true
        defer { if held { close(fd) } }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        XCTAssertEqual(bound, 0); XCTAssertEqual(listen(fd, 1), 0)
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }, 0)
        let port = UInt16(bigEndian: address.sin_port)
        guard case .observed(let evidence) = try Listener.fixtureSelf(port: port, deadline: ProcessInfo.processInfo.systemUptime + 3) else {
            return XCTFail("self listener not observed")
        }
        XCTAssertTrue(evidence.contains { $0.descriptor == fd && $0.generation > 0 })
        close(fd); held = false
        XCTAssertEqual(try Listener.fixtureSelf(port: port, deadline: ProcessInfo.processInfo.systemUptime + 3), .notObserved)
        XCTAssertThrowsError(try Listener.fixtureSelf(port: port, deadline: ProcessInfo.processInfo.systemUptime - 1))
    }
}
