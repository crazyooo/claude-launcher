import Foundation
import Darwin

/// Positive, time-local evidence only. Missing listener evidence never proves cleanup.
enum RouterSystemControllerListener {
    struct Signature: Equatable {
        let descriptor: Int32
        let generation: UInt64
    }
    enum Observation: Equatable { case observed([Signature]), notObserved }
    private static let capacity = 8192

    static func observe(work: RouterSystemWork, deadline: TimeInterval) throws -> Observation {
        try collect(pid: work.pid, port: RouterSystemCompiler.controllerPort, deadline: deadline,
                    identity: { try RouterSystemKernelObservation.executable(work, expected: [RouterSystemLayout.core]) })
    }

    static func observeUser(_ expected: RouterProcessIdentity, port: UInt16, deadline: TimeInterval) throws -> Observation {
        try collect(pid: expected.pid, port: port, deadline: deadline, identity: {
            guard case .present(let current) = RouterProcessIdentity.observe(expected.pid), current == expected else {
                throw RouterConnectionFailure.identityChanged
            }
            let value = try RouterSystemKernelObservation.Reader.live.process(expected.pid)
            guard value.uid == getuid(), value.realUID == getuid(),
                  value.work.birthSeconds == expected.seconds, value.work.birthMicroseconds == expected.microseconds else {
                throw RouterConnectionFailure.identityChanged
            }
            return value
        })
    }

    /// Test an ephemeral listener owned by this unprivileged test process only.
    static func fixtureSelf(port: UInt16, deadline: TimeInterval) throws -> Observation {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        return try collect(pid: getpid(), port: port, deadline: deadline,
                           identity: { try RouterSystemKernelObservation.Reader.live.process(getpid()) })
    }

    private static func collect(pid: Int32, port: UInt16, deadline: TimeInterval,
                                identity: () throws -> RouterSystemKernelObservation.ProcessSnapshot) throws -> Observation {
        guard pid > 0, port > 0 else { throw RouterSystemError.ownershipUnknown }
        try fresh(deadline)
        let before = try identity()
        guard before.work.pid == pid else { throw RouterSystemError.ownershipUnknown }
        let first = try scan(pid: pid, port: port, deadline: deadline)
        guard try identity() == before else { throw RouterSystemError.ownershipUnknown }
        let second = try scan(pid: pid, port: port, deadline: deadline)
        guard try identity() == before, first == second else { throw RouterSystemError.ownershipUnknown }
        try fresh(deadline)
        return first.isEmpty ? .notObserved : .observed(first)
    }

    private static func scan(pid: Int32, port: UInt16, deadline: TimeInterval) throws -> [Signature] {
        try fresh(deadline)
        var descriptors = [proc_fdinfo](repeating: .init(), count: capacity)
        let count = descriptors.withUnsafeMutableBytes {
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
        }
        let entries = try decodeDescriptors(descriptors, bytes: count)
        var matches: [Signature] = []
        for entry in entries where entry.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
            try fresh(deadline)
            var info = socket_fdinfo()
            let size = proc_pidfdinfo(pid, entry.proc_fd, PROC_PIDFDSOCKETINFO,
                                     &info, Int32(MemoryLayout<socket_fdinfo>.stride))
            // Even a disappearing unrelated socket makes this round incomplete.
            if let match = try decodeSocket(info, bytes: size, descriptor: entry.proc_fd, port: port) {
                matches.append(match)
            }
        }
        try fresh(deadline)
        return matches.sorted { $0.descriptor < $1.descriptor }
    }

    static func decodeDescriptors(_ buffer: [proc_fdinfo], bytes: Int32) throws -> [proc_fdinfo] {
        let stride = MemoryLayout<proc_fdinfo>.stride
        // A full buffer might be truncated. Standard descriptors make zero ambiguous too.
        guard !buffer.isEmpty, buffer.count <= capacity, bytes > 0,
              Int(bytes) < buffer.count * stride, Int(bytes) % stride == 0 else {
            throw RouterSystemError.ownershipUnknown
        }
        let entries = Array(buffer.prefix(Int(bytes) / stride))
        guard entries.allSatisfy({ $0.proc_fd >= 0 }), Set(entries.map(\.proc_fd)).count == entries.count else {
            throw RouterSystemError.ownershipUnknown
        }
        return entries
    }

    static func decodeSocket(_ info: socket_fdinfo, bytes: Int32, descriptor: Int32, port: UInt16) throws -> Signature? {
        guard descriptor >= 0, port > 0, Int(bytes) == MemoryLayout<socket_fdinfo>.stride else {
            throw RouterSystemError.ownershipUnknown
        }
        let socket = info.psi
        guard socket.soi_family == AF_INET, socket.soi_type == SOCK_STREAM,
              socket.soi_protocol == IPPROTO_TCP, socket.soi_kind == SOCKINFO_TCP else { return nil }
        let tcp = socket.soi_proto.pri_tcp, ip = tcp.tcpsi_ini
        guard tcp.tcpsi_state == TSI_S_LISTEN, ip.insi_vflag == UInt8(INI_IPV4) else { return nil }
        guard ip.insi_lport >= 0, ip.insi_lport <= UInt16.max else { throw RouterSystemError.ownershipUnknown }
        guard UInt16(bigEndian: UInt16(ip.insi_lport)) == port,
              ip.insi_laddr.ina_46.i46a_addr4.s_addr == inet_addr("127.0.0.1") else { return nil }
        guard ip.insi_gencnt > 0 else { throw RouterSystemError.ownershipUnknown }
        return .init(descriptor: descriptor, generation: ip.insi_gencnt)
    }

    private static func fresh(_ deadline: TimeInterval) throws {
        guard deadline.isFinite, ProcessInfo.processInfo.systemUptime < deadline else {
            throw RouterSystemError.operationUnsettled
        }
    }
}
