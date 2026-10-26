import Foundation
import Darwin

/// Read-only evidence about this process's TCP socket. The observer never owns or closes the FD.
enum RouterSystemOutboundSocket {
    typealias Tuple = RouterOwnedTCPProbe.Tuple

    struct Process: Equatable {
        let identity: RouterSystemKernelObservation.ProcessSnapshot
        let path: String
    }
    struct Signature: Equatable {
        let descriptor: Int32
        let generation: UInt64
        let tuple: Tuple
    }
    enum Source { case installedHelper, fixture }
    struct Evidence {
        let source: Source
        let process: Process
        let socket: Signature
        let interval: RouterTrafficInterval
        let collectorAuthenticated = false
        let canPromoteAccepted = false
    }
    enum Unknown: String {
        case unavailable, incomplete, notObserved, ambiguous, changed, timedOut, cancelled
    }
    enum Observation {
        case observed(Evidence)
        case unknown(Unknown)
    }
    struct Readers {
        var clock: () throws -> RouterSystemClock
        var process: () throws -> Process
        var descriptors: () throws -> [proc_fdinfo]
        var socket: (Int32) throws -> (socket_fdinfo, Int32)
    }

    static func installedSelf(tuple: Tuple, until deadline: TimeInterval) -> Observation {
        guard getuid() == 0, geteuid() == 0 else { return .unknown(.unavailable) }
        return collect(tuple, until: deadline, source: .installedHelper, readers: native)
    }

    static func fixtureSelf(tuple: Tuple, until deadline: TimeInterval) -> Observation {
        guard getuid() != 0, geteuid() == getuid() else { return .unknown(.unavailable) }
        return collect(tuple, until: deadline, source: .fixture, readers: native)
    }

    static func fixture(tuple: Tuple, until deadline: TimeInterval, readers: Readers) -> Observation {
        guard getuid() != 0, geteuid() == getuid() else { return .unknown(.unavailable) }
        return collect(tuple, until: deadline, source: .fixture, readers: readers)
    }

    private static func collect(_ tuple: Tuple, until deadline: TimeInterval,
                                source: Source, readers: Readers) -> Observation {
        do {
            guard deadline.isFinite, tuple.local.family == tuple.peer.family,
                  !tuple.local.address.contains("%"), !tuple.peer.address.contains("%") else {
                return .unknown(.incomplete)
            }
            let began = try readers.clock()
            let expires = min(deadline, began.uptime + 5)
            var previous = began
            func checkpoint() throws -> RouterSystemClock {
                let now = try readers.clock()
                try RouterOwnedTCPProbe.requireFresh(start: began, now: now, deadline: expires)
                try RouterOwnedTCPProbe.requireFresh(start: previous, now: now, deadline: expires)
                previous = now
                return now
            }
            _ = try checkpoint()
            let process = try readers.process(), work = process.identity.work
            guard work.pid == getpid(), work.bootID == began.bootID,
                  work.birthSeconds > 0, work.birthMicroseconds < 1_000_000,
                  Double(work.birthSeconds) + Double(work.birthMicroseconds) / 1_000_000 <=
                    began.date.timeIntervalSince1970,
                  process.identity.uid == getuid(), process.identity.realUID == getuid(),
                  RouterValidation.validProcessPath(process.path),
                  source != .installedHelper || process.path == RouterSystemLayout.helper else {
                return .unknown(.incomplete)
            }

            func scan() throws -> [Signature] {
                _ = try checkpoint()
                let entries = try readers.descriptors()
                // The native reader also validates the syscall byte count. Preserve its
                // completeness and uniqueness contract for explicitly injected fixtures.
                guard !entries.isEmpty, entries.count < 8192,
                      entries.allSatisfy({ $0.proc_fd >= 0 }),
                      Set(entries.map(\.proc_fd)).count == entries.count else {
                    throw RouterSystemError.ownershipUnknown
                }
                var matches: [Signature] = []
                for entry in entries where entry.proc_fdtype == UInt32(PROX_FDTYPE_SOCKET) {
                    _ = try checkpoint()
                    let (info, count) = try readers.socket(entry.proc_fd)
                    if let signature = try decode(info, bytes: count, descriptor: entry.proc_fd),
                       signature.tuple == tuple {
                        matches.append(signature)
                    }
                }
                _ = try checkpoint()
                return matches.sorted { $0.descriptor < $1.descriptor }
            }

            let first = try scan()
            guard try readers.process() == process else { return .unknown(.changed) }
            let second = try scan()
            guard try readers.process() == process, first == second else { return .unknown(.changed) }
            let interval = RouterTrafficInterval(start: began, end: try checkpoint())
            try interval.validate(boot: began.bootID, maximumDuration: 5)
            guard let signature = first.first else { return .unknown(.notObserved) }
            guard first.count == 1 else { return .unknown(.ambiguous) }
            return .observed(.init(source: source, process: process, socket: signature, interval: interval))
        } catch RouterOwnedProbeError.cancelled {
            return .unknown(.cancelled)
        } catch RouterOwnedProbeError.timedOut {
            return .unknown(.timedOut)
        } catch {
            return .unknown(.incomplete)
        }
    }

    /// A malformed/short socket row makes the entire scan incomplete, including unrelated rows.
    static func decode(_ info: socket_fdinfo, bytes: Int32, descriptor: Int32) throws -> Signature? {
        guard descriptor >= 0, Int(bytes) == MemoryLayout<socket_fdinfo>.stride else {
            throw RouterSystemError.ownershipUnknown
        }
        let socket = info.psi
        guard socket.soi_type == SOCK_STREAM, socket.soi_protocol == IPPROTO_TCP,
              socket.soi_kind == SOCKINFO_TCP, socket.soi_family == AF_INET || socket.soi_family == AF_INET6 else {
            return nil
        }
        let tcp = socket.soi_proto.pri_tcp, ip = tcp.tcpsi_ini
        guard tcp.tcpsi_state == TSI_S_ESTABLISHED else { return nil }
        guard ip.insi_vflag == UInt8(socket.soi_family == AF_INET ? INI_IPV4 : INI_IPV6),
              ip.insi_gencnt > 0, ip.insi_lport > 0, ip.insi_lport <= UInt16.max,
              ip.insi_fport > 0, ip.insi_fport <= UInt16.max else { throw RouterSystemError.ownershipUnknown }

        func endpoint(local: Bool) throws -> RouterOwnedTCPProbe.Endpoint {
            var storage = sockaddr_storage()
            let size: socklen_t
            let port = UInt16(local ? ip.insi_lport : ip.insi_fport) // Already network byte order.
            if socket.soi_family == AF_INET {
                var address = sockaddr_in()
                address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
                address.sin_family = sa_family_t(AF_INET); address.sin_port = port
                address.sin_addr = local ? ip.insi_laddr.ina_46.i46a_addr4 : ip.insi_faddr.ina_46.i46a_addr4
                size = socklen_t(MemoryLayout<sockaddr_in>.size)
                withUnsafeMutableBytes(of: &storage) { destination in
                    withUnsafeBytes(of: address) { destination.copyBytes(from: $0) }
                }
            } else {
                var address = sockaddr_in6()
                address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
                address.sin6_family = sa_family_t(AF_INET6); address.sin6_port = port
                address.sin6_addr = local ? ip.insi_laddr.ina_6 : ip.insi_faddr.ina_6
                // The kernel's in6_ifindex is not a sockaddr scope. Scoped, mapped and
                // link-local endpoints remain unsupported by the existing address decoder.
                size = socklen_t(MemoryLayout<sockaddr_in6>.size)
                withUnsafeMutableBytes(of: &storage) { destination in
                    withUnsafeBytes(of: address) { destination.copyBytes(from: $0) }
                }
            }
            return try RouterOwnedTCPProbe.decodeAddress(storage, length: size, local: local)
        }
        return try .init(descriptor: descriptor, generation: ip.insi_gencnt,
                         tuple: .init(local: endpoint(local: true), peer: endpoint(local: false)))
    }

    private static var native: Readers {
        .init(clock: RouterSystemKernelObservation.clock, process: {
            let before = try RouterSystemKernelObservation.Reader.live.process(getpid())
            var buffer = [CChar](repeating: 0, count: 4096)
            let count = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
            guard count > 0, Int(count) < buffer.count,
                  let nul = buffer.firstIndex(of: 0), nul == Int(count),
                  let path = String(bytes: buffer.prefix(nul).map { UInt8(bitPattern: $0) }, encoding: .utf8),
                  RouterValidation.validProcessPath(path),
                  try RouterSystemKernelObservation.Reader.live.process(getpid()) == before else {
                throw RouterSystemError.ownershipUnknown
            }
            return .init(identity: before, path: path)
        }, descriptors: {
            var buffer = [proc_fdinfo](repeating: .init(), count: 8192)
            let count = buffer.withUnsafeMutableBytes {
                proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count))
            }
            return try RouterSystemControllerListener.decodeDescriptors(buffer, bytes: count)
        }, socket: { descriptor in
            var info = socket_fdinfo()
            let count = proc_pidfdinfo(getpid(), descriptor, PROC_PIDFDSOCKETINFO,
                                      &info, Int32(MemoryLayout<socket_fdinfo>.stride))
            return (info, count)
        })
    }
}
