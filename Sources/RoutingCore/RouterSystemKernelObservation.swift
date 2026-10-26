import Foundation
import Darwin

/// Read-only kernel observations. No historical PID becomes a signal/wait owner here.
enum RouterSystemKernelObservation {
    enum ExitObservation: Equatable { case sameProcess, exited, unknown }
    enum FormerDispatch: Equatable { case formerBootEnded, formerHostGroupEmpty, unsettled, unknown }
    struct ProcessSnapshot: Equatable {
        let work: RouterSystemWork
        let uid: UInt32
        let realUID: UInt32
        let parentPID: Int32
        let processGroup: Int32
    }
    enum ProcessSample { case present(ProcessSnapshot), absent, unknown }
    struct Reader {
        var boot: () throws -> UUID
        var sample: (Int32, UUID) -> ProcessSample
        var group: (Int32) throws -> [Int32]
        static var live: Self { .init(boot: bootID, sample: rawProcess, group: groupMembers) }

        func process(_ pid: Int32) throws -> ProcessSnapshot {
            let currentBoot = try boot()
            guard case .present(let first) = sample(pid, currentBoot),
                  case .present(let second) = sample(pid, currentBoot), first == second,
                  try boot() == currentBoot else { throw RouterSystemError.ownershipUnknown }
            return second
        }
        func exit(_ old: RouterSystemWork) -> ExitObservation {
            guard old.pid > 0, old.birthSeconds > 0, old.birthMicroseconds < 1_000_000,
                  let currentBoot = try? boot() else { return .unknown }
            if currentBoot != old.bootID { return (try? boot()) == currentBoot ? .exited : .unknown }
            func verdict(_ value: ProcessSample) -> ExitObservation {
                switch value {
                case .absent: return .exited
                case .unknown: return .unknown
                case .present(let value): return value.work == old ? .sameProcess : .exited
                }
            }
            let first = verdict(sample(old.pid, currentBoot)), second = verdict(sample(old.pid, currentBoot))
            guard first == second, (try? boot()) == currentBoot else { return .unknown }
            return first
        }
        /// Observes only the former host and its original group. This does not prove
        /// that an arbitrary descendant which escaped that group has exited.
        func formerDispatch(_ fence: RouterSystemDispatchFence) -> FormerDispatch {
            guard fence.processGroup == fence.host.pid else { return .unknown }
            return formerHostGroup(fence.host)
        }
        /// A boot transition settles the former group without consulting a reused numeric PGID.
        func formerHostGroup(_ work: RouterSystemWork) -> FormerDispatch {
            guard work.pid > 0, work.birthSeconds > 0, work.birthMicroseconds < 1_000_000,
                  let currentBoot = try? boot() else { return .unknown }
            if currentBoot != work.bootID {
                return (try? boot()) == currentBoot ? .formerBootEnded : .unknown
            }
            // A reused PGID with unrelated live members remains unsettled, never a target for signals.
            for _ in 0..<2 {
                switch exit(work) {
                case .sameProcess: return .unsettled
                case .unknown: return .unknown
                case .exited: break
                }
                guard let members = try? group(work.pid) else { return .unknown }
                if !members.isEmpty { return .unsettled }
                guard (try? boot()) == currentBoot else { return .unknown }
            }
            return .formerHostGroupEmpty
        }
    }

    static func bootID() throws -> UUID {
        var buffer = [CChar](repeating: 0, count: 64), size = 64
        guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0, size == 37, buffer[36] == 0,
              let string = String(bytes: buffer.prefix(36).map { UInt8(bitPattern: $0) }, encoding: .utf8),
              let uuid = UUID(uuidString: string) else { throw RouterSystemError.ownershipUnknown }
        return uuid
    }
    static func clock() throws -> RouterSystemClock {
        let before = try bootID(), uptime = ProcessInfo.processInfo.systemUptime, date = Date()
        guard try bootID() == before, uptime.isFinite, uptime >= 0, date.timeIntervalSince1970.isFinite else {
            throw RouterSystemError.ownershipUnknown
        }
        return .init(bootID: before, uptime: uptime, date: date)
    }
    private static func rawProcess(_ pid: Int32, boot: UUID) -> ProcessSample {
        guard pid > 0 else { return .unknown }
        var info = proc_bsdinfo()
        errno = 0
        let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.stride))
        return decodeProcess(pid: pid, boot: boot, info: info, count: count, error: errno)
    }
    static func decodeProcess(pid: Int32, boot: UUID, info: proc_bsdinfo, count: Int32, error: Int32) -> ProcessSample {
        guard pid > 0 else { return .unknown }
        if count <= 0 { return error == ESRCH ? .absent : .unknown }
        guard Int(count) == MemoryLayout<proc_bsdinfo>.stride, info.pbi_pid == UInt32(pid),
              info.pbi_pgid <= UInt32(Int32.max), info.pbi_ppid <= UInt32(Int32.max),
              info.pbi_start_tvsec > 0, info.pbi_start_tvusec < 1_000_000 else { return .unknown }
        return .present(.init(work: .init(bootID: boot, pid: pid, birthSeconds: info.pbi_start_tvsec,
            birthMicroseconds: info.pbi_start_tvusec), uid: info.pbi_uid, realUID: info.pbi_ruid,
            parentPID: Int32(info.pbi_ppid), processGroup: Int32(info.pbi_pgid)))
    }
    static func groupMembers(_ group: Int32) throws -> [Int32] {
        guard group > 0 else { throw RouterSystemError.ownershipUnknown }
        var members = [pid_t](repeating: 0, count: 8192)
        errno = 0
        let count = members.withUnsafeMutableBytes {
            proc_listpids(UInt32(PROC_PGRP_ONLY), UInt32(group), $0.baseAddress, Int32($0.count))
        }
        return try decodeGroup(members, count: count, error: errno)
    }
    static func decodeGroup(_ buffer: [Int32], count: Int32, error: Int32) throws -> [Int32] {
        let stride = MemoryLayout<pid_t>.stride
        guard count >= 0, Int(count) < buffer.count * stride, Int(count) % stride == 0,
              count != 0 || error == 0 else { throw RouterSystemError.ownershipUnknown }
        let members = Array(buffer.prefix(Int(count) / stride))
        guard members.allSatisfy({ $0 > 0 }), Set(members).count == members.count else { throw RouterSystemError.ownershipUnknown }
        return members
    }
    static func executable(_ work: RouterSystemWork, expected: Set<String>) throws -> ProcessSnapshot {
        try image(work, expected: expected).process
    }
    private static func image(_ work: RouterSystemWork, expected: Set<String>) throws -> (process: ProcessSnapshot, path: String) {
        let before = try Reader.live.process(work.pid)
        guard before.work == work, before.uid == 0, before.realUID == 0 else { throw RouterSystemError.ownershipUnknown }
        var buffer = [CChar](repeating: 0, count: 4096)
        let length = proc_pidpath(work.pid, &buffer, UInt32(buffer.count))
        guard length > 0, length < buffer.count, buffer.contains(0), expected.contains(String(cString: buffer)) else {
            throw RouterSystemError.ownershipUnknown
        }
        let after = try Reader.live.process(work.pid)
        guard before == after else { throw RouterSystemError.ownershipUnknown }
        return (after, String(cString: buffer))
    }
    /// Observes exec only. The fixed core path does not establish controller health or routing success.
    static func coreExecObserved(_ work: RouterSystemWork, fence: RouterSystemDispatchFence) throws -> Bool {
        let parent = try host()
        guard parent.work == fence.host, parent.processGroup == fence.processGroup else { throw RouterSystemError.ownershipUnknown }
        let current = try image(work, expected: [RouterSystemLayout.helper, RouterSystemLayout.core])
        guard work.bootID == fence.host.bootID, work.pid != fence.host.pid,
              current.process.parentPID == fence.host.pid, current.process.processGroup == fence.processGroup else {
            throw RouterSystemError.ownershipUnknown
        }
        return current.path == RouterSystemLayout.core
    }
    static func host() throws -> ProcessSnapshot {
        let sample = try Reader.live.process(getpid())
        let verified = try executable(sample.work, expected: [RouterSystemLayout.helper])
        guard verified.processGroup == verified.work.pid, getpgrp() == verified.work.pid else {
            throw RouterSystemError.ownershipUnknown
        }
        return verified
    }
    static func child(_ pid: Int32, fence: RouterSystemDispatchFence) throws -> RouterSystemWork {
        let current = try host()
        guard current.work == fence.host, current.processGroup == fence.processGroup else { throw RouterSystemError.ownershipUnknown }
        let sample = try Reader.live.process(pid)
        let verified = try executable(sample.work, expected: [RouterSystemLayout.helper])
        guard verified.parentPID == fence.host.pid, verified.processGroup == fence.processGroup,
              verified.work.bootID == fence.host.bootID else { throw RouterSystemError.ownershipUnknown }
        return verified.work
    }
}
