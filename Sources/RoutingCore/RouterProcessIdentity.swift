import Foundation
import Darwin

struct RouterProcessIdentity: Codable, Equatable {
    let pid: Int32
    let seconds: UInt64
    let microseconds: UInt64
    let executable: String
    static func observe(_ pid: Int32) -> RouterProcessObservation {
        guard pid > 0 else { return .unknown }
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else {
            return kill(pid, 0) == -1 && errno == ESRCH ? .absent : .unknown
        }
        var bytes = [CChar](repeating: 0, count: 4096)
        guard info.pbi_uid == getuid(), info.pbi_start_tvsec > 0,
              proc_pidpath(pid, &bytes, UInt32(bytes.count)) > 0 else { return .unknown }
        return .present(.init(pid: pid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec,
                              executable: String(cString: bytes)))
    }
}
enum RouterProcessObservation {
    case absent, unknown, present(RouterProcessIdentity)
    func provesExit(of old: RouterProcessIdentity) -> Bool {
        switch self {
        case .absent: return true
        case .unknown: return false
        case .present(let value): return value.pid == old.pid && (value.seconds != old.seconds || value.microseconds != old.microseconds)
        }
    }
}
