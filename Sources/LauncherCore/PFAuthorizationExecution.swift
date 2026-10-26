import Foundation
import Darwin

/// Kernel process identity survives exec and is independent of a reusable PID.
/// This selects a local authorization process, never a root request's outcome.
public struct PFAuthorizationExecutionIdentity: Codable, Equatable, Sendable {
    public let executionID: UUID
    let bootUUID: UUID
    let pid: Int32
    let startSeconds, startMicroseconds: UInt64

    init(executionID: UUID, bootUUID: UUID, pid: Int32, startSeconds: UInt64, startMicroseconds: UInt64) {
        self.executionID = executionID; self.bootUUID = bootUUID; self.pid = pid
        self.startSeconds = startSeconds; self.startMicroseconds = startMicroseconds
    }
    private enum CodingKeys: String, CodingKey { case executionID, bootUUID, pid, startSeconds, startMicroseconds }
    public init(from decoder: Decoder) throws {
        try ConnectorSchema.keys(decoder, ["executionID", "bootUUID", "pid", "startSeconds", "startMicroseconds"])
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        executionID = try fields.decode(UUID.self, forKey: .executionID)
        bootUUID = try fields.decode(UUID.self, forKey: .bootUUID)
        pid = try fields.decode(Int32.self, forKey: .pid)
        startSeconds = try fields.decode(UInt64.self, forKey: .startSeconds)
        startMicroseconds = try fields.decode(UInt64.self, forKey: .startMicroseconds)
        guard valid else { throw ConnectorSchema.invalid(decoder) }
    }
    var valid: Bool { pid > 0 && startSeconds > 0 && startSeconds <= UInt64(Int64.max) && startMicroseconds < 1_000_000 }

    public func observe() -> PFAuthorizationExecutionState { PFAuthorizationProcessIdentity.observe(self) }
}

public enum PFAuthorizationExecutionState: Equatable { case sameProcessAlive, originalExited, unknown }

enum PFAuthorizationProcessIdentity {
    enum Sample { case process(pid: Int32, seconds: UInt64, microseconds: UInt64), absent, unknown }
    static let unavailable = LauncherError.message("无法确认原授权进程身份；保持操作占用。")

    static func bootUUID() -> UUID? {
        var bytes = [CChar](repeating: 0, count: 64), size = 64
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0,
              size == 37, bytes[36] == 0 else { return nil }
        let text = String(bytes: bytes.prefix(36).map { UInt8(bitPattern: $0) }, encoding: .utf8)
        return text.flatMap(UUID.init(uuidString:))
    }

    static func sample(_ pid: Int32) -> Sample {
        guard pid > 0 else { return .unknown }
        var info = proc_bsdinfo()
        errno = 0
        let count = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, Int32(MemoryLayout<proc_bsdinfo>.size))
        let error = errno
        if count <= 0 { return error == ESRCH ? .absent : .unknown }
        guard count == MemoryLayout<proc_bsdinfo>.size, info.pbi_pid == UInt32(pid),
              info.pbi_start_tvsec > 0, info.pbi_start_tvsec <= UInt64(Int64.max),
              info.pbi_start_tvusec < 1_000_000 else { return .unknown }
        return .process(pid: pid, seconds: info.pbi_start_tvsec, microseconds: info.pbi_start_tvusec)
    }

    static func capture(pid: Int32, executionID: UUID) throws -> PFAuthorizationExecutionIdentity {
        guard let boot = bootUUID(), case let .process(actual, seconds, microseconds) = sample(pid) else { throw unavailable }
        return .init(executionID: executionID, bootUUID: boot, pid: actual, startSeconds: seconds, startMicroseconds: microseconds)
    }

    static func observe(_ identity: PFAuthorizationExecutionIdentity) -> PFAuthorizationExecutionState {
        evaluate(identity, boot: bootUUID(), sample: { sample(identity.pid) })
    }

    // Explicit error categories are testable without interpreting permission failure as exit.
    static func evaluate(_ identity: PFAuthorizationExecutionIdentity, boot: UUID?, sample: () -> Sample) -> PFAuthorizationExecutionState {
        guard identity.valid, let boot else { return .unknown }
        guard boot == identity.bootUUID else { return .originalExited }
        switch sample() {
        case .absent: return .originalExited
        case .unknown: return .unknown
        case let .process(pid, seconds, microseconds):
            guard pid == identity.pid, seconds > 0, seconds <= UInt64(Int64.max), microseconds < 1_000_000 else { return .unknown }
            return seconds == identity.startSeconds && microseconds == identity.startMicroseconds ? .sameProcessAlive : .originalExited
        }
    }
}
