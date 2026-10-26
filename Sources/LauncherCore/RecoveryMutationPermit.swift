import Foundation
import Darwin

/// Orders App invalidation against one nonblocking frame write. It never waits while holding its lock.
public final class RecoveryMutationPermit: @unchecked Sendable {
    public let command: ConnectorHoldRequest
    public let generation: Int
    private let lock = NSLock()
    private var available = true
    let validUntil: Double
    public init(command: ConnectorHoldRequest, generation: Int) throws {
        guard command.valid, ![.status, .commit].contains(command.action), generation >= 0 else { throw Self.failure }
        self.command = command; self.generation = generation
        validUntil = connectorTime() + 5
    }
    /// Commit construction is internal: the coordinator captures all evidence deadlines first.
    init(commit command: ConnectorHoldRequest, generation: Int, validUntil: Double) throws {
        guard command.valid, command.action == .commit, generation >= 0,
              validUntil.isFinite, validUntil >= 0 else { throw Self.failure }
        self.command = command; self.generation = generation; self.validUntil = validUntil
    }
    static let failure = LauncherError.message("本次恢复命令已取消、超时或发送结果未知；请查询原操作。")
    public func cancel() { lock.lock(); available = false; lock.unlock() }
    func write(_ fd: Int32, data: Data, deadline: Double, clock: () -> Double = connectorTime,
               transmit: (Int32, Data) -> Int = { fd, data in
                   data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress!, $0.count, 0) }
               }) throws {
        lock.lock(); defer { lock.unlock() }
        guard available else { throw Self.failure }
        available = false
        let now = clock()
        guard now.isFinite, deadline.isFinite, now < min(deadline, validUntil), !data.isEmpty, data.count <= 8193,
              transmit(fd, data) == data.count else { throw Self.failure }
    }
}
