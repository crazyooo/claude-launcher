import Foundation

/// Identity of one passed PF attempt. This is a selector, never client-supplied proof.
public struct ConnectorPFBinding: Codable, Equatable, Sendable {
    let requestID: String
    let expectedRevision: Int64
    let planID, planSHA256, runtimeSHA256, serviceInstance, generation: String
    let receivedNotBefore: Double

    var valid: Bool {
        PFControlContext.hex(requestID, length: 32) && PFControlContext.hex(planID, length: 32) &&
            PFControlContext.hex(planSHA256, length: 64) && PFControlContext.hex(runtimeSHA256, length: 64) &&
            PFControlContext.hex(serviceInstance, length: 32) && PFControlContext.hex(generation, length: 32) &&
            (0..<PFControlContext.maximumRevision).contains(expectedRevision) && receivedNotBefore.isFinite &&
            (0...253_402_300_799).contains(receivedNotBefore)
    }
}

public struct ConnectorTransactionBinding: Codable, Equatable, Sendable {
    public let id: UUID
    let gatewayInstance: UUID
    let configurationDigest: String
    // Immutable pre-reservation epoch, including on idempotent retries.
    let initialEpoch: UInt64
    let pf: ConnectorPFBinding

    public init?(snapshot: ConnectorSnapshot, pf: ConnectorPFBinding) {
        guard snapshot.transactionProtocol == 2, snapshot.isCurrent(), pf.valid,
              PFControlContext.hex(snapshot.configDigest, length: 64), snapshot.epoch < UInt64.max else { return nil }
        id = UUID(); gatewayInstance = snapshot.instanceID; configurationDigest = snapshot.configDigest
        initialEpoch = snapshot.epoch; self.pf = pf
    }
    var valid: Bool {
        pf.valid && PFControlContext.hex(configurationDigest, length: 64) && initialEpoch < UInt64.max
    }
    public init?(hold: ConnectorHoldBinding, pf: ConnectorPFBinding) {
        guard hold.valid, pf.valid else { return nil }
        id = hold.id; gatewayInstance = hold.gatewayInstance; configurationDigest = hold.configurationDigest
        initialEpoch = hold.initialEpoch; self.pf = pf
    }
}

public struct ConnectorTransactionStatus: Codable, Equatable, Sendable {
    public let id: UUID
    public let phase: String
    public let reason: String
    public var drainPending = false
}

/// The fence persists through cancellation/expiry. Only explicit drain-and-leave releases it.
struct ConnectorFence {
    let binding: ConnectorTransactionBinding
    let effectiveEpoch: UInt64
    private(set) var phase = "reserving"
    private(set) var reason = "transaction_reserving"
    private(set) var deadline: Double
    private(set) var probeID: UUID?
    var fenced: Bool { phase != "released" }
    var terminal: Bool { ["cancelled", "expired", "interrupted", "released"].contains(phase) }
    var status: ConnectorTransactionStatus { .init(id: binding.id, phase: phase, reason: reason) }

    init(binding: ConnectorTransactionBinding, effectiveEpoch: UInt64, now: Double) {
        self.binding = binding; self.effectiveEpoch = effectiveEpoch; deadline = now + 12
    }
    mutating func reserved() { if phase == "reserving" { phase = "reserved"; reason = "transaction_reserved" } }
    mutating func begin(id: UUID, now: Double) -> Bool {
        guard phase == "reserved", now < deadline else { return false }
        phase = "probing"; reason = "transaction_probing"; probeID = id
        // Reservation time is part of the preparation budget, never extended by retries.
        return true
    }
    mutating func revoking(id: UUID, now: Double) -> Bool {
        guard phase == "probing", probeID == id, now < deadline else { return false }
        phase = "revoking"; reason = "transaction_revoking"; return true
    }
    mutating func prepared() { if phase == "revoking" { phase = "prepared"; reason = "transaction_prepared" } }
    mutating func cancelling() { if phase == "cancelled" { phase = "cancelling" } }
    mutating func cancelled() { if phase == "cancelling" { phase = "cancelled" } }
    mutating func commit(now: Double, pfDeadline: Double?, grantDeadline: Double) -> Bool {
        guard phase == "prepared", now < deadline, let pfDeadline, now < pfDeadline, now < grantDeadline else { return false }
        deadline = min(pfDeadline, grantDeadline); phase = "committed"; reason = "transaction_committed"; return true
    }
    mutating func stop(_ code: String, expired: Bool = false) {
        guard fenced else { return }
        // Preserve the first terminal result for same-operation queries/retries.
        if terminal { return }
        phase = expired ? "expired" : code == "transaction_cancelled" ? "cancelled" : "interrupted"
        reason = code
    }
    mutating func leaving() -> Bool {
        guard terminal, fenced else { return false }
        phase = "leaving"; reason = "transaction_leaving"; return true
    }
    mutating func released() { if phase == "leaving" { phase = "released"; reason = "transaction_released" } }
    func expired(at now: Double) -> Bool { !terminal && !["leaving", "cancelling"].contains(phase) && now >= deadline }
    mutating func shorten(to deadline: Double) { self.deadline = min(self.deadline, deadline) }
}

enum ConnectorPFVerifier {
    /// Re-read a root-owned report in production. No endpoint or report from IPC is trusted.
    static func deadline(for binding: ConnectorPFBinding) -> Double? {
        let started = connectorTime(), wall = Date()
        guard binding.valid, let report = PFObservation.load() else { return nil }
        let now = Date(), elapsed = connectorTime() - started
        guard now >= wall, elapsed >= 0, elapsed < 1,
              let expiry = report.connectorExpiry(matching: binding, at: now) else { return nil }
        // Subtract the read interval conservatively rather than extending the wall deadline.
        let deadline = started + expiry - now.timeIntervalSince1970
        return deadline > connectorTime() ? deadline : nil
    }
}
