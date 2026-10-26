import Foundation

/// An operation identity and the last mutation that may have been sent, never a permission.
public struct RecoveryOperationIntent: Codable, Equatable {
    public enum Checkpoint: String, Codable { case hold, authorization, prepare, commit, cancel, leave, closed }
    public let hold: ConnectorHoldBinding
    public let target: CheckTarget
    public let settingsDigest, environmentDigest, localContext: String
    public let createdAt: Date
    /// Saved with the initial hold so cancellation remains possible after a later disk failure.
    public let cancellation: ConnectorHoldRequest
    public private(set) var request: PFRecoveryRequest?
    public private(set) var executionID: UUID?
    public private(set) var transaction: ConnectorTransactionBinding?
    public private(set) var pending: ConnectorHoldRequest?
    public private(set) var checkpoint: Checkpoint
    public var active: Bool { checkpoint != .closed }

    public init(snapshot: ConnectorSnapshot, target: CheckTarget, settings: PreflightSettings,
                environment: [String: String], localContext: String, now: Date = Date()) throws {
        guard snapshot.controlProtocol == 2, let hold = ConnectorHoldBinding(snapshot: snapshot),
              PFControlContext.hex(localContext, length: 64) else { throw Self.failure }
        try settings.validate()
        self.hold = hold; self.target = target; settingsDigest = settings.fingerprint
        environmentDigest = ClientInspection.environmentFingerprint(environment)
        self.localContext = localContext; createdAt = now
        cancellation = .init(action: .cancel, hold: hold)
        pending = .init(action: .hold, hold: hold); checkpoint = .hold
        guard valid else { throw Self.failure }
    }
    static let failure = LauncherError.message("恢复操作身份或阶段不一致；保留原操作，不自动重试。")
    /// Before persistence, a typed query confirms the candidate still describes an idle Gateway.
    /// hold_unknown here means only that the candidate has not been installed, never a held ACK.
    public func canEstablish(after reply: ConnectorHoldReply, for query: ConnectorHoldRequest, at now: Date = Date()) -> Bool {
        let snapshot = reply.snapshot
        return checkpoint == .hold && query.action == .status && query.hold == hold &&
            reply.version == 2 && reply.commandID == query.commandID && reply.holdID == hold.id &&
            !reply.accepted && reply.reason == "hold_unknown" && !reply.localWorkPending &&
            ["none", "released"].contains(reply.operation) && snapshot.isCurrent(at: now) &&
            snapshot.controlProtocol == 2 && snapshot.transactionProtocol == 2 && snapshot.holdProtocol == 1 &&
            snapshot.instanceID == hold.gatewayInstance && snapshot.configDigest == hold.configurationDigest &&
            snapshot.epoch == hold.initialEpoch &&
            (snapshot.hold == nil || snapshot.hold?.phase == "released" && snapshot.hold?.drainPending == false) &&
            (snapshot.transaction == nil || snapshot.transaction?.phase == "released" && snapshot.transaction?.drainPending == false)
    }
    var valid: Bool {
        guard hold.valid, PFControlContext.hex(settingsDigest, length: 64),
              PFControlContext.hex(environmentDigest, length: 64), PFControlContext.hex(localContext, length: 64),
              createdAt.timeIntervalSince1970.isFinite, (0...253_402_300_799).contains(createdAt.timeIntervalSince1970),
              (request == nil) == (executionID == nil),
              cancellation.valid, cancellation.hold == hold, cancellation.action == .cancel,
              transaction.map({ $0.valid && hold.matches($0) && $0.pf.matchesOriginal(request) }) ?? true else { return false }
        if let pending {
            guard pending.valid, pending.hold == hold,
                  pending.action == .cancel ? pending == cancellation : pending.commandID != cancellation.commandID else { return false }
            if [.prepare, .commit].contains(pending.action), pending.binding != transaction { return false }
        }
        switch checkpoint {
        case .hold: return request == nil && transaction == nil && pending?.action == .hold
        case .authorization: return request != nil && transaction == nil && pending == nil
        case .prepare: return transaction != nil && pending?.action == .prepare
        case .commit: return transaction != nil && pending?.action == .commit
        case .cancel: return pending == cancellation
        case .leave: return pending?.action == .leave
        case .closed: return pending == nil
        }
    }
    func follows(_ old: Self) -> Bool {
        guard valid, hold == old.hold, target == old.target, settingsDigest == old.settingsDigest,
              environmentDigest == old.environmentDigest, localContext == old.localContext,
              createdAt == old.createdAt, cancellation == old.cancellation,
              old.request == nil || request == old.request,
              old.transaction == nil || transaction == old.transaction else { return false }
        if let pending, let previous = old.pending, pending.commandID == previous.commandID, pending != previous { return false }
        if checkpoint == old.checkpoint {
            // Only explicit original-request authorization retry may change an execution identity.
            return self == old || (checkpoint == .authorization && request == old.request && pending == nil)
        }
        let transitions: [Checkpoint: Set<Checkpoint>] = [
            .hold: [.authorization, .cancel, .leave], .authorization: [.prepare, .cancel, .leave],
            .prepare: [.commit, .cancel, .leave], .commit: [.cancel, .leave],
            .cancel: [.leave], .leave: [.closed], .closed: []]
        return transitions[old.checkpoint]?.contains(checkpoint) == true
    }
    public func associating(_ authorization: PFAuthorizationIntent) throws -> Self {
        guard [.hold, .authorization].contains(checkpoint), !authorization.startMayHaveBeenSent,
              request == nil || request == authorization.request else { throw Self.failure }
        var next = self; next.request = authorization.request; next.executionID = authorization.executionID
        next.pending = nil; next.checkpoint = .authorization
        guard next.follows(self) else { throw Self.failure }; return next
    }
    public func preparing(_ binding: ConnectorTransactionBinding) throws -> Self {
        guard checkpoint == .authorization else { throw Self.failure }
        var next = self; next.transaction = binding; next.checkpoint = .prepare
        next.pending = .init(action: .prepare, hold: hold, binding: binding)
        guard next.follows(self) else { throw Self.failure }; return next
    }
    public func committing() throws -> Self {
        guard checkpoint == .prepare, let transaction else { throw Self.failure }
        var next = self; next.checkpoint = .commit
        next.pending = .init(action: .commit, hold: hold, binding: transaction)
        guard next.follows(self) else { throw Self.failure }; return next
    }
    public func cancelling() throws -> Self {
        guard active, ![.leave].contains(checkpoint) else { throw Self.failure }
        var next = self; next.checkpoint = .cancel; next.pending = cancellation
        guard next.follows(self) else { throw Self.failure }; return next
    }
    public func leaving() throws -> Self {
        guard active else { throw Self.failure }
        if checkpoint == .leave { return self }
        var next = self; next.checkpoint = .leave; next.pending = .init(action: .leave, hold: hold)
        guard next.follows(self) else { throw Self.failure }; return next
    }
    public func closing(after reply: ConnectorHoldReply, for query: ConnectorHoldRequest) throws -> Self {
        guard checkpoint == .leave, query.valid, query.hold == hold,
              query.action == .status || query == pending,
              reply.version == 2, reply.commandID == query.commandID, reply.accepted, reply.holdID == hold.id,
              !reply.localWorkPending, reply.operation == "released",
              reply.snapshot.hold?.id == hold.id, reply.snapshot.hold?.phase == "released",
              reply.snapshot.hold?.drainPending == false, !reply.snapshot.trafficEnabled,
              reply.snapshot.version == 1, !reply.snapshot.protectionVerified, !reply.snapshot.launchAuthorized else { throw Self.failure }
        // prepare may have been persisted without ever reaching the Supervisor.
        let observedTransaction = reply.snapshot.transaction
        let transactionReleased = observedTransaction == nil ||
            observedTransaction?.phase == "released" && observedTransaction?.drainPending == false
        let sameGateway = reply.snapshot.instanceID == hold.gatewayInstance && reply.snapshot.configDigest == hold.configurationDigest &&
            reply.snapshot.epoch > hold.initialEpoch && reply.snapshot.state == "blocked" && transactionReleased
        let orphan = reply.reason == "orphan_released_restart_required" && reply.snapshot.state == "stopped"
        guard sameGateway || orphan else { throw Self.failure }
        var next = self; next.checkpoint = .closed; next.pending = nil; return next
    }

    private enum Field: String, CodingKey, CaseIterable {
        case version, hold, target, settingsDigest, environmentDigest, localContext, createdAt, cancellation
        case request, executionID, transaction, pending, checkpoint
    }
    public init(from decoder: Decoder) throws {
        try ConnectorSchema.keys(decoder, Set(Field.allCases.map(\.rawValue)))
        let fields = try decoder.container(keyedBy: Field.self)
        let root = try decoder.container(keyedBy: ConnectorSchema.Key.self)
        try ConnectorSchema.identity(root.superDecoder(forKey: .init("hold")), pf: false)
        guard try fields.decode(Int.self, forKey: .version) == 1 else { throw ConnectorSchema.invalid(decoder) }
        hold = try fields.decode(ConnectorHoldBinding.self, forKey: .hold)
        target = try fields.decode(CheckTarget.self, forKey: .target)
        settingsDigest = try fields.decode(String.self, forKey: .settingsDigest)
        environmentDigest = try fields.decode(String.self, forKey: .environmentDigest)
        localContext = try fields.decode(String.self, forKey: .localContext)
        createdAt = try fields.decode(Date.self, forKey: .createdAt)
        cancellation = try fields.decode(ConnectorHoldRequest.self, forKey: .cancellation)
        request = try fields.decodeIfPresent(PFRecoveryRequest.self, forKey: .request)
        executionID = try fields.decodeIfPresent(UUID.self, forKey: .executionID)
        if try !fields.decodeNil(forKey: .transaction) {
            try ConnectorSchema.identity(root.superDecoder(forKey: .init("transaction")), pf: true)
        }
        transaction = try fields.decodeIfPresent(ConnectorTransactionBinding.self, forKey: .transaction)
        pending = try fields.decodeIfPresent(ConnectorHoldRequest.self, forKey: .pending)
        checkpoint = try fields.decode(Checkpoint.self, forKey: .checkpoint)
        guard valid else { throw ConnectorSchema.invalid(decoder) }
    }
    public func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: Field.self)
        try fields.encode(1, forKey: .version); try fields.encode(hold, forKey: .hold); try fields.encode(target, forKey: .target)
        try fields.encode(settingsDigest, forKey: .settingsDigest); try fields.encode(environmentDigest, forKey: .environmentDigest)
        try fields.encode(localContext, forKey: .localContext); try fields.encode(createdAt, forKey: .createdAt)
        try fields.encode(cancellation, forKey: .cancellation); try fields.encode(request, forKey: .request)
        try fields.encode(executionID, forKey: .executionID); try fields.encode(transaction, forKey: .transaction)
        try fields.encode(pending, forKey: .pending); try fields.encode(checkpoint, forKey: .checkpoint)
    }
}

extension ConnectorPFBinding {
    func matchesOriginal(_ request: PFRecoveryRequest?) -> Bool {
        guard let request else { return false }
        return requestID == request.id && expectedRevision == request.context.receipt_revision &&
            planID == request.context.plan_id && planSHA256 == request.context.plan_sha256 &&
            runtimeSHA256 == request.context.runtime_sha256 && serviceInstance == request.context.service_instance &&
            receivedNotBefore == request.createdAt.timeIntervalSince1970
    }
}
