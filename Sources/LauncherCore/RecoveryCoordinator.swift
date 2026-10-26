import Foundation

/// App-local continuation policy. Persistence and I/O remain explicit effects of the App owner.
/// Restoring an operation restores selectors only; it never reconstructs automatic continuation.
public struct RecoveryCoordinator {
    public enum Mode: String { case observationOnly, live, continuingPrepared, invalidated }
    public private(set) var intent: RecoveryOperationIntent?
    public private(set) var mode: Mode = .observationOnly
    public private(set) var generation = 0
    public private(set) var observation: ConnectorHoldReply?
    private var permit: RecoveryMutationPermit?
    private var issuedCommands = Set<UUID>()
    public init() {}
    public var active: Bool { intent?.active == true }

    private mutating func revoke() {
        permit?.cancel(); permit = nil
        if generation < Int.max { generation += 1 }
    }
    public mutating func restore(_ saved: RecoveryOperationIntent) {
        revoke(); intent = saved; mode = .observationOnly; observation = nil; issuedCommands = []
    }
    public mutating func begin(_ saved: RecoveryOperationIntent) throws {
        guard !active, generation < Int.max, saved.valid, saved.checkpoint == .hold else { throw RecoveryOperationIntent.failure }
        revoke(); intent = saved; mode = .live; observation = nil; issuedCommands = []
    }
    /// Preserve the durable identity even if invalidation won the race with an fsync.
    public mutating func recordSaved(_ next: RecoveryOperationIntent) throws {
        guard let previous = intent, next.follows(previous) else { throw RecoveryOperationIntent.failure }
        intent = next
        if !next.active { revoke(); mode = .observationOnly }
        else if [.cancel, .leave].contains(next.checkpoint) { revoke(); mode = .invalidated }
    }
    public mutating func becameUnknown() { revoke(); mode = .observationOnly; observation = nil }
    public mutating func invalidate() { revoke(); mode = .invalidated; observation = nil }

    public mutating func observe(_ reply: ConnectorHoldReply, for query: ConnectorHoldRequest, ticket: Int) {
        guard ticket == generation, let intent, query.valid, query.hold == intent.hold,
              query.action == .status || query == intent.pending || query == intent.cancellation,
              reply.version == 2, reply.commandID == query.commandID, reply.holdID == intent.hold.id else { return }
        // Keep correlated stale/stopped replies for explicit cleanup, but never grant from them.
        if let previous = observation,
           previous.snapshot.instanceID == reply.snapshot.instanceID,
           (reply.snapshot.epoch < previous.snapshot.epoch || reply.snapshot.sampledAt < previous.snapshot.sampledAt) { return }
        observation = reply
    }
    private func current(_ now: Date) -> ConnectorHoldReply? {
        guard let intent, let reply = observation, reply.accepted, !reply.localWorkPending,
              reply.snapshot.isCurrent(at: now), reply.snapshot.controlProtocol == 2,
              reply.snapshot.transactionProtocol == 2, reply.snapshot.holdProtocol == 1,
              reply.snapshot.instanceID == intent.hold.gatewayInstance,
              reply.snapshot.configDigest == intent.hold.configurationDigest,
              reply.snapshot.epoch == intent.hold.initialEpoch + 1,
              reply.snapshot.hold?.id == intent.hold.id, reply.snapshot.hold?.drainPending == false else { return nil }
        return reply
    }
    private func held(_ now: Date) -> Bool {
        guard let reply = current(now) else { return false }
        let old = reply.snapshot.transaction
        let noAttachment = old == nil || old?.id != intent?.hold.id && old?.phase == "released" && old?.drainPending == false
        return reply.snapshot.state == "blocked" && reply.snapshot.hold?.phase == "held" &&
            reply.operation == "held" && noAttachment
    }
    private func prepared(_ now: Date) -> Bool {
        guard let intent, intent.transaction != nil, let reply = current(now) else { return false }
        return reply.snapshot.state == "blocked" && reply.snapshot.hold?.phase == "attached" &&
            reply.operation == "prepared" && reply.snapshot.transaction?.id == intent.transaction?.id &&
            reply.snapshot.transaction?.phase == "prepared" && reply.snapshot.transaction?.drainPending == false
    }
    public func matches(settings: PreflightSettings, connector: ConnectorConfiguration, target: CheckTarget,
                        environment: [String: String], context: String) -> Bool {
        guard let intent else { return false }
        return intent.target == target && intent.settingsDigest == settings.fingerprint &&
            intent.hold.configurationDigest == connector.digest && intent.localContext == context &&
            intent.environmentDigest == ClientInspection.environmentFingerprint(environment)
    }
    public func canAuthorize(at now: Date = Date()) -> Bool {
        mode == .live && intent?.checkpoint == .hold && held(now)
    }
    public func canSubmitAuthorization(at now: Date = Date()) -> Bool {
        mode == .live && intent?.checkpoint == .authorization && held(now)
    }
    public func preparedObserved(at now: Date = Date()) -> Bool { prepared(now) }
    public func preparationBinding(pf: PFRecoveryCoordinator, report: PFObservation?, at now: Date = Date()) -> ConnectorTransactionBinding? {
        guard mode == .live, let intent, intent.checkpoint == .authorization,
              pf.request == intent.request, pf.authorizationID == nil, held(now),
              let binding = pf.connectorBinding(report: report, at: now), binding.matchesOriginal(intent.request) else { return nil }
        return ConnectorTransactionBinding(hold: intent.hold, pf: binding)
    }
    public func canSendPreparation(pf: PFRecoveryCoordinator, report: PFObservation?, at now: Date = Date()) -> Bool {
        guard mode == .live, let intent, intent.checkpoint == .prepare, let transaction = intent.transaction,
              pf.request == intent.request, pf.authorizationID == nil, held(now),
              let binding = pf.connectorBinding(report: report, at: now) else { return false }
        return transaction.pf == binding
    }
    public var canExplicitlyContinue: Bool {
        mode == .observationOnly && intent.map { [.prepare, .commit].contains($0.checkpoint) } == true && prepared(Date())
    }
    /// This method represents an explicit click, never startup or polling.
    public mutating func continuePrepared(at now: Date = Date()) throws {
        guard mode == .observationOnly, let intent, [.prepare, .commit].contains(intent.checkpoint),
              prepared(now), generation < Int.max else {
            throw RecoveryOperationIntent.failure
        }
        revoke()
        // An explicit continuation may retry only the original commit, never hold or prepare.
        if intent.checkpoint == .commit, let command = intent.pending { issuedCommands.remove(command.commandID) }
        mode = .continuingPrepared
    }
    public func canCommit(local: RecoveryLocalTargetReport, context: String, settings: PreflightSettings,
                          connector: ConnectorConfiguration, target: CheckTarget, environment: [String: String],
                          pf: PFObservation?, authorization: PFRecoveryCoordinator, at now: Date = Date()) -> Bool {
        canCommit(local: local, context: context, settings: settings, connector: connector, target: target,
                  environment: environment, pf: pf, authorization: authorization, now: now, tick: connectorTime())
    }
    func canCommit(local: RecoveryLocalTargetReport, context: String, settings: PreflightSettings,
                   connector: ConnectorConfiguration, target: CheckTarget, environment: [String: String],
                   pf: PFObservation?, authorization: PFRecoveryCoordinator, now: Date, tick: Double) -> Bool {
        guard [.live, .continuingPrepared].contains(mode), let intent,
              [.prepare, .commit].contains(intent.checkpoint), let transaction = intent.transaction,
              !authorization.authorizationInFlight, authorization.request == intent.request,
              matches(settings: settings, connector: connector, target: target, environment: environment, context: context),
              local.satisfiesLocalRequirements(target: target, context: context, now: now, tick: tick),
              pf?.connectorExpiry(matching: transaction.pf, at: now) != nil else { return false }
        return prepared(now)
    }
    public func forwardingObserved(pf: PFObservation?, at now: Date = Date()) -> Bool {
        guard let intent, intent.checkpoint == .commit, let transaction = intent.transaction,
              let reply = current(now), reply.operation == "committed", reply.snapshot.state == "allowed",
              reply.snapshot.hold?.phase == "attached", reply.snapshot.transaction?.id == transaction.id,
              reply.snapshot.transaction?.phase == "committed", reply.snapshot.transaction?.drainPending == false,
              pf?.connectorExpiry(matching: transaction.pf, at: now) != nil else { return false }
        return true // Connector-only observation, never StrictProtection or client launch permission.
    }
    /// Permission to request cleanup, not evidence that cleanup or process exit is complete.
    public var canRequestLeave: Bool {
        guard let intent, intent.active, let reply = observation, reply.accepted, !reply.localWorkPending,
              reply.version == 2, reply.holdID == intent.hold.id, reply.snapshot.version == 1,
              !reply.snapshot.protectionVerified, !reply.snapshot.launchAuthorized else { return false }
        let snapshot = reply.snapshot
        if snapshot.state == "stopped", snapshot.reason == "orphan_hold", snapshot.hold?.id == intent.hold.id {
            return true // Supervisor must still acquire the original Gateway lifetime lock.
        }
        guard snapshot.instanceID == intent.hold.gatewayInstance,
              snapshot.configDigest == intent.hold.configurationDigest else { return false }
        if snapshot.state == "stopped", snapshot.reason == "gateway_exited" { return true }
        if ["unknown", "interrupted"].contains(reply.operation), snapshot.hold?.id != intent.hold.id {
            return true // Supervisor stops its owned child before attempting exit proof.
        }
        guard snapshot.epoch > intent.hold.initialEpoch, snapshot.state == "blocked",
              snapshot.hold?.id == intent.hold.id, snapshot.hold?.drainPending == false,
              ["cancelled", "interrupted", "released"].contains(snapshot.hold?.phase ?? "") else { return false }
        guard let transaction = snapshot.transaction else { return true }
        guard !transaction.drainPending else { return false }
        return transaction.id == intent.transaction?.id ?
            ["cancelled", "expired", "interrupted", "released"].contains(transaction.phase) : transaction.phase == "released"
    }
    /// The caller has durably saved this exact pending command and rechecked its phase prerequisites.
    public mutating func mutationPermit(for command: ConnectorHoldRequest) throws -> RecoveryMutationPermit {
        guard let intent, command == intent.pending,
              [.hold, .prepare].contains(command.action), mode == .live,
              !issuedCommands.contains(command.commandID), permit == nil else {
            throw RecoveryOperationIntent.failure
        }
        let next = try RecoveryMutationPermit(command: command, generation: generation)
        issuedCommands.insert(command.commandID); permit = next; return next
    }
    public mutating func commitPermit(local: RecoveryLocalTargetReport, context: String, settings: PreflightSettings,
                                      connector: ConnectorConfiguration, target: CheckTarget, environment: [String: String],
                                      pf: PFObservation?, authorization: PFRecoveryCoordinator) throws -> RecoveryMutationPermit {
        let tick = connectorTime(), now = Date()
        return try commitPermit(local: local, context: context, settings: settings, connector: connector, target: target,
                                environment: environment, pf: pf, authorization: authorization, now: now, tick: tick)
    }
    /// Convert wall-clock evidence to fixed monotonic deadlines before any IPC wait.
    mutating func commitPermit(local: RecoveryLocalTargetReport, context: String, settings: PreflightSettings,
                               connector: ConnectorConfiguration, target: CheckTarget, environment: [String: String],
                               pf: PFObservation?, authorization: PFRecoveryCoordinator,
                               now: Date, tick: Double) throws -> RecoveryMutationPermit {
        guard tick.isFinite, tick >= 0, let intent, intent.checkpoint == .commit,
              let command = intent.pending, command.action == .commit, let transaction = intent.transaction,
              let pf, let reply = current(now), permit == nil, !issuedCommands.contains(command.commandID),
              canCommit(local: local, context: context, settings: settings, connector: connector, target: target,
                        environment: environment, pf: pf, authorization: authorization, now: now, tick: tick),
              let pfExpiry = pf.connectorExpiry(matching: transaction.pf, at: now) else { throw RecoveryOperationIntent.failure }
        let wall = now.timeIntervalSince1970, snapshot = reply.snapshot
        let sampled = snapshot.sampledAt.timeIntervalSince1970
        let deadlines = [tick + 5, local.startedTick + 30,
                         tick + local.startedAt.addingTimeInterval(30).timeIntervalSince(now),
                         tick + (pfExpiry - wall), tick + (pf.checked_at + 10 - wall),
                         tick + (sampled + 4 - wall), tick + (sampled + 3 - snapshot.heartbeatAge - wall)]
        guard deadlines.allSatisfy(\.isFinite), let deadline = deadlines.min(), deadline > tick else {
            throw RecoveryOperationIntent.failure
        }
        let next = try RecoveryMutationPermit(commit: command, generation: generation, validUntil: deadline)
        issuedCommands.insert(command.commandID); permit = next
        return next
    }
    public mutating func mutationReturned(ticket: Int) {
        guard ticket == generation else { return }; permit?.cancel(); permit = nil
    }
    public var diagnostic: [String: String] {
        ["mode": mode.rawValue, "checkpoint": intent?.checkpoint.rawValue ?? "none",
         "target": intent?.target.rawValue ?? "unknown", "launch_authorized": "false",
         "protection_verified": "false"]
    }
}
