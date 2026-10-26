import Foundation
import Darwin

protocol RouterSystemDispatchChild: AnyObject {
    var instance: UUID { get }
    var pid: pid_t { get }
    func observe() -> RouterOwnedChild.Observation
    func closeGate()
    func releaseGate() throws
    func signal(_ number: Int32) throws
    func waitUntil(_ deadline: TimeInterval) -> RouterOwnedChild.Observation
}
extension RouterOwnedChild: RouterSystemDispatchChild {}

/// Retained for the host's entire lifetime. Historical journal PIDs never become child owners.
final class RouterSystemDispatch {
    enum Settlement: Equatable { case neverDispatched, neverSpawned, running, exited, unknown }
    struct Operations {
        var clock: () throws -> RouterSystemClock
        var currentHost: () throws -> RouterSystemWork
        var verifyCode: () throws -> Void
        var verifyStage: (RouterSystemIntent, String) throws -> Void
        var capture: () throws -> RouterSystemBaselineSnapshot
        /// Must either return the owner immediately after spawn, or throw before any child exists.
        var spawn: (UUID) throws -> RouterSystemDispatchChild
        var identify: (Int32, RouterSystemDispatchFence) throws -> RouterSystemWork
        /// false must mean the exact child is still the fixed helper; uncertainty throws.
        var coreExecObserved: (RouterSystemWork, RouterSystemDispatchFence) throws -> Bool
        var loadForExecution: (TimeInterval) throws -> RouterSystemJournal
        var waitForExecPoll: () -> Void = { Thread.sleep(forTimeInterval: 0.01) }
    }
    private final class Slot {
        let fence: RouterSystemDispatchFence
        var claimed = false
        var noChild = false
        var child: RouterSystemDispatchChild?
        var work: RouterSystemWork?
        init(_ fence: RouterSystemDispatchFence) { self.fence = fence }
    }
    private let identity: RouterSystemInstallationIdentity
    private let host: RouterSystemWork
    private let journal: RouterSystemJournalStore
    private let baselines: RouterSystemBaselineStore
    private let operations: Operations
    private let lock = NSLock()
    private var slot: Slot?

    convenience init(installation: RouterSystemInstallation, journal: RouterSystemJournalStore,
                     baselines: RouterSystemBaselineStore, stage: RouterSystemStage,
                     capture: @escaping () throws -> RouterSystemBaselineSnapshot) throws {
        try installation.verifyCode()
        let host = try RouterSystemKernelObservation.host().work
        self.init(identity: installation.manifest.identity, host: host, journal: journal, baselines: baselines,
                  operations: .init(clock: RouterSystemKernelObservation.clock,
                    currentHost: { try RouterSystemKernelObservation.host().work }, verifyCode: installation.verifyCode,
                    verifyStage: stage.verify, capture: capture,
                    spawn: { try RouterOwnedChild.spawn(instance: $0, executable: RouterSystemLayout.helper,
                        arguments: ["--core-child", $0.uuidString.lowercased()]) }, identify: RouterSystemKernelObservation.child,
                    coreExecObserved: { try RouterSystemKernelObservation.coreExecObserved($0, fence: $1) },
                    loadForExecution: { try journal.load(until: $0) }))
    }
    private init(identity: RouterSystemInstallationIdentity, host: RouterSystemWork, journal: RouterSystemJournalStore,
                 baselines: RouterSystemBaselineStore, operations: Operations) {
        self.identity = identity; self.host = host; self.journal = journal; self.baselines = baselines; self.operations = operations
    }
    static func fixture(identity: RouterSystemInstallationIdentity, host: RouterSystemWork, journal: RouterSystemJournalStore,
                        baselines: RouterSystemBaselineStore, operations: Operations) throws -> RouterSystemDispatch {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        return .init(identity: identity, host: host, journal: journal, baselines: baselines, operations: operations)
    }

    func prepare(_ intent: RouterSystemIntent, digest: String) throws -> RouterSystemDispatchFence {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        guard slot?.claimed != true else { throw RouterSystemError.operationUnsettled }
        let state = try prepared(intent)
        try baselines.requireUnclaimed(intent.id)
        try fresh(intent); try operations.verifyCode(); try operations.verifyStage(intent, digest)
        let snapshot = try operations.capture()
        guard snapshot.networkFingerprint == intent.networkFingerprint else { throw RouterSystemError.networkConflict }
        try fresh(intent)
        let fence = try baselines.create(intent: intent, configurationDigest: digest, host: host, snapshot: snapshot)
        guard try prepared(intent).revision == state.revision else { throw RouterSystemError.conflict }
        try fresh(intent)
        slot = Slot(fence) // Only unclaimed reservations may be replaced; evidence files remain.
        return fence
    }

    func start(_ intent: RouterSystemIntent, digest: String, fence: RouterSystemDispatchFence,
               recordWork: (RouterSystemWork) throws -> Void) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        guard let slot, !slot.claimed, slot.fence == fence, fence.host == host else { throw RouterSystemError.operationUnsettled }
        let revision = try applying(intent, digest: digest, fence: fence, work: nil).revision
        try operations.verifyCode(); try operations.verifyStage(intent, digest)
        let baseline = try baselines.read(intent: intent, fence: fence)
        guard try baseline.snapshot.sameStartEnvironment(as: operations.capture()) else { throw RouterSystemError.networkConflict }
        try fresh(intent)
        slot.claimed = true
        do {
            try baselines.claim(intent: intent, fence: fence) {
                guard try self.applying(intent, digest: digest, fence: fence, work: nil).revision == revision else {
                    throw RouterSystemError.conflict
                }
            }
            guard try applying(intent, digest: digest, fence: fence, work: nil).revision == revision else { throw RouterSystemError.conflict }
            try fresh(intent)
            let child = try operations.spawn(intent.id)
            slot.child = child // No throwing work between spawn and retaining the only signal/wait owner.
            guard child.instance == intent.id, child.pid > 0 else { throw RouterSystemError.ownershipUnknown }
            let work = try operations.identify(child.pid, fence)
            guard work.pid == child.pid, work.bootID == host.bootID, work.pid != host.pid,
                  work.birthSeconds > 0, work.birthMicroseconds < 1_000_000 else { throw RouterSystemError.ownershipUnknown }
            slot.work = work
            try recordWork(work)
            let saved = try applying(intent, digest: digest, fence: fence, work: work).revision
            try operations.verifyCode(); try operations.verifyStage(intent, digest)
            guard try baseline.snapshot.sameStartEnvironment(as: operations.capture()) else { throw RouterSystemError.networkConflict }
            guard try applying(intent, digest: digest, fence: fence, work: work).revision == saved else { throw RouterSystemError.conflict }
            try fresh(intent)
            try child.releaseGate()
            try waitForExec(intent, digest: digest, fence: fence, work: work, revision: saved, child: child)
        } catch {
            if slot.child == nil { slot.noChild = true } // In this live host, no spawn ever returned an owner.
            slot.child?.closeGate()
            throw error
        }
    }

    /// Keep Provider inside start until the child finishes its own applying/work checks and exec.
    /// A failed observation after START never implies the core did not execute.
    private func waitForExec(_ intent: RouterSystemIntent, digest: String, fence: RouterSystemDispatchFence,
                             work: RouterSystemWork, revision: UUID, child: RouterSystemDispatchChild) throws {
        func boundAndRunning() throws {
            try fresh(intent)
            guard try applying(intent, digest: digest, fence: fence, work: work).revision == revision,
                  child.observe() == .running else { throw RouterSystemError.operationUnsettled }
            try fresh(intent)
        }
        while true {
            try boundAndRunning()
            let executed = try operations.coreExecObserved(work, fence)
            try boundAndRunning()
            if executed {
                try operations.verifyCode()
                guard try operations.coreExecObserved(work, fence) else { throw RouterSystemError.ownershipUnknown }
                try boundAndRunning()
                return
            }
            operations.waitForExecPoll()
        }
    }

    func localSettlement(_ fence: RouterSystemDispatchFence) -> Settlement {
        guard lock.try() else { return .unknown }
        defer { lock.unlock() }
        guard let slot, slot.fence == fence else { return .unknown }
        return settlement(slot)
    }
    private func settlement(_ slot: Slot) -> Settlement {
        if !slot.claimed { return .neverDispatched }
        if slot.noChild { return .neverSpawned }
        guard let child = slot.child else { return .unknown }
        switch child.observe() {
        case .running: return .running
        case .exited: return .exited
        case .ownershipUnknown: return .unknown
        }
    }
    /// Stops only the locally held direct child. No claim about descendants, interfaces, routes or DNS.
    func stop(_ fence: RouterSystemDispatchFence) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        guard let slot, slot.fence == fence else { throw RouterSystemError.ownershipUnknown }
        switch settlement(slot) {
        case .neverDispatched, .neverSpawned, .exited: return
        case .unknown: throw RouterSystemError.ownershipUnknown
        case .running: break
        }
        guard let child = slot.child else { throw RouterSystemError.ownershipUnknown }
        child.closeGate()
        for (signal, grace): (Int32, TimeInterval) in [(SIGTERM, 0.5), (SIGKILL, 1)] {
            try child.signal(signal)
            switch child.waitUntil(ProcessInfo.processInfo.systemUptime + grace) {
            case .exited: return
            case .ownershipUnknown: throw RouterSystemError.ownershipUnknown
            case .running: continue
            }
        }
        throw RouterSystemError.operationUnsettled
    }

    func retireAfterConfirmedCleanup(_ fence: RouterSystemDispatchFence) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        let state = try journal.load(until: ProcessInfo.processInfo.systemUptime + 2)
        guard state.installation == identity, state.dispatch == fence, state.intent?.id == fence.instance,
              state.phase == .stopped,
              ["owned_cleanup_confirmed", "external_environment_acknowledged"].contains(state.reason) else { throw RouterSystemError.cleanupUnproven }
        // A restarted host (or an already-retired slot) has no signal owner to recreate.
        guard let slot else { return }
        guard slot.fence == fence, [.neverDispatched, .neverSpawned, .exited].contains(settlement(slot)) else {
            throw RouterSystemError.cleanupUnproven
        }
        self.slot = nil // Durable claim survives; it is not erased by retiring the in-memory owner.
    }
    private func prepared(_ intent: RouterSystemIntent) throws -> RouterSystemJournal {
        let state = try operations.loadForExecution(intent.deadlineUptime)
        guard state.installation == identity, state.phase == .prepared, state.intent == intent,
              state.dispatch == nil, state.work == nil, state.configurationDigest == nil else { throw RouterSystemError.conflict }
        return state
    }
    private func applying(_ intent: RouterSystemIntent, digest: String, fence: RouterSystemDispatchFence,
                          work: RouterSystemWork?) throws -> RouterSystemJournal {
        try fresh(intent)
        let state = try operations.loadForExecution(intent.deadlineUptime)
        try fresh(intent)
        guard state.installation == identity, state.phase == .applying, state.intent == intent,
              state.dispatch == fence, state.configurationDigest == digest, state.work == work else { throw RouterSystemError.ownershipUnknown }
        return state
    }
    private func fresh(_ intent: RouterSystemIntent) throws {
        let now = try operations.clock()
        guard now.bootID == host.bootID, now.bootID == intent.issued.bootID, now.uptime >= intent.issued.uptime,
              now.uptime < intent.deadlineUptime, now.date >= intent.issued.date, now.date < intent.expiresAt,
              try operations.currentHost() == host else { throw RouterSystemError.stalePreview }
    }
}
