import Foundation
import CryptoKit

/// System effects are supplied only by the installed provider or deterministic tests, never by IPC.
struct RouterSystemEffects {
    var clock: () throws -> RouterSystemClock
    var load: () throws -> RouterSystemJournal
    var save: (RouterSystemJournal, UUID) throws -> Void
    var network: () throws -> RouterSystemObservation
    var stage: (RouterSystemIntent, [UUID: RouterCredential]) throws -> String
    /// Captures an immutable baseline and reserves a local slot. Must not spawn or modify networking.
    var prepareDispatch: (RouterSystemIntent, String) throws -> RouterSystemDispatchFence
    /// The callback must complete before the child is permitted to execute the network core.
    var start: (RouterSystemIntent, String, RouterSystemDispatchFence, (RouterSystemWork) throws -> Void) throws -> Void
    var observe: (RouterSystemJournal) throws -> RouterSystemRuntimeObservation
    var stop: (RouterSystemJournal) throws -> Void
    var cleanup: (RouterSystemJournal) throws -> RouterSystemCleanupProof
    var environmentCandidate: (RouterSystemJournal) throws -> RouterSystemEnvironmentCandidate = { _ in throw RouterSystemError.ownershipUnknown }
    var archiveEnvironment: (RouterSystemJournal) throws -> Void = { _ in throw RouterSystemError.journalUnknown }
    /// Helper-owned evidence collection only. The production default has no authenticated collector.
    /// IPC and UI callers cannot supply this seal or trigger a journal write directly.
    var collectAcceptance: (RouterSystemJournal) throws -> RouterAcceptanceEvidenceSeal? = { _ in nil }
    /// Pre-apply upstream resolver reachability. Default refuses when bootstrap UDP/53 is dead.
    var resolverHealth: (RouterSystemProfile) throws -> Void = { try RouterSystemResolverHealth.requireReachable(profile: $0) }
}

final class RouterSystemProvider {
    private let effects: RouterSystemEffects
    private let lock = NSLock()
    private var uncertainSave: (before: UUID, after: UUID)?
    init(effects: RouterSystemEffects) { self.effects = effects }

    func handle(_ request: RouterSystemRequest) throws -> RouterSystemStatus {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        var state = try effects.load()
        try Self.validateJournal(state)
        if let uncertainSave {
            guard case .status = request, state.revision == uncertainSave.before || state.revision == uncertainSave.after else {
                throw RouterSystemError.journalUnknown
            }
            self.uncertainSave = nil
        }
        switch request {
        case .prepare(let id, let plan, let profile):
            guard [.idle, .prepared, .stopped].contains(state.phase) else { throw RouterSystemError.operationUnsettled }
            guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else { throw RouterSystemError.invalidPlan }
            let digest = try Self.digest(plan: plan, profile: profile)
            if let prior = state.intent, prior.id == id {
                guard prior.digest == digest else { throw RouterSystemError.conflict }
                return .init(state) // An old identity never receives a renewed permission.
            }
            if state.usedEnvironmentReviewIDs != nil { try effects.archiveEnvironment(state) }
            let observation = try effects.network(); try Self.requireClear(observation)
            let now = try effects.clock(); try Self.validateClock(now)
            state.intent = .init(id: id, plan: plan, profile: profile, digest: digest,
                networkFingerprint: observation.fingerprint, issued: now,
                expiresAt: now.date.addingTimeInterval(60), deadlineUptime: now.uptime + 60)
            state.phase = .prepared; state.configurationDigest = nil; state.dispatch = nil; state.work = nil; state.footprint = nil
            state.reason = "prepared_not_applied"
            state.environmentReview = nil; state.usedEnvironmentReviewIDs = nil
            try persist(&state)
            return .init(state)

        case .apply(let id, let credentials):
            guard let intent = state.intent, intent.id == id else { throw RouterSystemError.conflict }
            if state.phase != .prepared {
                if state.phase == .stopped { return .init(state) }
                return try reconcile(&state) // Lost replies never cause another start.
            }
            try fresh(intent)
            let expected = Set(intent.plan.proxies.compactMap(\.credentialReference))
            guard credentials.count == expected.count, Set(credentials.map(\.reference)) == expected else { throw RouterSystemError.invalidCredentials }
            for item in credentials { do { try item.value.validate() } catch { throw RouterSystemError.invalidCredentials } }
            let values = Dictionary(uniqueKeysWithValues: credentials.map { ($0.reference, $0.value) })
            let digest = try effects.stage(intent, values)
            guard Self.validDigest(digest) else { throw RouterSystemError.configurationRejected }
            let observation = try effects.network(); try Self.requireClear(observation)
            guard observation.fingerprint == intent.networkFingerprint else { throw RouterSystemError.networkConflict }
            // Refuse a known blackhole: dead core-side resolver under fake-ip takes down
            // every hostname (2026-10-25). Does not claim routing_verified.
            try effects.resolverHealth(intent.profile)
            try fresh(intent)
            let dispatch = try effects.prepareDispatch(intent, digest)
            try Self.validateDispatch(dispatch, intent: intent, configurationDigest: digest)
            let afterBaseline = try effects.network(); try Self.requireClear(afterBaseline)
            guard afterBaseline.fingerprint == dispatch.networkFingerprint else { throw RouterSystemError.networkConflict }
            try fresh(intent)
            state.dispatch = dispatch
            state.configurationDigest = digest; state.phase = .applying; state.reason = "execution_pending"
            try persist(&state)
            do {
                try effects.start(intent, digest, dispatch) { work in
                    guard work.bootID == intent.issued.bootID, work.pid > 0, work.pid != dispatch.host.pid, work.birthSeconds > 0,
                          work.birthMicroseconds < 1_000_000, state.work == nil else { throw RouterSystemError.ownershipUnknown }
                    try self.fresh(intent)
                    state.work = work
                    try self.persist(&state)
                    try self.fresh(intent) // Persistence cannot extend the gate's lifetime.
                }
                return try reconcile(&state)
            } catch {
                if uncertainSave == nil {
                    state.phase = .fault; state.reason = "execution_outcome_unconfirmed"
                    try persist(&state)
                }
                throw error
            }

        case .previewEnvironment(let id, let reviewID):
            guard state.intent?.id == id, state.phase == .stopping,
                  state.reason == "external_environment_changed" else { throw RouterSystemError.conflict }
            if state.environmentReview?.review.id == reviewID { return .init(state) }
            let used = state.usedEnvironmentReviewIDs ?? []
            guard used.count < 64, !used.contains(reviewID) else { throw RouterSystemError.conflict }
            let candidate = try effects.environmentCandidate(state)
            let transition = try RouterSystemEnvironmentTransition.make(state, id: reviewID, candidate: candidate)
            try transition.requireFresh(effects.clock())
            state.environmentReview = transition; state.usedEnvironmentReviewIDs = used + [reviewID]
            try persist(&state)
            return .init(state)

        case .confirmEnvironment(let id, let reviewID, let digest):
            guard state.intent?.id == id, var transition = state.environmentReview,
                  transition.review.id == reviewID, transition.review.digest == digest else { throw RouterSystemError.conflict }
            // The validated journal is the sole commit result, including after a lost reply.
            if transition.confirmed != nil { return .init(state) }
            guard state.phase == .stopping, state.reason == "external_environment_changed" else { throw RouterSystemError.conflict }
            try transition.requireFresh(effects.clock())
            try transition.requireMatch(effects.environmentCandidate(state), state: state)
            let now = try effects.clock(); try transition.requireFresh(now)
            transition.confirmed = now
            state.environmentReview = transition; state.phase = .stopped; state.reason = "external_environment_acknowledged"
            try persist(&state)
            return .init(state)

        case .status(let id):
            if let id, state.intent?.id != id { throw RouterSystemError.conflict }
            if [.applying, .active, .stopping, .fault].contains(state.phase) {
                let original = state
                do { return try reconcile(&state) }
                catch {
                    // Management identity remains queryable when runtime probes fail. A write
                    // with an unknown result must first be resolved by the normal journal path.
                    guard uncertainSave == nil else { throw error }
                    let current = try effects.load()
                    try Self.validateJournal(current)
                    guard let installation = original.installation, installation.isValid,
                          current.installation == installation,
                          try Self.sameManagementRecord(original, current),
                          id == nil || current.intent?.id == id else { throw error }
                    return try RouterSystemStatus.managementOnly(current)
                }
            }
            return .init(state)

        case .stop(let id):
            guard state.intent?.id == id else { throw RouterSystemError.conflict }
            if state.phase == .stopped { return .init(state) }
            if state.phase == .prepared {
                // No execution grant is possible while the journal remains prepared.
                state.phase = .stopped; state.reason = "unused_preview_cancelled"
                try persist(&state); return .init(state)
            }
            state.environmentReview = nil
            state.phase = .stopping; state.reason = "owned_stop_pending"
            try persist(&state)
            try effects.stop(state)
            return try finishStop(&state)
        }
    }
    private static func sameManagementRecord(_ lhs: RouterSystemJournal, _ rhs: RouterSystemJournal) throws -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(lhs) == encoder.encode(rhs)
    }

    /// Validated read-only journal snapshot under the same operation lock.
    /// Internal: the rollback restore driver reads sealed accepted pointers with the
    /// single-writer discipline intact; it never mutates through this path.
    func snapshot() throws -> RouterSystemJournal {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        guard uncertainSave == nil else { throw RouterSystemError.journalUnknown }
        let state = try effects.load()
        try Self.validateJournal(state)
        return state
    }

    private func reconcile(_ state: inout RouterSystemJournal) throws -> RouterSystemStatus {
        if state.phase == .stopping { return try finishStop(&state) }
        guard let intent = state.intent else { throw RouterSystemError.journalUnknown }
        let observed = try effects.observe(state)
        guard observed.instance == intent.id, observed.ownershipConfirmed else { throw RouterSystemError.ownershipUnknown }
        if let footprint = observed.footprint {
            guard footprint.instance == intent.id, footprint.configurationDigest == state.configurationDigest,
                  footprint.work == state.work, footprint.interfaceIndex > 0, !footprint.interfaceName.isEmpty,
                  !footprint.addresses.isEmpty, !footprint.routeSignatures.isEmpty else { throw RouterSystemError.ownershipUnknown }
            if let previous = state.footprint, previous != footprint { throw RouterSystemError.ownershipUnknown }
            state.footprint = footprint
        }
        let runtimeComplete = observed.processAlive && observed.controllerHealthy && observed.capturePresent
            && observed.startWorkSettled && observed.footprint != nil
        if runtimeComplete {
            state.phase = .active; state.reason = "capture_observed_traffic_acceptance_pending"
        } else {
            state.phase = .fault; state.reason = "runtime_evidence_incomplete"
        }
        // Management and route observations never promote a configuration to accepted.
        try persist(&state)
        if runtimeComplete, let seal = try effects.collectAcceptance(state) {
            try promoteAccepted(into: &state, seal: seal)
        }
        return .init(state, observation: observed)
    }

    /// Rotates sealed history with the same CAS discipline as every other journal mutation.
    /// Refused evidence and an identical retry never advance revision or previousAccepted.
    private func promoteAccepted(into state: inout RouterSystemJournal,
                                 seal: RouterAcceptanceEvidenceSeal) throws {
        guard let intent = state.intent, state.configurationDigest != nil else {
            throw RouterSystemError.journalUnknown
        }
        // The accepted pointer stores the compiler plan/profile digest. The staged
        // configuration hash is bound inside the collector receipt/evidence instead.
        switch RouterAcceptancePromotion.decide(plan: intent.plan, profile: intent.profile,
                                                configurationDigest: intent.digest, seal: seal) {
        case .refuse:
            return
        case .promote(let accepted):
            guard state.accepted != accepted else { return }
            if let current = state.accepted { state.previousAccepted = current }
            state.accepted = accepted
            try persist(&state)
        }
    }

    private func finishStop(_ state: inout RouterSystemJournal) throws -> RouterSystemStatus {
        let proof = try effects.cleanup(state)
        guard let dispatch = state.dispatch, proof.instance == state.intent?.id,
              proof.dispatch == dispatch else { throw RouterSystemError.cleanupUnproven }
        if !proof.complete {
            guard state.work != nil, state.footprint != nil, proof.ownedResourcesAbsent,
                  !proof.externalStatePreserved else { throw RouterSystemError.cleanupUnproven }
            if state.reason != "external_environment_changed" {
                state.reason = "external_environment_changed"
                try persist(&state)
            }
            return .init(state)
        }
        state.environmentReview = nil // Used identities remain until durable history precedes the next prepare.
        state.phase = .stopped; state.reason = "owned_cleanup_confirmed"
        try persist(&state)
        return .init(state)
    }
    private func persist(_ state: inout RouterSystemJournal) throws {
        let before = state.revision
        state.revision = UUID()
        do {
            try Self.validateJournal(state)
            if let review = state.environmentReview { try review.requireFresh(effects.clock()) }
            try effects.save(state, before)
            if let review = state.environmentReview { try review.requireFresh(effects.clock()) }
        }
        catch { uncertainSave = (before, state.revision); throw RouterSystemError.journalUnknown }
    }
    private static func validateClock(_ clock: RouterSystemClock) throws {
        guard clock.uptime.isFinite, clock.uptime >= 0, clock.date.timeIntervalSince1970.isFinite else { throw RouterSystemError.stalePreview }
    }
    private func fresh(_ intent: RouterSystemIntent) throws {
        let now = try effects.clock(); try Self.validateClock(now)
        guard now.bootID == intent.issued.bootID, now.uptime >= intent.issued.uptime, now.uptime < intent.deadlineUptime,
              now.date >= intent.issued.date, now.date < intent.expiresAt else { throw RouterSystemError.stalePreview }
    }
    /// Shape gate for accepted pointers. Empty digests, plan/config mismatch, and
    /// evidence digests that collide with the configuration digest are refused.
    /// Presence alone is not enough to claim live traffic acceptance.
    static func validateAcceptedConfiguration(_ value: RouterAcceptedConfiguration) throws {
        guard !RouterValidation.issues(in: value.plan).contains(where: { $0.severity == .error }),
              validDigest(value.configurationDigest),
              validDigest(value.acceptanceEvidenceDigest),
              value.acceptanceEvidenceDigest != value.configurationDigest,
              value.configurationDigest == (try digest(plan: value.plan, profile: value.profile)) else {
            throw RouterSystemError.journalUnknown
        }
    }

    static func validateJournal(_ state: RouterSystemJournal) throws {
        if let identity = state.installation, !identity.isValid { throw RouterSystemError.journalUnknown }
        guard state.version == 1, RouterSystemJournal.reasons[state.phase]?.contains(state.reason) == true else {
            throw RouterSystemError.journalUnknown
        }
        if let accepted = state.accepted { try validateAcceptedConfiguration(accepted) }
        if let previous = state.previousAccepted { try validateAcceptedConfiguration(previous) }
        if let used = state.usedEnvironmentReviewIDs {
            guard !used.isEmpty, used.count <= 64, Set(used).count == used.count,
                  [.stopping, .stopped].contains(state.phase), state.work != nil, state.footprint != nil else {
                throw RouterSystemError.journalUnknown
            }
        }
        if let transition = state.environmentReview { try transition.validate(in: state) }
        if state.reason == "external_environment_acknowledged" {
            guard state.environmentReview?.confirmed != nil else { throw RouterSystemError.journalUnknown }
        }
        if ["external_environment_changed", "external_environment_acknowledged"].contains(state.reason) {
            guard state.work != nil, state.footprint != nil else { throw RouterSystemError.journalUnknown }
        }
        if state.phase == .idle {
            guard state.intent == nil, state.work == nil, state.footprint == nil,
                  state.configurationDigest == nil, state.dispatch == nil else { throw RouterSystemError.journalUnknown }
            return
        }
        guard let intent = state.intent, !RouterValidation.issues(in: intent.plan).contains(where: { $0.severity == .error }),
              intent.digest == (try Self.digest(plan: intent.plan, profile: intent.profile)), Self.validDigest(intent.networkFingerprint),
              intent.deadlineUptime == intent.issued.uptime + 60, intent.expiresAt == intent.issued.date.addingTimeInterval(60) else { throw RouterSystemError.journalUnknown }
        try validateClock(intent.issued)
        if state.phase == .prepared {
            guard state.work == nil, state.configurationDigest == nil, state.footprint == nil,
                  state.dispatch == nil else { throw RouterSystemError.journalUnknown }
        }
        if let digest = state.configurationDigest {
            guard let dispatch = state.dispatch else { throw RouterSystemError.journalUnknown }
            try validateDispatch(dispatch, intent: intent, configurationDigest: digest)
        } else if state.dispatch != nil { throw RouterSystemError.journalUnknown }
        if [.applying, .active, .stopping, .fault].contains(state.phase) ||
            ["owned_cleanup_confirmed", "external_environment_acknowledged"].contains(state.reason) {
            guard state.configurationDigest != nil, state.dispatch != nil else { throw RouterSystemError.journalUnknown }
        }
        if state.reason == "unused_preview_cancelled" {
            guard state.configurationDigest == nil, state.dispatch == nil, state.work == nil, state.footprint == nil else {
                throw RouterSystemError.journalUnknown
            }
        }
        if let digest = state.configurationDigest, !Self.validDigest(digest) { throw RouterSystemError.journalUnknown }
        if state.work != nil && state.configurationDigest == nil { throw RouterSystemError.journalUnknown }
        if let work = state.work {
            guard work.bootID == intent.issued.bootID, work.pid > 0, work.pid != state.dispatch?.host.pid, work.birthSeconds > 0,
                  work.birthMicroseconds < 1_000_000 else { throw RouterSystemError.journalUnknown }
        }
        if state.phase == .active {
            guard state.work != nil, state.footprint != nil, state.configurationDigest != nil else { throw RouterSystemError.journalUnknown }
        }
        if let footprint = state.footprint {
            guard footprint.instance == intent.id, footprint.work == state.work, footprint.configurationDigest == state.configurationDigest,
                  footprint.interfaceIndex > 0, !footprint.interfaceName.isEmpty, footprint.interfaceName.utf8.count <= 32,
                  footprint.interfaceName.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }),
                  !footprint.addresses.isEmpty, footprint.addresses.count <= 32,
                  !footprint.routeSignatures.isEmpty, footprint.routeSignatures.count <= 4096,
                  (footprint.addresses + footprint.routeSignatures).allSatisfy({ !$0.isEmpty && $0.utf8.count <= 1024 && !$0.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) }) else { throw RouterSystemError.journalUnknown }
        }
    }
    static func digest(plan: RouterPlan, profile: RouterSystemProfile) throws -> String {
        try RouterSystemCompiler.digest(plan: plan, profile: profile)
    }
    static func validateDispatch(_ value: RouterSystemDispatchFence, intent: RouterSystemIntent, configurationDigest: String) throws {
        guard value.instance == intent.id, value.host.bootID == intent.issued.bootID,
              value.host.pid > 0, value.host.birthSeconds > 0, value.host.birthMicroseconds < 1_000_000,
              value.processGroup == value.host.pid, value.gateDeadlineUptime == intent.deadlineUptime,
              value.gateExpiresAt == intent.expiresAt, value.networkFingerprint == intent.networkFingerprint,
              value.configurationDigest == configurationDigest, validDigest(value.baselineDigest), validDigest(configurationDigest) else {
            throw RouterSystemError.journalUnknown
        }
    }
    static func validDigest(_ value: String) -> Bool { value.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } }
    static func requireClear(_ value: RouterSystemObservation) throws {
        guard value.complete, value.applicationProxyEnabled == false, value.automaticProxyEnabled == false,
              value.connectedVPN == false, value.tunnelCaptureInterfaces.isEmpty, value.userCoreJobPresent == false else { throw RouterSystemError.networkConflict }
    }
}
