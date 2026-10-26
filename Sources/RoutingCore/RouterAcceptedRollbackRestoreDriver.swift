import Foundation

/// Production rollback TUN restore driver: wires `RouterAcceptedRollbackRestore`
/// side effects to the real system pipeline.
///
/// The restored run is a **new** operation identity driving the normal
/// prepare → apply pipeline with the sealed previous-accepted plan/profile:
/// - the provider re-runs requireClear / network-fingerprint gates on prepare and apply;
/// - credentials are re-resolved per reference at apply time (never copied from history);
/// - a still-owned running instance is stopped first; a foreign environment changed
///   state refuses the restore instead of being torn through;
/// - acceptance happens only through the evidence-collected promotion on the new
///   instance. The driver never writes accepted and never treats the historical
///   digest as a new success; the sealed pointers are untouched.
///
/// The sealed pointer must still exist and match the preview at execution time —
/// a stale preview over a rotated journal refuses instead of restoring blindly.
enum RouterAcceptedRollbackRestoreDriver {
    enum Failure: Error, Equatable {
        case previewDigestMismatch
        case sealedPointerMissing
        case sealedPointerMismatch
        case foreignEnvironmentChanged
        case restoredInstanceNotRunning
        case duplicateCredentialReferences
    }

    struct Dependencies: Sendable {
        /// Validated journal read (provider snapshot in production).
        var snapshot: @Sendable () throws -> RouterSystemJournal
        /// Normal system pipeline entry (prepare/apply/status/stop).
        var handle: @Sendable (RouterSystemRequest) throws -> RouterSystemStatus
        /// Per-reference secret resolution at apply time (Keychain in production).
        var credential: @Sendable (UUID) throws -> RouterCredential
        /// Fresh operation identity source; never derived from history.
        var newInstanceID: @Sendable () -> UUID

        init(snapshot: @escaping @Sendable () throws -> RouterSystemJournal,
             handle: @escaping @Sendable (RouterSystemRequest) throws -> RouterSystemStatus,
             credential: @escaping @Sendable (UUID) throws -> RouterCredential,
             newInstanceID: @escaping @Sendable () -> UUID = { UUID() }) {
            self.snapshot = snapshot
            self.handle = handle
            self.credential = credential
            self.newInstanceID = newInstanceID
        }
    }

    /// Execute the restore as a fresh provider pipeline run.
    static func restore(preview: RouterAcceptedRollback.Preview,
                        dependencies: Dependencies) throws
        -> RouterAcceptedRollbackRestore.SideEffects.Outcome {
        // The compiler digest of the preview's plan/profile must equal the sealed
        // configuration digest; otherwise the preview no longer describes the seal.
        let digest = try RouterSystemProvider.digest(plan: preview.plan, profile: preview.profile)
        guard digest == preview.historicalConfigurationDigest else {
            throw Failure.previewDigestMismatch
        }

        let state = try dependencies.snapshot()
        let sealed: RouterAcceptedConfiguration?
        switch preview.source {
        case .previousAccepted: sealed = state.previousAccepted
        case .accepted: sealed = state.accepted
        }
        guard let sealed else { throw Failure.sealedPointerMissing }
        guard sealed.configurationDigest == preview.historicalConfigurationDigest,
              sealed.acceptanceEvidenceDigest == preview.historicalEvidenceDigest,
              sealed.plan == preview.plan, sealed.profile == preview.profile else {
            throw Failure.sealedPointerMismatch
        }

        // A still-owned running instance is stopped through the normal stop path.
        // "external_environment_changed" means a foreign footprint survived cleanup —
        // refuse instead of tearing through it.
        if let intent = state.intent, [.applying, .active, .stopping, .fault].contains(state.phase) {
            let stopped = try dependencies.handle(.stop(id: intent.id))
            guard stopped.phase == "stopped" || stopped.phase == "idle",
                  stopped.reason != "external_environment_changed" else {
                throw Failure.foreignEnvironmentChanged
            }
        }

        let id = dependencies.newInstanceID()
        _ = try dependencies.handle(.prepare(id: id, plan: preview.plan, profile: preview.profile))
        let references = preview.plan.proxies.compactMap(\.credentialReference)
        guard Set(references).count == references.count else {
            throw Failure.duplicateCredentialReferences
        }
        let credentials = try references.map { reference in
            RouterSystemCredential(reference: reference, value: try dependencies.credential(reference))
        }
        _ = try dependencies.handle(.apply(id: id, credentials: credentials))
        let final = try dependencies.handle(.status(id: id))
        guard final.phase == "active", final.instance == id, final.planDigest == digest else {
            throw Failure.restoredInstanceNotRunning
        }
        return .init(
            networkModified: true,
            detail: "回退恢复：新实例 \(id.uuidString.prefix(8))… 已按 sealed \(preview.source.rawValue) 的 plan/profile 走 prepare→apply（requireClear/指纹门禁全程重跑）。流量验收仍须新证据；历史 digest 未当作新成功；accepted/previousAccepted 指针未被本驱动改写。")
    }

    /// Production-shaped side effects bound to one sealed preview.
    /// The closure re-checks its own invariants on every invocation; it does not
    /// trust the caller beyond the gate that already ran.
    static func sideEffects(preview: RouterAcceptedRollback.Preview,
                            dependencies: Dependencies) -> RouterAcceptedRollbackRestore.SideEffects {
        .init(restoreOwnTun: { _ in
            try restore(preview: preview, dependencies: dependencies)
        })
    }
}
