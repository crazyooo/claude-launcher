import Foundation
import Darwin
import SystemConfiguration

/// The installed service starts idle. Only an authenticated explicit apply can execute the core.
public enum RouterSystemHost {
    public static func run() throws -> Never {
        var startupPhase = RouterSystemHostDiagnostic.Phase.installation
        do {
            let installation = try RouterSystemInstallation.verify()
            startupPhase = .reaping
            try RouterOwnedChild.requireExclusiveReaping()
            startupPhase = .processIdentity
            _ = try RouterSystemKernelObservation.host()
            startupPhase = .hostLease
            let lease = try RouterSystemHostLease.acquire(in: installation.state)
            startupPhase = .journal
            let journal = try RouterSystemJournalStore(directory: installation.state, installation: installation.manifest.identity)
            _ = try journal.load(until: ProcessInfo.processInfo.systemUptime + 2) // Never initialize on restart.
            startupPhase = .stage
            let command = try RouterSystemCommand(ownerUID: installation.manifest.ownerUID)
            let stage = try RouterSystemStage(installation: installation, command: command)
            startupPhase = .baseline
            let baselines = try RouterSystemBaselineStore(installation: installation)
            let network: () throws -> RouterSystemObservation = {
                RouterSystemObservation.collect(ownerUID: installation.manifest.ownerUID,
                    run: command.captureObservation, proxies: {
                        guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { throw RouterSystemError.ownershipUnknown }
                        return values
                    })
            }
            // Observation may include our running TUN. Provider requires a clear network only before apply.
            let capture = { try RouterSystemBaselineSnapshot.collect(command: command, network: network) }
            startupPhase = .dispatch
            let dispatch = try RouterSystemDispatch(installation: installation, journal: journal,
                baselines: baselines, stage: stage, capture: capture)
            startupPhase = .runtime
            let runtime = try RouterSystemRuntimeEffects(installation: installation, journal: journal,
                baselines: baselines, stage: stage, dispatch: dispatch, command: command, capture: capture)
            let provider = RouterSystemProvider(effects: .init(clock: RouterSystemKernelObservation.clock,
                load: { try journal.load(until: ProcessInfo.processInfo.systemUptime + 2) },
                save: { state, previous in
                    let deadline = try saveDeadline(state, now: RouterSystemKernelObservation.clock())
                    try journal.save(state, expecting: previous, until: deadline)
                    // A late write is uncertain; it does not extend an execution permission.
                    _ = try saveDeadline(state, now: RouterSystemKernelObservation.clock())
                }, network: network, stage: stage.stage,
                prepareDispatch: { try dispatch.prepare($0, digest: $1) },
                start: { try dispatch.start($0, digest: $1, fence: $2, recordWork: $3) },
                observe: runtime.observe, stop: runtime.stop, cleanup: runtime.cleanup,
                environmentCandidate: runtime.baselineCandidate, archiveEnvironment: { state in
                    try runtime.archiveEnvironment(state, archive: journal.archiveEnvironment)
                }))
            let endpoint = RouterSystemHostEndpoint(directory: installation.state, lease: lease, journal: journal, baselines: baselines,
                                                   dispatch: dispatch, provider: provider,
                connectionReader: .init(installation: installation, journal: journal, stage: stage, baselines: baselines,
                    probeNetwork: { deadline in
                        try captureForProbe(command: command, ownerUID: installation.manifest.ownerUID, deadline: deadline)
                    }))
            startupPhase = .socketActivation
            let listener = try RouterSystemActivatedSocket(installation: installation)
            let server = RouterSystemSocketServer(ownerUID: installation.manifest.ownerUID,
                                                  connections: endpoint.connections,
                                                  hitCorrelation: endpoint.hitCorrelation,
                                                  execute: endpoint.handle)
            defer { withExtendedLifetime((installation, lease, journal, command, stage, baselines, dispatch, runtime, endpoint, listener, server)) {} }
            startupPhase = .serving
            return try server.serve(listener: listener.fd)
        } catch {
            RouterSystemHostDiagnostic.record(startupPhase, error: error)
            throw error
        }
    }

    /// Uses the host's existing child owner. This budget rejects late results;
    /// filesystem and kernel calls are not promised to be hard-real-time cancellable.
    private static func captureForProbe(command: RouterSystemCommand, ownerUID: UInt32,
                                        deadline: TimeInterval) throws -> RouterSystemBaselineSnapshot {
        func fresh(reserving seconds: TimeInterval = 0) throws {
            guard deadline.isFinite, ProcessInfo.processInfo.systemUptime + seconds < deadline else {
                throw RouterOwnedProbeError.timedOut
            }
        }
        let network = {
            RouterSystemObservation.collect(ownerUID: ownerUID, run: { path, arguments, timeout in
                try fresh(reserving: 3)
                let result = try command.captureObservation(path, arguments, timeout)
                try fresh()
                return result
            }, proxies: {
                try fresh()
                guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else {
                    throw RouterSystemError.ownershipUnknown
                }
                try fresh()
                return values
            })
        }
        try fresh()
        let snapshot = try RouterSystemBaselineSnapshot.collect(read: { query in
            try fresh(reserving: 3)
            let result = try command.run(query)
            try fresh()
            return result
        }, interfaces: RouterSystemInterfaceSnapshot.collect, network: network,
            clock: RouterSystemKernelObservation.clock)
        try fresh()
        return snapshot
    }

    static func saveDeadline(_ state: RouterSystemJournal, now: RouterSystemClock) throws -> TimeInterval {
        guard now.uptime.isFinite, now.uptime >= 0, now.date.timeIntervalSince1970.isFinite else { throw RouterSystemError.stalePreview }
        if state.phase == .applying {
            guard let intent = state.intent, now.bootID == intent.issued.bootID,
                  now.uptime >= intent.issued.uptime, now.uptime < intent.deadlineUptime,
                  now.date >= intent.issued.date, now.date < intent.expiresAt else { throw RouterSystemError.stalePreview }
            return intent.deadlineUptime
        }
        if let review = state.environmentReview {
            try review.requireFresh(now)
            return min(now.uptime + 2, review.issued.uptime + 60)
        }
        return now.uptime + 2 // Historical bookkeeping availability, never a START grant.
    }
}

/// Serializes prechecks and retirement with the provider, not just the provider mutation itself.
final class RouterSystemHostEndpoint {
    private let directory: RouterSystemDirectory
    private let lease: RouterSystemHostLease
    private let journal: RouterSystemJournalStore
    private let baselines: RouterSystemBaselineStore
    private let dispatch: RouterSystemDispatch
    private let provider: RouterSystemProvider
    private let connectionReader: RouterSystemConnections?
    private let lock = NSLock()
    init(directory: RouterSystemDirectory, lease: RouterSystemHostLease, journal: RouterSystemJournalStore, baselines: RouterSystemBaselineStore,
         dispatch: RouterSystemDispatch, provider: RouterSystemProvider, connectionReader: RouterSystemConnections? = nil) {
        self.directory = directory; self.lease = lease; self.journal = journal; self.baselines = baselines
        self.dispatch = dispatch; self.provider = provider
        self.connectionReader = connectionReader
    }
    func connections(_ query: RouterConnectionQuery) throws -> RouterConnectionSnapshot {
        guard lock.try() else { throw RouterConnectionFailure.busy }
        defer { lock.unlock() }
        let operation = try RouterSystemHostLease.acquireExisting(in: directory, purpose: .operation)
        defer { operation.release() }
        try lease.verify()
        guard let connectionReader else { throw RouterConnectionFailure.unsupportedComponent }
        let sample = try connectionReader.read(query)
        try lease.verify(); try operation.verify()
        return sample
    }

    /// Armed GUI→helper hit correlation. Fail-closed without active instance.
    /// Loopback-only live capture; remote targets refuse without network mutation.
    /// Never writes accepted / never mutates journal.
    func hitCorrelation(_ query: RouterHitCorrelationQuery) throws -> RouterHitCorrelationReply {
        guard lock.try() else {
            return .refused(request: query.request, reason: RouterConnectionFailure.busy.rawValue)
        }
        defer { lock.unlock() }
        let operation = try RouterSystemHostLease.acquireExisting(in: directory, purpose: .operation)
        defer { operation.release() }
        try lease.verify()
        guard let connectionReader else {
            return .refused(request: query.request, reason: RouterConnectionFailure.unsupportedComponent.rawValue)
        }
        let state = try journal.load(until: ProcessInfo.processInfo.systemUptime + 2)
        guard state.phase == .active, let intent = state.intent, intent.id == query.instance else {
            return .refused(request: query.request, reason: RouterConnectionFailure.noActiveInstance.rawValue)
        }
        guard let arming = query.reconstructedArming,
              let mode = RouterHitCorrelationEntry.Mode(rawValue: query.mode),
              arming.mode == mode else {
            return .refused(request: query.request, reason: "hit_correlation_mode_mismatch")
        }
        do {
            try RouterHitCorrelationEntry.requireArmed(arming, mode: mode)
        } catch RouterHitCorrelationEntry.Failure.expired {
            return .refused(request: query.request, reason: "hit_correlation_arming_expired")
        } catch {
            return .refused(request: query.request, reason: "hit_correlation_disarmed")
        }
        let endpoint: RouterOwnedTCPProbe.Endpoint
        do {
            endpoint = try RouterOwnedTCPProbe.Endpoint(address: query.address, port: query.port)
        } catch {
            return .refused(request: query.request, reason: "invalid_target")
        }
        guard endpoint.isLoopback else {
            return .refused(request: query.request, reason: "remote_target_requires_user_clear_window")
        }
        switch mode {
        case .tcpNumeric:
            do {
                let report = try RouterHitCorrelationEntry.captureAndCorrelateTCP(
                    arming: arming, connections: connectionReader,
                    address: query.address, port: query.port,
                    plan: intent.plan, profile: intent.profile)
                try lease.verify(); try operation.verify()
                // Loopback own-probe under active binding may attest matrix cells only;
                // canPromoteAccepted stays false inside correlated(...).
                return .correlated(request: query.request, report: report,
                                   collectorAuthenticated: endpoint.isLoopback)
            } catch {
                return .refused(request: query.request, reason: Self.hitCorrelationFailureReason(error))
            }
        case .tlsHeld:
            guard let serverName = query.serverName, RouterValidation.validDomain(serverName) else {
                return .refused(request: query.request, reason: "tls_server_name_required")
            }
            let tlsTarget: RouterTLSConnection.Endpoint
            do {
                tlsTarget = try RouterTLSConnection.Endpoint(address: query.address, port: query.port)
            } catch {
                return .refused(request: query.request, reason: "invalid_target")
            }
            // Single writer before sem.signal; reader only after wait — no async lock.
            final class Box: @unchecked Sendable {
                var result: Result<RouterHitCorrelationEntry.Report, Error>?
            }
            let box = Box()
            let sem = DispatchSemaphore(value: 0)
            Task {
                do {
                    let report = try await RouterHitCorrelationEntry.captureAndCorrelateTLS(
                        arming: arming, connections: connectionReader, target: tlsTarget,
                        serverName: serverName, plan: intent.plan, profile: intent.profile)
                    box.result = .success(report)
                } catch {
                    box.result = .failure(error)
                }
                sem.signal()
            }
            if sem.wait(timeout: .now() + 70) == .timedOut {
                return .refused(request: query.request, reason: "timedOut")
            }
            let outcome = box.result
            switch outcome {
            case .success(let report):
                try lease.verify(); try operation.verify()
                return .correlated(request: query.request, report: report,
                                   collectorAuthenticated: endpoint.isLoopback)
            case .failure(let error):
                return .refused(request: query.request, reason: Self.hitCorrelationFailureReason(error))
            case nil:
                return .refused(request: query.request, reason: "operationUnsettled")
            }
        }
    }

    private static func hitCorrelationFailureReason(_ error: Error) -> String {
        if let failure = error as? RouterConnectionFailure { return failure.rawValue }
        if let failure = error as? RouterHitCorrelationEntry.Failure {
            switch failure {
            case .disarmed: return "hit_correlation_disarmed"
            case .expired: return "hit_correlation_arming_expired"
            case .modeMismatch: return "hit_correlation_mode_mismatch"
            }
        }
        if let failure = error as? RouterOwnedProbeError { return failure.rawValue }
        if let failure = error as? RouterTrafficEvidenceError { return failure.rawValue }
        if let failure = error as? RouterTLSConnection.Failure { return String(describing: failure) }
        return "operationUnsettled"
    }
    func handle(_ request: RouterSystemRequest) throws -> RouterSystemStatus {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        // The installer takes the same lease before checking idle/stopped state.
        // Keep it for the entire request so a concurrent apply cannot race an upgrade.
        let operation = try RouterSystemHostLease.acquire(in: directory, purpose: .operation)
        defer { withExtendedLifetime(operation) {} }
        try lease.verify()
        try retireConfirmedSlot()
        if case .prepare(let id, _, _) = request { try baselines.requireUnclaimed(id) }
        let result = try provider.handle(request)
        try retireConfirmedSlot()
        return result
    }
    private func retireConfirmedSlot() throws {
        let state = try journal.load(until: ProcessInfo.processInfo.systemUptime + 2)
        if state.phase == .stopped,
           ["owned_cleanup_confirmed", "external_environment_acknowledged"].contains(state.reason), let fence = state.dispatch {
            try dispatch.retireAfterConfirmedCleanup(fence)
        }
    }
}
