import Foundation
import Darwin

/// Samples a running core without invoking provider reconciliation, cleanup, or journal writes.
final class RouterSystemConnections {
    struct Readers {
        var load: (TimeInterval) throws -> RouterSystemJournal
        var material: (RouterSystemJournal) throws -> RouterConnectionMaterial
        var process: (RouterSystemWork) throws -> RouterSystemKernelObservation.ProcessSnapshot
        var listeners: (RouterSystemWork, TimeInterval) throws -> RouterSystemControllerListener.Observation
        var body: (String, TimeInterval) throws -> Data
        var clock: () -> (Date, TimeInterval)
    }
    private let identity: RouterSystemInstallationIdentity
    private let readers: Readers
    private let probeReaders: ProbeReaders?
    private let source: OwnProbeObservation.Source

    init(identity: RouterSystemInstallationIdentity, readers: Readers, fixtureProbe: ProbeReaders? = nil) {
        self.identity = identity; self.readers = readers; probeReaders = fixtureProbe; source = .fixture
    }
    private init(identity: RouterSystemInstallationIdentity, readers: Readers, installedProbe: ProbeReaders?) {
        self.identity = identity; self.readers = readers; probeReaders = installedProbe; source = .installedReaders
    }
    convenience init(installation: RouterSystemInstallation, journal: RouterSystemJournalStore,
                     stage: RouterSystemStage, baselines: RouterSystemBaselineStore,
                     probeNetwork: ((TimeInterval) throws -> RouterSystemBaselineSnapshot)? = nil) {
        let probe: ProbeReaders? = probeNetwork.map { capture in
            .init(clock: RouterSystemKernelObservation.clock,
                open: { try RouterOwnedTCPProbe.installed(address: $0, port: $1, until: $2) },
                context: { state, deadline in
                    try RouterSystemProvider.validateJournal(state)
                    guard state.installation == installation.manifest.identity, state.phase == .active,
                          let intent = state.intent, let work = state.work, let fence = state.dispatch,
                          let digest = state.configurationDigest else { throw RouterTrafficEvidenceError.sourceChanged }
                    try baselines.verifyClaim(intent: intent, fence: fence)
                    _ = try baselines.read(intent: intent, fence: fence)
                    let source = try stage.evidenceSource(intent, configurationDigest: digest)
                    let network = try capture(deadline)
                    let binding = RouterTrafficBinding(phase: .active, installation: installation.manifest.identity,
                        instance: intent.id, revision: state.revision, work: work, planDigest: intent.digest,
                        configurationDigest: digest, stageReceiptDigest: source.receiptDigest,
                        baselineID: fence.baselineID, baselineDigest: fence.baselineDigest,
                        networkFingerprint: network.networkFingerprint, coreSHA256: RouterCoreRelease.executableSHA256,
                        coreVersion: RouterCoreRelease.version, compilerPolicy: RouterSystemCompiler.policyVersion)
                    try binding.validate()
                    guard source.matches(binding) else { throw RouterTrafficEvidenceError.sourceChanged }
                    return .init(binding: binding, network: network, verify: {
                        try baselines.verifyClaim(intent: intent, fence: fence)
                        _ = try baselines.read(intent: intent, fence: fence)
                        try source.withVerifiedDirectory { _ in () }
                    })
                }, openTLS: { target, serverName, deadline in
                    try await RouterTLSConnection.installed(target: target, serverName: serverName, until: deadline)
                })
        }
        self.init(identity: installation.manifest.identity, readers: .init(load: { try journal.load(until: $0) },
            material: { state in
                guard let intent = state.intent, let fence = state.dispatch, let digest = state.configurationDigest else {
                    throw RouterConnectionFailure.identityChanged
                }
                try baselines.verifyClaim(intent: intent, fence: fence)
                return try stage.controllerMaterial(intent, configurationDigest: digest)
            }, process: { try RouterSystemKernelObservation.executable($0, expected: [RouterSystemLayout.core]) },
            listeners: { try RouterSystemControllerListener.observe(work: $0, deadline: $1) },
            body: { try RouterSystemControllerHTTP.connections(port: RouterSystemCompiler.controllerPort, secret: $0, until: $1) },
            clock: { (Date(), ProcessInfo.processInfo.systemUptime) }), installedProbe: probe)
    }
    func read(_ query: RouterConnectionQuery) throws -> RouterConnectionSnapshot {
        try readTransaction(query) { _, _, _ in }
    }
    private struct Evidence: Equatable {
        let state: Data
        let process: RouterSystemKernelObservation.ProcessSnapshot
        let listeners: [RouterSystemControllerListener.Signature]
        let material: RouterConnectionMaterial
        let binding: RouterConnectionBinding
    }
    private struct RawCapture {
        let snapshot: RouterConnectionSnapshot
        let journal: RouterSystemJournal
        let evidence: Evidence
        let body: Data
        let trackers: [RouterTrafficTracker]
    }
    private func captureRaw(_ query: RouterConnectionQuery, until limit: TimeInterval? = nil) throws -> RawCapture {
        var captured: (Evidence, RouterSystemJournal, Data)?
        let snapshot = try readTransaction(query, until: limit) { captured = ($0, $1, $2) }
        guard let captured else { throw RouterTrafficEvidenceError.sourceChanged }
        return try .init(snapshot: snapshot, journal: captured.1, evidence: captured.0, body: captured.2,
                         trackers: RouterTrafficTrackerParser.parse(captured.2))
    }
    private func readTransaction(_ query: RouterConnectionQuery, until limit: TimeInterval? = nil,
                                 captured: (Evidence, RouterSystemJournal, Data) -> Void) throws -> RouterConnectionSnapshot {
        if let limit, !limit.isFinite { throw RouterConnectionFailure.stale }
        let deadline = min(readers.clock().1 + 5, limit ?? .infinity)
        var first: Evidence?
        var observedState: RouterSystemJournal?
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        func observe() throws -> RouterConnectionBinding {
            if Task.isCancelled { throw RouterOwnedProbeError.cancelled }
            guard readers.clock().1 < deadline else { throw RouterConnectionFailure.stale }
            let state = try readers.load(deadline)
            try RouterSystemProvider.validateJournal(state)
            guard state.installation == identity else { throw RouterConnectionFailure.identityChanged }
            switch state.phase {
            case .idle, .prepared, .stopped: throw RouterConnectionFailure.noActiveInstance
            case .active: break
            default: throw RouterConnectionFailure.unavailable
            }
            guard let intent = state.intent, let work = state.work, let fence = state.dispatch,
                  let digest = state.configurationDigest else { throw RouterConnectionFailure.identityChanged }
            let material = try readers.material(state)
            let process = try readers.process(work)
            guard process.work == work, process.uid == 0, process.realUID == 0,
                  process.parentPID == fence.host.pid, process.processGroup == fence.processGroup,
                  case .observed(let listeners) = try readers.listeners(work, deadline), !listeners.isEmpty else {
                throw RouterConnectionFailure.identityChanged
            }
            struct Epoch: Encodable { let work: RouterSystemWork; let dispatch: RouterSystemDispatchFence }
            let binding = RouterConnectionBinding(mode: .system, installation: identity.id, instance: intent.id,
                epoch: RouterSystemObservation.hash(try encoder.encode(Epoch(work: work, dispatch: fence))), configurationDigest: digest)
            let evidence = Evidence(state: try encoder.encode(state), process: process, listeners: listeners, material: material, binding: binding)
            if let first, first != evidence { throw RouterConnectionFailure.identityChanged }
            first = evidence
            observedState = state
            if Task.isCancelled { throw RouterOwnedProbeError.cancelled }
            guard readers.clock().1 < deadline else { throw RouterConnectionFailure.stale }
            return binding
        }
        var rawBody: Data?
        let snapshot = try RouterConnectionCollector.read(request: query.request, expectedInstance: query.instance, mode: .system,
            observe: observe, readBody: { _ in
                guard let material = first?.material else { throw RouterConnectionFailure.identityChanged }
                if Task.isCancelled { throw RouterOwnedProbeError.cancelled }
                guard self.readers.clock().1 < deadline else { throw RouterConnectionFailure.stale }
                let body = try self.readers.body(material.secret, deadline)
                if Task.isCancelled { throw RouterOwnedProbeError.cancelled }
                guard self.readers.clock().1 < deadline else { throw RouterConnectionFailure.stale }
                rawBody = body
                return (body, material.redactions)
            }, clock: readers.clock)
        guard let first, let observedState, let rawBody else { throw RouterConnectionFailure.identityChanged }
        captured(first, observedState, rawBody)
        return snapshot
    }

    struct ProbeContext {
        let binding: RouterTrafficBinding
        let network: RouterSystemBaselineSnapshot
        /// Retains the original Stage image capability, rather than reacquiring equal hashes.
        let verify: () throws -> Void
    }
    struct ProbeReaders {
        var clock: () throws -> RouterSystemClock
        var open: (String, UInt16, TimeInterval) throws -> RouterOwnedTCPProbe
        var context: (RouterSystemJournal, TimeInterval) throws -> ProbeContext
        var openTLS: ((RouterTLSConnection.Endpoint, String, TimeInterval) async throws -> RouterTLSConnection)? = nil
    }
    /// Private in-memory observation. Not Codable, not a receipt, not an acceptance capability.
    struct OwnProbeObservation {
        enum Source { case fixture, installedReaders }
        let source: Source
        let binding: RouterTrafficBinding
        /// Whole operation, including checks before the socket existed.
        let interval: RouterTrafficInterval
        let connectStartedAt: RouterSystemClock
        /// Complete bounded first sample, before opening the probe socket.
        let priorTrackerIDs: Set<UUID>
        let socketInterval: RouterTrafficInterval
        let socket: RouterOwnedTCPProbe.Sample
        let controllerInterval: RouterTrafficInterval
        fileprivate let body: Data
        let trackers: [RouterTrafficTracker]
        let collectorAuthenticated = false
        let canPromoteAccepted = false
    }

    struct OwnEchoObservation {
        let socketObservation: OwnProbeObservation
        let exchange: RouterOwnedTCPIO.Observation
        let collectorAuthenticated = false
        let canPromoteAccepted = false
    }

    /// Fixture-only payload path; never connected to production IPC or UI.
    func observeOwnTCPEchoFixture(address: String, port: UInt16) throws -> OwnEchoObservation {
        guard source == .fixture, getuid() != 0, geteuid() == getuid(), !address.contains("%"),
              try RouterOwnedTCPProbe.Endpoint(address: address, port: port).isLoopback else {
            throw RouterOwnedProbeError.unavailable
        }
        let result = try observeOwnTCPTransaction(address: address, port: port, nonce: UUID())
        guard let exchange = result.1 else { throw RouterOwnedProbeError.unavailable }
        return .init(socketObservation: result.0, exchange: exchange)
    }

    /// Native own-TCP capture. Automatic/background sampling remains forbidden.
    /// Production callers must go through armed `hitCorrelation` IPC (or fixture tests).
    /// Observes only this helper's numeric TCP connection, never a selected application's path.
    func observeOwnTCP(address: String, port: UInt16) throws -> OwnProbeObservation {
        try observeOwnTCPTransaction(address: address, port: port, nonce: nil).0
    }

    private func observeOwnTCPTransaction(address: String, port: UInt16, nonce: UUID?) throws ->
        (OwnProbeObservation, RouterOwnedTCPIO.Observation?) {
        guard let probeReaders else { throw RouterConnectionFailure.unsupportedComponent }
        if source == .fixture, getuid() == 0 || geteuid() == 0 { throw RouterOwnedProbeError.unavailable }
        _ = try RouterOwnedTCPProbe.Endpoint(address: address, port: port)
        let began = try probeReaders.clock(), deadline = began.uptime + 60
        func fresh() throws {
            try RouterOwnedTCPProbe.requireFresh(start: began, now: probeReaders.clock(), deadline: deadline)
        }
        let first = try captureRaw(.init(request: UUID(), instance: nil))
        let context = try probeReaders.context(first.journal, deadline)
        try context.binding.validate()
        try context.verify(); try fresh()
        guard context.binding.installation == identity, context.binding.revision == first.journal.revision,
              context.binding.instance == first.snapshot.binding.instance,
              context.network.captured.bootID == began.bootID,
              context.network.captured.uptime >= began.uptime, context.network.captured.date >= began.date else {
            throw RouterTrafficEvidenceError.sourceChanged
        }
        let socket = try probeReaders.open(address, port, min(deadline, try probeReaders.clock().uptime + 3))
        defer { socket.close() }
        guard (source == .fixture) == socket.fixture else { throw RouterTrafficEvidenceError.sourceChanged }
        let socketBefore = try socket.sample(until: deadline)
        let exchange = try nonce.map { try socket.exchangeLoopbackFixture(nonce: $0, until: deadline) }
        let during = try captureRaw(.init(request: UUID(), instance: first.snapshot.binding.instance))
        try fresh()
        let finalContext = try probeReaders.context(during.journal, deadline)
        try context.verify(); try finalContext.verify(); try fresh()
        let last = try captureRaw(.init(request: UUID(), instance: first.snapshot.binding.instance))
        try context.verify(); try finalContext.verify()
        let socketAfter = try socket.sample(until: deadline), ended = try probeReaders.clock()
        guard first.evidence == during.evidence, during.evidence == last.evidence,
              socketBefore == socketAfter,
              socketAfter.process.identity.work.bootID == began.bootID,
              try RouterTrafficCodec.encode(context.binding) == RouterTrafficCodec.encode(finalContext.binding),
              try context.network.sameStartEnvironment(as: finalContext.network),
              finalContext.network.captured.uptime >= context.network.captured.uptime,
              finalContext.network.captured.date >= context.network.captured.date,
              finalContext.network.captured.uptime <= ended.uptime,
              finalContext.network.captured.date <= ended.date else { throw RouterTrafficEvidenceError.sourceChanged }
        try RouterOwnedTCPProbe.requireFresh(start: began, now: ended, deadline: deadline)
        let controller = RouterTrafficInterval(
            start: .init(bootID: began.bootID, uptime: during.snapshot.startedUptime, date: during.snapshot.startedAt),
            end: .init(bootID: began.bootID, uptime: during.snapshot.completedUptime, date: during.snapshot.completedAt))
        try controller.validate(boot: began.bootID, maximumDuration: 5)
        let socketInterval = RouterTrafficInterval(start: socket.openedAt, end: ended)
        try socketInterval.validate(boot: began.bootID, maximumDuration: 60)
        let operation = RouterTrafficInterval(start: began, end: ended)
        let connecting = RouterTrafficInterval(start: socket.connectStartedAt, end: socket.openedAt)
        try operation.validate(boot: began.bootID, maximumDuration: 60)
        try connecting.validate(boot: began.bootID, maximumDuration: 3)
        guard operation.contains(connecting), operation.contains(socketInterval),
              first.snapshot.completedUptime <= connecting.start.uptime,
              first.snapshot.completedAt <= connecting.start.date,
              context.network.captured.uptime <= connecting.start.uptime,
              context.network.captured.date <= connecting.start.date,
              socketInterval.contains(controller),
              context.network.captured.uptime <= controller.start.uptime,
              context.network.captured.date <= controller.start.date,
              finalContext.network.captured.uptime >= controller.end.uptime,
              finalContext.network.captured.date >= controller.end.date else {
            throw RouterTrafficEvidenceError.sourceChanged
        }
        if let exchange {
            try exchange.interval.validate(boot: began.bootID, maximumDuration: 5)
            guard socketInterval.contains(exchange.interval),
                  exchange.interval.end.uptime <= controller.start.uptime,
                  exchange.interval.end.date <= controller.start.date else {
                throw RouterTrafficEvidenceError.sourceChanged
            }
        }
        // Only the middle body is bracketed by current network snapshots. The
        // final transaction verifies source stability; it is not selected data.
        return (.init(source: source, binding: context.binding, interval: operation,
                     connectStartedAt: connecting.start, priorTrackerIDs: Set(first.trackers.map(\.id)),
                     socketInterval: socketInterval,
                     socket: socketAfter, controllerInterval: controller, body: during.body, trackers: during.trackers), exchange)
    }
    /// Private numeric TLS capture. Authentication name does not establish DNS or application coverage.
    struct OwnTLSObservation {
        let source: OwnProbeObservation.Source
        let binding: RouterTrafficBinding
        let interval: RouterTrafficInterval
        let priorTrackerIDs: Set<UUID>
        let requestNonce: UUID
        let heldInterval: RouterTrafficInterval
        let before: RouterTLSConnection.Sample
        let after: RouterTLSConnection.Sample
        let exchange: RouterTLSConnection.Exchange
        let controllerInterval: RouterTrafficInterval
        let trackers: [RouterTrafficTracker]
        let collectorAuthenticated = false
        let canPromoteAccepted = false

        /// Revalidated by both capture and correlation, without manufacturing an old POSIX sample.
        func validate() throws {
            try binding.validate()
            let boot = binding.work.bootID
            try interval.validate(boot: boot, maximumDuration: 60)
            let lifetime = RouterTrafficInterval(start: before.connectStartedAt, end: interval.end)
            let held = heldInterval, sampled = controllerInterval
            for value in [lifetime, held, sampled, exchange.interval] {
                try value.validate(boot: boot, maximumDuration: 5)
            }
            func precedes(_ a: RouterSystemClock, _ b: RouterSystemClock) -> Bool {
                a.bootID == b.bootID && a.uptime <= b.uptime && a.date <= b.date
            }
            guard interval.contains(lifetime), lifetime.contains(held), held.end == interval.end,
                  held.start == before.socket.interval.end, held.contains(sampled),
                  held.contains(exchange.interval), held.contains(after.socket.interval),
                  precedes(exchange.interval.end, sampled.start),
                  precedes(sampled.end, after.socket.interval.start),
                  precedes(before.socket.interval.end, exchange.interval.start),
                  exchange.interval.contains(exchange.before.socket.interval),
                  exchange.interval.contains(exchange.after.socket.interval),
                  precedes(exchange.before.socket.interval.end, exchange.after.socket.interval.start),
                  exchange.reply.nonce == requestNonce,
                  RouterTrafficAddress.bytes(exchange.reply.serverReportedPeerIP) != nil,
                  (source == .fixture) == (before.source == .fixture),
                  source != .installedReaders || before.trust == .system,
                  priorTrackerIDs.count <= RouterConnectionProjection.connectionLimit else {
                throw RouterTrafficEvidenceError.invalidReceipt
            }
            for sample in [before, after, exchange.before, exchange.after] {
                try sample.socket.interval.validate(boot: boot, maximumDuration: 5)
                guard lifetime.contains(sample.socket.interval), sample.source == before.source,
                      sample.socket.source == before.source, sample.trust == before.trust,
                      sample.serverName == before.serverName, RouterValidation.validDomain(sample.serverName),
                      sample.protocolVersion == before.protocolVersion,
                      sample.protocolVersion == 0x0303 || sample.protocolVersion == 0x0304,
                      sample.connectStartedAt == before.connectStartedAt,
                      sample.socket.process == before.socket.process,
                      sample.socket.socket == before.socket.socket else {
                    throw RouterTrafficEvidenceError.invalidReceipt
                }
            }
        }
    }

    /// Own-TLS collector. Automatic destinations remain forbidden; no journal mutation or accepted promotion.
    /// Production callers must go through armed `hitCorrelation` IPC (or fixture tests).
    func observeOwnTLS(target: RouterTLSConnection.Endpoint, serverName: String) async throws -> OwnTLSObservation {
        guard let probeReaders, let open = probeReaders.openTLS else {
            throw RouterConnectionFailure.unsupportedComponent
        }
        if source == .fixture {
            guard getuid() != 0, geteuid() == getuid(), target.isLoopback else {
                throw RouterTLSConnection.Failure.unavailable
            }
        }
        guard !target.address.contains("%"), RouterValidation.validDomain(serverName) else {
            throw RouterTLSConnection.Failure.invalidTarget
        }
        _ = try RouterTLSConnection.Endpoint(address: target.address, port: target.port)
        let began = try probeReaders.clock(), deadline = began.uptime + 60
        var previous = began
        @discardableResult func checkpoint(_ limit: TimeInterval) throws -> RouterSystemClock {
            try Task.checkCancellation()
            let now = try probeReaders.clock()
            try RouterOwnedTCPProbe.requireFresh(start: began, now: now, deadline: limit)
            try RouterOwnedTCPProbe.requireFresh(start: previous, now: now, deadline: limit)
            previous = now
            return now
        }
        try checkpoint(deadline)
        let first = try captureRaw(.init(request: UUID(), instance: nil), until: deadline)
        try checkpoint(deadline)
        let context = try probeReaders.context(first.journal, deadline)
        try context.binding.validate(); try context.network.validate()
        try checkpoint(deadline)
        try context.verify()
        let beforeOpen = try checkpoint(deadline)
        guard context.binding.installation == identity, context.binding.revision == first.journal.revision,
              context.binding.instance == first.snapshot.binding.instance,
              context.network.captured.bootID == began.bootID,
              context.network.captured.uptime >= began.uptime, context.network.captured.date >= began.date,
              context.network.captured.uptime <= beforeOpen.uptime, context.network.captured.date <= beforeOpen.date else {
            throw RouterTrafficEvidenceError.sourceChanged
        }
        // Preconditions precede creation. All held-phase readers inherit this absolute deadline.
        let heldDeadline = min(deadline, beforeOpen.uptime + 5)
        let owner = try await open(target, serverName, heldDeadline)
        defer { owner.close() }
        return try await withTaskCancellationHandler(operation: {
            try checkpoint(heldDeadline)
            let before = try await owner.sample()
            guard (source == .fixture) == (before.source == .fixture),
                  source != .installedReaders || before.trust == .system else {
                throw RouterTrafficEvidenceError.sourceChanged
            }
            let nonce = UUID()
            let exchange = try await owner.exchange(nonce: nonce)
            try checkpoint(heldDeadline)
            let query = RouterConnectionQuery(request: UUID(), instance: first.snapshot.binding.instance)
            let during = try captureRaw(query, until: heldDeadline)
            try checkpoint(heldDeadline)
            let finalContext = try probeReaders.context(during.journal, heldDeadline)
            try checkpoint(heldDeadline)
            try context.verify(); try checkpoint(heldDeadline)
            try finalContext.verify(); try checkpoint(heldDeadline)
            let last = try captureRaw(.init(request: UUID(), instance: first.snapshot.binding.instance), until: heldDeadline)
            try checkpoint(heldDeadline)
            try context.verify(); try checkpoint(heldDeadline)
            try finalContext.verify(); try checkpoint(heldDeadline)
            let after = try await owner.sample()
            let ended = try checkpoint(heldDeadline)
            guard first.evidence == during.evidence, during.evidence == last.evidence,
                  after.socket.socket.tuple.peer == target, after.serverName == serverName.lowercased(),
                  try RouterTrafficCodec.encode(context.binding) == RouterTrafficCodec.encode(finalContext.binding),
                  try context.network.sameStartEnvironment(as: finalContext.network) else {
                throw RouterTrafficEvidenceError.sourceChanged
            }
            let controller = RouterTrafficInterval(
                start: .init(bootID: began.bootID, uptime: during.snapshot.startedUptime, date: during.snapshot.startedAt),
                end: .init(bootID: began.bootID, uptime: during.snapshot.completedUptime, date: during.snapshot.completedAt))
            guard context.network.captured.uptime <= before.connectStartedAt.uptime,
                  context.network.captured.date <= before.connectStartedAt.date,
                  first.snapshot.completedUptime <= before.connectStartedAt.uptime,
                  first.snapshot.completedAt <= before.connectStartedAt.date,
                  context.network.captured.uptime <= controller.start.uptime,
                  context.network.captured.date <= controller.start.date,
                  finalContext.network.captured.bootID == began.bootID,
                  finalContext.network.captured.uptime >= controller.end.uptime,
                  finalContext.network.captured.date >= controller.end.date,
                  finalContext.network.captured.uptime <= ended.uptime,
                  finalContext.network.captured.date <= ended.date else {
                throw RouterTrafficEvidenceError.sourceChanged
            }
            let observation = OwnTLSObservation(source: source, binding: context.binding,
                interval: .init(start: began, end: ended), priorTrackerIDs: Set(first.trackers.map(\.id)),
                requestNonce: nonce, heldInterval: .init(start: before.socket.interval.end, end: ended),
                before: before, after: after, exchange: exchange, controllerInterval: controller,
                trackers: during.trackers)
            try observation.validate()
            try checkpoint(heldDeadline)
            return observation
        }, onCancel: { owner.close() })
    }
}

/// Result of assembling privately observed own-TCP attempts into an immutable receipt.
/// This is still a live-collector-unavailable assessment, never an acceptance authority.
struct RouterSystemAcceptanceCollection {
    let receipt: RouterTrafficReceipt
    let assessment: RouterTrafficAssessment
    let evidenceDigest: String

    /// The only production seal shape until authenticated remote/application collection exists.
    func evidenceSeal() -> RouterAcceptanceEvidenceSeal {
        .fromLiveAssessment(planDigest: receipt.before.planDigest,
                            configurationDigest: receipt.before.planDigest,
                            evidenceDigest: evidenceDigest, assessment: assessment)
    }
}

/// Assembles completed own-TCP observations without inventing targets, payloads or coverage.
/// Unobserved or uncorrelated cases are left absent so assessment reports notRun.
enum RouterSystemAcceptanceCollector {
    enum Source {
        case fixtureHarness
        case installedReaders
    }

    static func collect(state: RouterSystemJournal, plan: RouterPlan, profile: RouterSystemProfile,
                        observations: [RouterSystemConnections.OwnProbeObservation],
                        source: Source) throws -> RouterSystemAcceptanceCollection {
        try RouterSystemProvider.validateJournal(state)
        guard state.phase == .active, let intent = state.intent, let work = state.work,
              let configurationDigest = state.configurationDigest, !observations.isEmpty,
              intent.plan == plan, intent.profile == profile else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
        let expectedSource: RouterSystemConnections.OwnProbeObservation.Source =
            source == .fixtureHarness ? .fixture : .installedReaders
        guard let first = observations.first else { throw RouterTrafficEvidenceError.invalidReceipt }
        let binding = first.binding
        try binding.validate()
        guard binding.installation == state.installation, binding.instance == intent.id,
              binding.revision == state.revision, binding.work == work,
              binding.planDigest == intent.digest, binding.configurationDigest == configurationDigest,
              binding.networkFingerprint == intent.networkFingerprint else {
            throw RouterTrafficEvidenceError.sourceChanged
        }
        let bindingBytes = try RouterTrafficCodec.encode(binding)
        let bindingDigest = try binding.digest()
        let session = UUID()
        let requirements = try RouterTrafficCoveragePolicy.requirements(plan)
        var records: [RouterTrafficCaseRecord] = []
        var start = first.interval.start
        var end = first.interval.end

        for observation in observations {
            guard observation.source == expectedSource,
                  try RouterTrafficCodec.encode(observation.binding) == bindingBytes else {
                throw RouterTrafficEvidenceError.sourceChanged
            }
            guard try RouterTrafficCorrelator.evaluateOwn(observation, plan: plan, profile: profile).relation ==
                    .candidateUnverified else { continue }
            if observation.interval.start.uptime < start.uptime || observation.interval.start.date < start.date {
                start = observation.interval.start
            }
            if observation.interval.end.uptime > end.uptime || observation.interval.end.date > end.date {
                end = observation.interval.end
            }
            let tuple = observation.socket.tuple
            guard let destination = RouterTrafficAddress.bytes(tuple.peer.address),
                  let sourceAddress = RouterTrafficAddress.bytes(tuple.local.address),
                  sourceAddress.count == destination.count else { continue }
            let target = RouterTrafficProbeTarget(host: tuple.peer.address, port: tuple.peer.port, transport: .tcp)
            let endpointDigest = try target.digest()
            var candidates: [RouterTrafficCaseRecord] = []
            for id in requirements where id.transport == .tcp {
                let familyBytes = id.family == .ipv4 ? 4 : 16
                guard destination.count == familyBytes else { continue }
                let attempt = UUID(), nonce = UUID()
                let transcript = RouterTrafficTranscript(outcome: .incomplete, requestNonce: nonce,
                    endpointDigest: endpointDigest, expectedEgress: nil, reply: nil,
                    rejectControlBefore: nil, rejectControlAfter: nil, gaps: [])
                let record = RouterTrafficCaseRecord(id: id, attempt: attempt, session: session,
                    bindingDigest: bindingDigest, interval: observation.interval, transcript: transcript)
                let facts = RouterTrafficAttemptFacts(id: id, attempt: attempt, session: session,
                    bindingDigest: bindingDigest, nonce: nonce, interval: observation.interval,
                    process: observation.socket.process.identity.work,
                    processPath: observation.socket.process.path,
                    sourceIP: tuple.local.address, sourcePort: tuple.local.port,
                    destinationIP: tuple.peer.address, destinationPort: tuple.peer.port,
                    domain: nil, target: target)
                let correlation = try record.correlate(binding: binding, plan: plan, profile: profile,
                    attempt: facts, snapshotBinding: binding, snapshotInterval: observation.controllerInterval,
                    body: observation.body)
                if correlation.relation == .candidateUnverified { candidates.append(record) }
            }
            guard candidates.count <= 1 else { throw RouterTrafficEvidenceError.invalidReceipt }
            if let record = candidates.first { records.append(record) }
        }

        let receipt = RouterTrafficReceipt(version: 1, coveragePolicy: RouterTrafficCoveragePolicy.version,
            session: session, before: binding, after: binding,
            interval: .init(start: start, end: end), records: records)
        let assessment = try receipt.assess(plan: plan, profile: profile)
        let encoded = try RouterTrafficCodec.encode(receipt)
        return .init(receipt: receipt, assessment: assessment,
                     evidenceDigest: RouterSystemObservation.hash(encoded))
    }
}
