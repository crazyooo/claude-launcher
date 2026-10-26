import Foundation
import Darwin

/// Live root effects share one dispatch owner and command runner with the host.
final class RouterSystemRuntimeEffects {
    typealias Correlation = RouterSystemRuntimeCorrelation
    struct Readers {
        var validate: (RouterSystemJournal) throws -> RouterSystemBaselineSnapshot
        var host: () throws -> RouterSystemWork
        var local: (RouterSystemDispatchFence) -> RouterSystemDispatch.Settlement
        var stop: (RouterSystemDispatchFence) throws -> Void
        var former: (RouterSystemDispatchFence) -> RouterSystemKernelObservation.FormerDispatch
        var exited: (RouterSystemWork) -> RouterSystemKernelObservation.ExitObservation
        var group: (Int32) throws -> [Int32]
        var controller: (RouterSystemJournal, TimeInterval) throws -> Correlation.Controller
        var snapshot: () throws -> RouterSystemBaselineSnapshot
        var route: (RouterSystemSelectedRoute.Family) throws -> RouterSystemSelectedRoute
        var clock: () throws -> RouterSystemClock
        var verifyClaim: (RouterSystemJournal) throws -> Void = { _ in throw RouterSystemError.ownershipUnknown }
        /// Fresh "still clear" observation sampled at stop time: no foreign capture,
        /// no system/application proxy, no VPN, no user core job. Covers the
        /// proxy/VPN surface that route-table diffing cannot see.
        var cleanEnvironment: () throws -> Bool = { throw RouterSystemError.ownershipUnknown }
    }
    private let readers: Readers
    private init(readers: Readers) { self.readers = readers }
    static func fixture(readers: Readers) throws -> RouterSystemRuntimeEffects {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        return .init(readers: readers)
    }
    convenience init(installation: RouterSystemInstallation, journal: RouterSystemJournalStore,
                     baselines: RouterSystemBaselineStore, stage: RouterSystemStage, dispatch: RouterSystemDispatch,
                     command: RouterSystemCommand, capture: @escaping () throws -> RouterSystemBaselineSnapshot) throws {
        try installation.verifyCode()
        self.init(readers: .init(validate: { state in
            try RouterSystemProvider.validateJournal(state)
            guard state.installation == installation.manifest.identity,
                  try journal.load(until: ProcessInfo.processInfo.systemUptime + 2).revision == state.revision,
                  let intent = state.intent, let fence = state.dispatch, let digest = state.configurationDigest else {
                throw RouterSystemError.ownershipUnknown
            }
            try stage.verify(intent, configurationDigest: digest)
            return try baselines.read(intent: intent, fence: fence).snapshot
        }, host: { try RouterSystemKernelObservation.host().work }, local: dispatch.localSettlement,
        stop: dispatch.stop, former: RouterSystemKernelObservation.Reader.live.formerDispatch,
        exited: RouterSystemKernelObservation.Reader.live.exit, group: RouterSystemKernelObservation.groupMembers,
        controller: { state, deadline in
            guard let intent = state.intent, let work = state.work, let fence = state.dispatch,
                  let digest = state.configurationDigest else { throw RouterSystemError.ownershipUnknown }
            try baselines.verifyClaim(intent: intent, fence: fence)
            let secret = try stage.controllerSecret(intent, configurationDigest: digest)
            let before = try RouterSystemKernelObservation.executable(work, expected: [RouterSystemLayout.core])
            guard before.parentPID == fence.host.pid, before.processGroup == fence.processGroup,
                  case .observed(let listener) = try RouterSystemControllerListener.observe(work: work, deadline: deadline) else {
                throw RouterSystemError.ownershipUnknown
            }
            let declaration = try RouterSystemControllerHTTP.declaration(secret: secret, until: deadline)
            guard try RouterSystemControllerListener.observe(work: work, deadline: deadline) == .observed(listener),
                  try RouterSystemKernelObservation.executable(work, expected: [RouterSystemLayout.core]) == before else {
                throw RouterSystemError.ownershipUnknown
            }
            return .init(process: before, listeners: listener, declaration: declaration)
        }, snapshot: capture, route: { try RouterSystemSelectedRoute.collect($0, command: command) },
        clock: RouterSystemKernelObservation.clock, verifyClaim: { state in
            guard let intent = state.intent, let fence = state.dispatch else { throw RouterSystemError.ownershipUnknown }
            try baselines.verifyClaim(intent: intent, fence: fence)
        }, cleanEnvironment: {
            let observation = RouterSystemObservation.collect()
            return observation.complete && observation.tunnelCaptureInterfaces.isEmpty
                && observation.applicationProxyEnabled == false && observation.automaticProxyEnabled == false
                && observation.connectedVPN == false && observation.userCoreJobPresent == false
        }))
    }

    func observe(_ state: RouterSystemJournal) throws -> RouterSystemRuntimeObservation {
        let began = try readers.clock(), baseline = try readers.validate(state)
        guard let intent = state.intent, let fence = state.dispatch, let digest = state.configurationDigest else {
            throw RouterSystemError.ownershipUnknown
        }
        guard let work = state.work else {
            let settled = try settlement(state, fence: fence)
            return .init(instance: intent.id, ownershipConfirmed: true, processAlive: false,
                         controllerHealthy: false, capturePresent: false, footprint: nil,
                         startWorkSettled: settled.dispatchSettled && settled.groupDrained)
        }
        switch readers.exited(work) {
        case .unknown: throw RouterSystemError.ownershipUnknown
        case .exited:
            let settled = try settlement(state, fence: fence)
            return .init(instance: intent.id, ownershipConfirmed: true, processAlive: false,
                         controllerHealthy: false, capturePresent: false, footprint: nil,
                         startWorkSettled: settled.dispatchSettled && settled.groupDrained)
        case .sameProcess: break
        }
        let deadline = began.uptime + 45
        let first = try readers.controller(state, min(deadline, try readers.clock().uptime + 3))
        let snapshot = try readers.snapshot()
        let v4 = try readers.route(.ipv4)
        let v6 = first.declaration.tunIPv6Configured ? try readers.route(.ipv6) : nil
        let second = try readers.controller(state, min(deadline, try readers.clock().uptime + 3))
        let lastSnapshot = try readers.snapshot()
        guard try snapshot.sameStartEnvironment(as: lastSnapshot),
              try readers.route(.ipv4) == v4,
              try !first.declaration.tunIPv6Configured || readers.route(.ipv6) == v6 else { throw RouterSystemError.networkConflict }
        let last = try readers.controller(state, min(deadline, try readers.clock().uptime + 3))
        guard second == last else { throw RouterSystemError.ownershipUnknown }
        let footprint = try Correlation.capture(instance: intent.id, work: work, digest: digest,
            baseline: baseline, current: lastSnapshot, first: first, second: last, ipv4: v4, ipv6: v6)
        _ = try readers.validate(state)
        try finish(began, deadline: deadline, sampled: lastSnapshot.captured)
        return .init(instance: intent.id, ownershipConfirmed: true, processAlive: true,
                     controllerHealthy: true, capturePresent: true, footprint: footprint,
                     startWorkSettled: true, ipv6CaptureObserved: first.declaration.tunIPv6Configured)
    }

    func stop(_ state: RouterSystemJournal) throws {
        _ = try readers.validate(state)
        guard let fence = state.dispatch else { throw RouterSystemError.ownershipUnknown }
        if try readers.host() == fence.host { try readers.stop(fence) }
        else {
            let settled = try settlement(state, fence: fence)
            guard settled.dispatchSettled, settled.processExited, settled.groupDrained else { throw RouterSystemError.operationUnsettled }
        }
    }
    func cleanup(_ state: RouterSystemJournal) throws -> RouterSystemCleanupProof {
        let began = try readers.clock(), baseline = try readers.validate(state)
        guard let intent = state.intent, let fence = state.dispatch else { throw RouterSystemError.ownershipUnknown }
        // status on a stopping record must continue draining a locally retained owner.
        if try readers.host() == fence.host { try readers.stop(fence) }
        let first = try settlement(state, fence: fence)
        let current = try readers.snapshot()
        let second = try settlement(state, fence: fence)
        _ = try readers.validate(state)
        try finish(began, deadline: began.uptime + 45, sampled: current.captured)
        return try Correlation.cleanup(instance: intent.id, dispatch: fence, footprint: state.footprint,
            baseline: baseline, current: current, first: first, second: second,
            cleanEnvironment: try sampleCleanEnvironment())
    }

    /// Unlike cleanup(), this never signals or drains work. Unknown ownership cannot be acknowledged away.
    func baselineCandidate(_ state: RouterSystemJournal) throws -> RouterSystemEnvironmentCandidate {
        let began = try readers.clock(), baseline = try readers.validate(state)
        guard state.phase == .stopping, let intent = state.intent, let fence = state.dispatch,
              let footprint = state.footprint, footprint.work == state.work,
              footprint.instance == intent.id, footprint.configurationDigest == state.configurationDigest else {
            throw RouterSystemError.cleanupUnproven
        }
        try readers.verifyClaim(state)
        let first = try settlement(state, fence: fence)
        let a = try readers.snapshot(), b = try readers.snapshot()
        guard a.captured.bootID == began.bootID, a.captured.uptime >= began.uptime, a.captured.date >= began.date,
              try a.sameStartEnvironment(as: b), b.captured.uptime >= a.captured.uptime,
              b.captured.date >= a.captured.date else { throw RouterSystemError.networkConflict }
        let second = try settlement(state, fence: fence)
        let proof = try Correlation.cleanup(instance: intent.id, dispatch: fence, footprint: footprint,
            baseline: baseline, current: b, first: first, second: second,
            cleanEnvironment: try sampleCleanEnvironment())
        _ = try readers.validate(state)
        try readers.verifyClaim(state)
        try finish(began, deadline: began.uptime + 45, sampled: b.captured)
        let result = try RouterSystemEnvironmentCandidate(sampled: b.captured, fingerprint: b.environmentDigest(),
            changes: b.changes(from: baseline), proof: proof)
        try RouterSystemEnvironmentTransition.requireOwned(result, state: state)
        return result
    }

    /// Archival does not authorize replacing the original journal unless its immutable sources
    /// still verify on both sides of the durable write.
    func archiveEnvironment(_ state: RouterSystemJournal, archive: (RouterSystemJournal) throws -> Void) throws {
        _ = try readers.validate(state)
        try readers.verifyClaim(state)
        try archive(state)
        _ = try readers.validate(state)
        try readers.verifyClaim(state)
    }

    /// Re-sample stop-time clear observation with a short bound. A single
    /// `RouterSystemObservation.collect` can return incomplete/false on machines
    /// with second-scale route-table jitter even when capture/proxy/VPN are clear
    /// (live evidence 2026-10-25: stop stuck while OBS capture=[]). Retries never
    /// invent a clear window — every sample must independently pass.
    static let cleanEnvironmentAttempts = 5
    static let cleanEnvironmentInterval: TimeInterval = 0.2

    static func awaitCleanEnvironment(attempts: Int = cleanEnvironmentAttempts,
                                      interval: TimeInterval = cleanEnvironmentInterval,
                                      sample: () throws -> Bool) throws -> Bool {
        guard attempts > 0, attempts <= 16, interval >= 0, interval <= 2, interval.isFinite else {
            throw RouterSystemError.operationUnsettled
        }
        var last = false
        for index in 0..<attempts {
            last = try sample()
            if last { return true }
            if index + 1 < attempts { Thread.sleep(forTimeInterval: interval) }
        }
        return last
    }

    private func sampleCleanEnvironment() throws -> Bool {
        try Self.awaitCleanEnvironment(sample: readers.cleanEnvironment)
    }

    private func settlement(_ state: RouterSystemJournal, fence: RouterSystemDispatchFence) throws -> Correlation.Settlement {
        let host = try readers.host()
        let settled: Bool, groupDrained: Bool
        if host == fence.host {
            settled = [.neverDispatched, .neverSpawned, .exited].contains(readers.local(fence))
            if settled {
                let a = try readers.group(fence.processGroup), b = try readers.group(fence.processGroup)
                let after = try readers.host()
                groupDrained = a == [host.pid] && b == [host.pid] && after == host
            } else { groupDrained = false }
        } else {
            switch readers.former(fence) {
            case .formerBootEnded, .formerHostGroupEmpty: settled = true; groupDrained = true
            case .unknown, .unsettled: settled = false; groupDrained = false
            }
        }
        return .init(dispatchSettled: settled, processExited: state.work.map { readers.exited($0) == .exited } ?? settled,
                     groupDrained: groupDrained)
    }
    private func finish(_ began: RouterSystemClock, deadline: TimeInterval, sampled: RouterSystemClock) throws {
        let now = try readers.clock()
        guard [began, sampled, now].allSatisfy({ $0.uptime.isFinite && $0.uptime >= 0 && $0.date.timeIntervalSince1970.isFinite }),
              deadline.isFinite, now.bootID == began.bootID, sampled.bootID == began.bootID,
              now.uptime >= sampled.uptime, sampled.uptime >= began.uptime, now.uptime < deadline,
              now.date >= sampled.date, sampled.date >= began.date else { throw RouterSystemError.operationUnsettled }
    }
}
