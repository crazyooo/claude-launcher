import XCTest
@testable import RoutingCore

final class RouterSystemProviderTests: XCTestCase {
    private final class Rig {
        var journal = RouterSystemJournal.empty()
        var clock = RouterSystemClock(bootID: UUID(), uptime: 100, date: Date(timeIntervalSince1970: 1000))
        var fingerprint = String(repeating: "a", count: 64)
        var proxyEnabled = false
        var starts = 0, stops = 0, stages = 0, grants = 0, observations = 0, saves = 0
        var failSaveAt: Int?, writeBeforeFailure = false
        var healthy = true, capture = true, settled = true, clean = true, owned = true
        var startFailsAfterGrant = false, cleanupID: UUID?
        var stageHook: (() throws -> Void)?
        var startHook: (() throws -> Void)?
        var baselineHook: (() throws -> Void)?
        var afterSave: ((RouterSystemJournal) -> Void)?
        var reservations = 0
        var omitCleanupFence = false
        var cleanupFenceOverride: RouterSystemDispatchFence?
        let configDigest = String(repeating: "b", count: 64)
        var plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        func effects() -> RouterSystemEffects {
            .init(clock: { self.clock }, load: { self.journal }, save: { next, revision in
                XCTAssertEqual(revision, self.journal.revision)
                self.saves += 1
                if self.saves == self.failSaveAt {
                    if self.writeBeforeFailure { self.journal = next }
                    throw RouterSystemError.journalUnknown
                }
                self.journal = next
                self.afterSave?(next)
            }, network: {
                .init(checkedAt: self.clock.date, fingerprint: self.fingerprint, complete: true,
                    defaultIPv4Interfaces: ["en0"], defaultIPv6Interfaces: [], tunnelCaptureInterfaces: [],
                    scopedTunnelInterfaces: [], applicationProxyEnabled: self.proxyEnabled, automaticProxyEnabled: false,
                    connectedVPN: false, userCoreJobPresent: false, unknowns: [])
            }, stage: { _, _ in
                self.stages += 1; try self.stageHook?(); return self.configDigest
            }, prepareDispatch: { intent, digest in
                self.reservations += 1
                let fence = RouterSystemDispatchFence(instance: intent.id,
                    host: .init(bootID: self.clock.bootID, pid: 700, birthSeconds: 90, birthMicroseconds: 0),
                    processGroup: 700, gateDeadlineUptime: intent.deadlineUptime, gateExpiresAt: intent.expiresAt,
                    baselineID: UUID(), baselineDigest: String(repeating: "d", count: 64),
                    networkFingerprint: self.fingerprint, configurationDigest: digest)
                try self.baselineHook?()
                return fence
            }, start: { intent, digest, fence, record in
                self.starts += 1
                XCTAssertEqual(self.journal.phase, .applying)
                XCTAssertEqual(self.journal.dispatch, fence)
                XCTAssertEqual(fence.instance, intent.id)
                XCTAssertEqual(fence.configurationDigest, digest)
                XCTAssertNil(self.journal.work)
                try self.startHook?()
                try record(.init(bootID: self.clock.bootID, pid: 1234, birthSeconds: 100, birthMicroseconds: 12))
                XCTAssertNotNil(self.journal.work)
                self.grants += 1
                if self.startFailsAfterGrant { throw RouterSystemError.operationUnsettled }
            }, observe: { state in
                self.observations += 1
                let footprint = state.work.map { work in
                    RouterSystemFootprint(instance: state.intent!.id, work: work, configurationDigest: self.configDigest,
                        interfaceName: "utun9", interfaceIndex: 12, addresses: ["198.18.0.1"], routeSignatures: ["route-test"])
                }
                return .init(instance: state.intent!.id, ownershipConfirmed: self.owned, processAlive: state.work != nil,
                    controllerHealthy: self.healthy, capturePresent: self.capture, footprint: footprint, startWorkSettled: self.settled)
            }, stop: { _ in self.stops += 1 }, cleanup: { state in
                .init(instance: self.cleanupID ?? state.intent!.id,
                    dispatch: self.omitCleanupFence ? nil : (self.cleanupFenceOverride ?? state.dispatch), startWorkSettled: self.settled, processExited: self.clean,
                    interfaceAbsent: self.clean, routesAbsent: self.clean, externalStatePreserved: self.clean)
            })
        }
        func prepare(_ provider: RouterSystemProvider, id: UUID = UUID()) throws -> UUID {
            _ = try provider.handle(.prepare(id: id, plan: plan, profile: profile)); return id
        }
        func advance(_ seconds: Double) {
            clock = .init(bootID: clock.bootID, uptime: clock.uptime + seconds, date: clock.date.addingTimeInterval(seconds))
        }
    }
    private func fails(_ expected: RouterSystemError, _ operation: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try operation(), file: file, line: line) { XCTAssertEqual($0 as? RouterSystemError, expected, file: file, line: line) }
    }

    func testPreparedIdentityCannotBeRepurposedOrRenewed() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects())
        let id = try rig.prepare(provider), original = rig.journal.intent!.expiresAt
        rig.advance(30); _ = try rig.prepare(provider, id: id)
        XCTAssertEqual(rig.journal.intent!.expiresAt, original)
        rig.plan.defaultDestination = .block
        fails(.conflict) { _ = try rig.prepare(provider, id: id) }
        XCTAssertEqual(rig.starts, 0)
    }
    func testApplyPersistsIdentityBeforeGrantAndReplayNeverStartsAgain() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        let result = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(result.phase, "active"); XCTAssertEqual(rig.grants, 1)
        _ = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.starts, 1); XCTAssertNil(rig.journal.accepted); XCTAssertNil(rig.journal.previousAccepted)
        XCTAssertFalse(result.routingVerified); XCTAssertFalse(result.protectionVerified); XCTAssertFalse(result.launchAuthorized)
    }
    func testSealedCollectorPersistsAcceptedAndRotatesOnlyOnNewEvidence() throws {
        let rig = Rig()
        var evidence = String(repeating: "e", count: 64)
        var sealed = true
        var effects = rig.effects()
        effects.collectAcceptance = { state in
            XCTAssertEqual(state.phase, .active)
            XCTAssertEqual(rig.journal.phase, .active) // Active is durable before collection begins.
            let intent = try XCTUnwrap(state.intent)
            if sealed {
                return .unitTestComplete(evidenceDigest: evidence, planDigest: intent.digest,
                                         configurationDigest: intent.digest)
            }
            return .fromLiveAssessment(planDigest: intent.digest, configurationDigest: intent.digest,
                                       evidenceDigest: evidence,
                                       assessment: RouterTrafficAssessment(cases: [], controlPlane: []))
        }
        let provider = RouterSystemProvider(effects: effects)
        let id = try rig.prepare(provider)
        let result = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.journal.accepted?.acceptanceEvidenceDigest, evidence)
        XCTAssertNil(rig.journal.previousAccepted)
        XCTAssertFalse(result.routingVerified)
        XCTAssertFalse(result.protectionVerified)
        XCTAssertFalse(result.launchAuthorized)

        let firstEvidence = evidence
        evidence = String(repeating: "f", count: 64)
        _ = try provider.handle(.status(id: id))
        XCTAssertEqual(rig.journal.accepted?.acceptanceEvidenceDigest, evidence)
        XCTAssertEqual(rig.journal.previousAccepted?.acceptanceEvidenceDigest, firstEvidence)

        let savesBeforeRetry = rig.saves
        let acceptedBeforeRetry = rig.journal.accepted
        let previousBeforeRetry = rig.journal.previousAccepted
        _ = try provider.handle(.status(id: id))
        XCTAssertEqual(rig.saves, savesBeforeRetry + 1) // Only the normal active observation is saved.
        XCTAssertEqual(rig.journal.accepted, acceptedBeforeRetry)
        XCTAssertEqual(rig.journal.previousAccepted, previousBeforeRetry)

        sealed = false
        _ = try provider.handle(.status(id: id))
        XCTAssertEqual(rig.journal.accepted, acceptedBeforeRetry)
        XCTAssertEqual(rig.journal.previousAccepted, previousBeforeRetry)
    }

    func testAcceptanceCollectorRunsOnlyAfterCompleteActiveObservation() throws {
        let rig = Rig()
        rig.capture = false
        var collectionCalls = 0
        var effects = rig.effects()
        effects.collectAcceptance = { _ in
            collectionCalls += 1
            return nil
        }
        let provider = RouterSystemProvider(effects: effects)
        let id = try rig.prepare(provider)
        let result = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(result.phase, "fault")
        XCTAssertEqual(collectionCalls, 0)
        XCTAssertNil(rig.journal.accepted)
        XCTAssertNil(rig.journal.previousAccepted)
    }

    func testUnknownAcceptedSaveSettlesWithoutDuplicateRotation() throws {
        for written in [false, true] {
            let rig = Rig()
            let evidence = String(repeating: "e", count: 64)
            var effects = rig.effects()
            effects.collectAcceptance = { state in
                let intent = try XCTUnwrap(state.intent)
                return .unitTestComplete(evidenceDigest: evidence, planDigest: intent.digest,
                                         configurationDigest: intent.digest)
            }
            let provider = RouterSystemProvider(effects: effects)
            let id = try rig.prepare(provider)
            rig.failSaveAt = 5 // prepare, applying, work, active, then accepted
            rig.writeBeforeFailure = written
            fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
            rig.failSaveAt = nil

            _ = try provider.handle(.status(id: id))
            XCTAssertEqual(rig.journal.accepted?.acceptanceEvidenceDigest, evidence)
            XCTAssertNil(rig.journal.previousAccepted)
            XCTAssertEqual(rig.saves, written ? 6 : 7)

            _ = try provider.handle(.status(id: id))
            XCTAssertEqual(rig.journal.accepted?.acceptanceEvidenceDigest, evidence)
            XCTAssertNil(rig.journal.previousAccepted)
            XCTAssertEqual(rig.saves, written ? 7 : 8)
        }
    }

    func testUnknownStartAfterGrantIsOnlyObservedAfterRestart() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        rig.startFailsAfterGrant = true
        fails(.operationUnsettled) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        let restarted = RouterSystemProvider(effects: rig.effects())
        _ = try restarted.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.starts, 1); XCTAssertEqual(rig.grants, 1)
    }
    func testBootChangeRollbackAndExactDeadlineRejectWithoutStart() throws {
        for variant in 0..<4 {
            let rig = Rig(), provider: RouterSystemProvider
            provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
            switch variant {
            case 0: rig.advance(60)
            case 1: rig.advance(-1)
            case 2: rig.clock = .init(bootID: UUID(), uptime: 101, date: rig.clock.date)
            default: rig.clock = .init(bootID: rig.clock.bootID, uptime: 101, date: rig.clock.date.addingTimeInterval(-1))
            }
            fails(.stalePreview) { _ = try provider.handle(.apply(id: id, credentials: [])) }
            XCTAssertEqual(rig.starts, 0)
        }
    }
    func testStageTimeAndNetworkChangesInvalidateBeforeExecution() throws {
        for variant in 0..<3 {
            let rig = Rig(), provider: RouterSystemProvider
            provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
            rig.stageHook = {
                if variant == 0 { rig.advance(60) }
                if variant == 1 { rig.fingerprint = String(repeating: "c", count: 64) }
                if variant == 2 { rig.proxyEnabled = true }
            }
            fails(variant == 0 ? .stalePreview : .networkConflict) { _ = try provider.handle(.apply(id: id, credentials: [])) }
            XCTAssertEqual(rig.starts, 0); XCTAssertNil(rig.journal.work)
        }
    }
    func testUncertainWritesNeverGrantAndRequireStatusBeforeRetry() throws {
        // 2=applying save, 3=work save. Both pre-rename and post-rename failures.
        for point in [2, 3] { for written in [false, true] {
            let rig = Rig(), provider: RouterSystemProvider
            provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
            rig.failSaveAt = point; rig.writeBeforeFailure = written
            fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
            XCTAssertEqual(rig.grants, 0)
            fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
            rig.failSaveAt = nil
            _ = try provider.handle(.status(id: id))
            if rig.journal.phase != .prepared {
                _ = try provider.handle(.apply(id: id, credentials: []))
                XCTAssertEqual(rig.starts, point == 3 ? 1 : 0)
                XCTAssertEqual(rig.grants, 0)
            }
        } }
    }
    func testHealthyControllerWithoutCaptureOrSettledWorkCannotBecomeActive() throws {
        for missingCapture in [false, true] {
            let rig = Rig(), provider: RouterSystemProvider
            provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
            if missingCapture { rig.capture = false } else { rig.settled = false }
            let result = try provider.handle(.apply(id: id, credentials: []))
            XCTAssertEqual(result.phase, "fault"); XCTAssertNil(rig.journal.accepted)
        }
    }
    func testStopRequiresBoundCompleteProofAndExplicitRetrySurvivesRestart() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        _ = try provider.handle(.apply(id: id, credentials: []))
        fails(.conflict) { _ = try provider.handle(.stop(id: UUID())) }
        rig.clean = false
        fails(.cleanupUnproven) { _ = try provider.handle(.stop(id: id)) }
        XCTAssertEqual(rig.journal.phase, .stopping)
        let restarted = RouterSystemProvider(effects: rig.effects())
        fails(.cleanupUnproven) { _ = try restarted.handle(.status(id: id)) }
        XCTAssertEqual(rig.stops, 1) // Queries do not send stop again.
        rig.clean = true; rig.cleanupID = UUID()
        fails(.cleanupUnproven) { _ = try restarted.handle(.stop(id: id)) }
        rig.cleanupID = id
        XCTAssertTrue(try restarted.handle(.stop(id: id)).cleanupConfirmed)
        XCTAssertEqual(rig.stops, 3)
    }
    func testCrashAfterStoppingSaveDoesNotPretendStopWasSent() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        _ = try provider.handle(.apply(id: id, credentials: []))
        rig.failSaveAt = rig.saves + 1; rig.writeBeforeFailure = true; rig.clean = false
        fails(.journalUnknown) { _ = try provider.handle(.stop(id: id)) }
        XCTAssertEqual(rig.stops, 0)
        rig.failSaveAt = nil; rig.clean = true
        XCTAssertTrue(try RouterSystemProvider(effects: rig.effects()).handle(.stop(id: id)).cleanupConfirmed)
        XCTAssertEqual(rig.stops, 1)
    }
    func testReentrantMutationRejectedWithoutDeadlock() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        rig.stageHook = { self.fails(.operationUnsettled) { _ = try provider.handle(.stop(id: id)) } }
        _ = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.starts, 1)
    }
    func testCancelUnusedPreviewDoesNotCallStopOrAllowLaterApply() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        _ = try provider.handle(.stop(id: id)); _ = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.starts, 0); XCTAssertEqual(rig.stops, 0)
    }
    func testCredentialsMustMatchReferencesExactlyBeforeStaging() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let reference = UUID()
        rig.plan.proxies = [.init(id: UUID(), name: "Example", kind: .http, host: "127.0.0.1", port: 1082, credentialReference: reference)]
        let id = try rig.prepare(provider), value = RouterCredential(username: "private-user", password: "private-pass")
        for credentials: [RouterSystemCredential] in [[], [.init(reference: UUID(), value: value)],
                                                     [.init(reference: reference, value: value), .init(reference: reference, value: value)]] {
            fails(.invalidCredentials) { _ = try provider.handle(.apply(id: id, credentials: credentials)) }
        }
        XCTAssertEqual(rig.stages, 0)
        let output = String(decoding: try JSONEncoder().encode(provider.handle(.status(id: id))), as: UTF8.self)
        XCTAssertFalse(output.contains("private-"))
    }
    func testWrongInstanceCannotPopulatePublicEvidence() throws {
        let rig = Rig() // Projection must defend itself outside the provider call site.
        let own = RouterSystemProvider(effects: rig.effects())
        _ = try rig.prepare(own)
        let result = RouterSystemStatus(rig.journal, observation: .init(instance: UUID(), ownershipConfirmed: true,
            processAlive: true, controllerHealthy: true, capturePresent: true, footprint: nil, startWorkSettled: true))
        XCTAssertFalse(result.processObserved); XCTAssertFalse(result.controllerHealthy); XCTAssertFalse(result.captureObserved)
    }
    func testDamagedActiveJournalRejectedBeforeObservation() throws {
        let rig = Rig(), provider: RouterSystemProvider
        provider = .init(effects: rig.effects()); let id = try rig.prepare(provider)
        rig.journal.phase = .active
        fails(.journalUnknown) { _ = try provider.handle(.status(id: id)) }
        XCTAssertEqual(rig.observations, 0)
    }
    func testApplyingSaveUnknownDoesNotSpawnAndLocalStopNeedsFence() throws {
        let rig = Rig()
        let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        rig.failSaveAt = 2; rig.writeBeforeFailure = true
        fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        XCTAssertNotNil(rig.journal.dispatch); XCTAssertNil(rig.journal.work); XCTAssertEqual(rig.starts, 0)
        rig.failSaveAt = nil
        _ = try provider.handle(.status(id: id))
        rig.omitCleanupFence = true
        fails(.cleanupUnproven) { _ = try provider.handle(.stop(id: id)) }
        rig.omitCleanupFence = false
        XCTAssertTrue(try provider.handle(.status(id: id)).cleanupConfirmed)
    }
    func testMissingWorkAfterRestartDoesNotProveSpawnAbsent() throws {
        let rig = Rig(); let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        rig.failSaveAt = 2; rig.writeBeforeFailure = true
        fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        rig.failSaveAt = nil; rig.settled = false
        let restarted = RouterSystemProvider(effects: rig.effects())
        fails(.cleanupUnproven) { _ = try restarted.handle(.stop(id: id)) }
        XCTAssertNil(rig.journal.work); XCTAssertEqual(rig.starts, 0)
        rig.settled = true // Inject independently proven host/group termination, not missing journal data.
        XCTAssertTrue(try restarted.handle(.status(id: id)).cleanupConfirmed)
        XCTAssertEqual(rig.starts, 0); XCTAssertEqual(rig.stops, 1)
    }
    func testPendingGateWithMissingWorkCannotBeClearedWithoutSettling() throws {
        let rig = Rig(); let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        rig.failSaveAt = 3; rig.settled = false
        fails(.journalUnknown) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        XCTAssertEqual(rig.starts, 1); XCTAssertNil(rig.journal.work); XCTAssertEqual(rig.grants, 0)
        rig.failSaveAt = nil; _ = try provider.handle(.status(id: id))
        fails(.cleanupUnproven) { _ = try provider.handle(.stop(id: id)) }
        rig.settled = true // Represents original child owner waitpid evidence.
        XCTAssertTrue(try provider.handle(.status(id: id)).cleanupConfirmed)
        XCTAssertEqual(rig.grants, 0)
    }
    func testBaselineNetworkFailureBeforeApplyingCanRetry() throws {
        let rig = Rig(); let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        rig.baselineHook = { rig.proxyEnabled = true }
        fails(.networkConflict) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        XCTAssertEqual(rig.journal.phase, .prepared); XCTAssertNil(rig.journal.dispatch); XCTAssertEqual(rig.starts, 0)
        rig.baselineHook = nil; rig.proxyEnabled = false
        _ = try provider.handle(.apply(id: id, credentials: []))
        XCTAssertEqual(rig.reservations, 2); XCTAssertEqual(rig.starts, 1)
    }
    func testExpiryDuringWorkSaveDoesNotReleaseGate() throws {
        let rig = Rig(); let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        rig.afterSave = { state in if state.phase == .applying && state.work != nil { rig.advance(60) } }
        fails(.stalePreview) { _ = try provider.handle(.apply(id: id, credentials: [])) }
        XCTAssertNotNil(rig.journal.work); XCTAssertNotNil(rig.journal.dispatch); XCTAssertEqual(rig.grants, 0)
    }
    func testCleanupRejectsDifferentDispatchEvenWithSameInstance() throws {
        let rig = Rig(); let provider = RouterSystemProvider(effects: rig.effects()), id = try rig.prepare(provider)
        _ = try provider.handle(.apply(id: id, credentials: []))
        let fence = try XCTUnwrap(rig.journal.dispatch)
        rig.cleanupFenceOverride = .init(instance: id, host: fence.host, processGroup: fence.processGroup,
            gateDeadlineUptime: fence.gateDeadlineUptime, gateExpiresAt: fence.gateExpiresAt,
            baselineID: UUID(), baselineDigest: fence.baselineDigest,
            networkFingerprint: fence.networkFingerprint, configurationDigest: fence.configurationDigest)
        fails(.cleanupUnproven) { _ = try provider.handle(.stop(id: id)) }
    }

}
