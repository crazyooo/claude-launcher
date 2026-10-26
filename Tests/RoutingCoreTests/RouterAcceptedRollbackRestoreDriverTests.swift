import XCTest
@testable import RoutingCore

/// Offline gate tests for the production rollback TUN restore driver.
/// Live mutation stays behind the conversation clear window (#task: live 实改须清场确认).
final class RouterAcceptedRollbackRestoreDriverTests: XCTestCase {
    private final class Rig {
        var journal = RouterSystemJournal.empty()
        var clock = RouterSystemClock(bootID: UUID(), uptime: 100, date: Date(timeIntervalSince1970: 1000))
        var fingerprint = String(repeating: "a", count: 64)
        var starts = 0, stops = 0, stages = 0
        var healthy = true, capture = true, settled = true, clean = true, owned = true
        var lastStageValues: [UUID: RouterCredential]?
        var credentialReads: [UUID] = []
        var credentialResult: Result<RouterCredential, Error> = .success(.init(username: "u", password: "p"))
        var plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let configDigest = String(repeating: "b", count: 64)

        func effects() -> RouterSystemEffects {
            .init(clock: { self.clock }, load: { self.journal }, save: { journal, _ in
                self.journal = journal
            }, network: {
                .init(checkedAt: self.clock.date, fingerprint: self.fingerprint, complete: true,
                    defaultIPv4Interfaces: ["en0"], defaultIPv6Interfaces: [], tunnelCaptureInterfaces: [],
                    scopedTunnelInterfaces: [], applicationProxyEnabled: false, automaticProxyEnabled: false,
                    connectedVPN: false, userCoreJobPresent: false, unknowns: [])
            }, stage: { _, values in
                self.stages += 1
                self.lastStageValues = values
                return self.configDigest
            }, prepareDispatch: { intent, digest in
                .init(instance: intent.id,
                    host: .init(bootID: self.clock.bootID, pid: 700, birthSeconds: 90, birthMicroseconds: 0),
                    processGroup: 700, gateDeadlineUptime: intent.deadlineUptime, gateExpiresAt: intent.expiresAt,
                    baselineID: UUID(), baselineDigest: String(repeating: "d", count: 64),
                    networkFingerprint: self.fingerprint, configurationDigest: digest)
            }, start: { intent, digest, fence, record in
                self.starts += 1
                XCTAssertEqual(self.journal.phase, .applying)
                XCTAssertEqual(self.journal.dispatch, fence)
                XCTAssertEqual(fence.instance, intent.id)
                XCTAssertEqual(fence.configurationDigest, digest)
                try record(.init(bootID: self.clock.bootID, pid: 1234, birthSeconds: 100, birthMicroseconds: 12))
            }, observe: { state in
                let footprint = state.work.map { work in
                    RouterSystemFootprint(instance: state.intent!.id, work: work, configurationDigest: self.configDigest,
                        interfaceName: "utun9", interfaceIndex: 12, addresses: ["198.18.0.1"], routeSignatures: ["route-test"])
                }
                return .init(instance: state.intent!.id, ownershipConfirmed: self.owned, processAlive: state.work != nil,
                    controllerHealthy: self.healthy, capturePresent: self.capture, footprint: footprint, startWorkSettled: self.settled)
            }, stop: { _ in self.stops += 1 }, cleanup: { state in
                .init(instance: state.intent!.id, dispatch: state.dispatch, startWorkSettled: self.settled,
                    processExited: self.clean, interfaceAbsent: self.clean, routesAbsent: self.clean,
                    externalStatePreserved: self.clean)
            })
        }
        func advance(_ seconds: Double) {
            clock = .init(bootID: clock.bootID, uptime: clock.uptime + seconds, date: clock.date.addingTimeInterval(seconds))
        }
        func credentialDependency() -> (UUID) throws -> RouterCredential {
            { reference in
                self.credentialReads.append(reference)
                return try self.credentialResult.get()
            }
        }
    }

    let profile = RouterSystemProfile(resolver: .cloudflare)
    let evidence = String(repeating: "e", count: 64)

    func planA(reference: UUID? = nil) -> RouterPlan {
        .init(proxies: reference.map {
            [.init(id: $0, name: "line", kind: .socks5, host: "192.0.2.10", port: 1080, credentialReference: $0)]
        } ?? [], rules: [], defaultDestination: .direct)
    }

    /// Two promoted runs so previousAccepted(planA) sits behind accepted(planB).
    /// Returns the restarted provider (collector disabled) plus the rig.
    private func rigWithRotatedSeal(planA: RouterPlan) throws -> (Rig, RouterSystemProvider, RouterAcceptedRollback.Preview) {
        let rig = Rig()
        var effects = rig.effects()
        effects.collectAcceptance = { state in
            .unitTestComplete(evidenceDigest: self.evidence, planDigest: state.intent!.digest,
                              configurationDigest: state.intent!.digest)
        }
        let credentialsFor: (RouterPlan) -> [RouterSystemCredential] = { plan in
            plan.proxies.compactMap(\.credentialReference).map {
                .init(reference: $0, value: RouterCredential(username: "u", password: "p"))
            }
        }
        rig.plan = planA
        let first = RouterSystemProvider(effects: effects)
        _ = try first.handle(.prepare(id: UUID(), plan: planA, profile: profile))
        _ = try first.handle(.apply(id: rig.journal.intent!.id,
                                    credentials: credentialsFor(planA)))
        XCTAssertEqual(rig.journal.accepted?.plan, planA)

        rig.advance(5)
        let planB = RouterPlan(proxies: [], rules: [], defaultDestination: .block)
        _ = try first.handle(.stop(id: rig.journal.intent!.id))
        _ = try first.handle(.prepare(id: UUID(), plan: planB, profile: profile))
        _ = try first.handle(.apply(id: rig.journal.intent!.id,
                                    credentials: credentialsFor(planB)))
        XCTAssertEqual(rig.journal.accepted?.plan, planB)
        XCTAssertEqual(rig.journal.previousAccepted?.plan, planA)

        // Restarted provider: production default (no collector) over the same journal.
        let provider = RouterSystemProvider(effects: rig.effects())
        let previous = try XCTUnwrap(provider.snapshot().previousAccepted)
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: previous.plan, profile: previous.profile,
            configurationDigest: previous.configurationDigest,
            evidenceDigest: previous.acceptanceEvidenceDigest)
        return (rig, provider, preview)
    }

    private func dependencies(_ rig: Rig, provider: RouterSystemProvider,
                      newID: @autoclosure @escaping () -> UUID = UUID())
        -> RouterAcceptedRollbackRestoreDriver.Dependencies {
        .init(snapshot: { try provider.snapshot() },
              handle: { try provider.handle($0) },
              credential: rig.credentialDependency(),
              newInstanceID: newID)
    }

    func testRestoreRunsFreshInstanceFromRotatedSealAndLeavesPointersUntouched() throws {
        let (rig, provider, preview) = try rigWithRotatedSeal(planA: planA())
        let newID = UUID()
        let outcome = try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider, newID: newID))
        XCTAssertTrue(outcome.networkModified)
        XCTAssertTrue(outcome.detail.contains("历史 digest 未当作新成功"))
        XCTAssertEqual(rig.starts, 3)
        XCTAssertEqual(rig.journal.intent?.id, newID)
        XCTAssertEqual(rig.journal.intent?.plan, preview.plan)
        XCTAssertEqual(rig.journal.phase, .active)
        // The driver never rewrites sealed pointers.
        XCTAssertEqual(rig.journal.accepted?.plan, .init(proxies: [], rules: [], defaultDestination: .block))
        XCTAssertEqual(rig.journal.previousAccepted?.plan, preview.plan)
        XCTAssertEqual(rig.journal.accepted?.acceptanceEvidenceDigest, evidence)
    }

    func testRestoreStopsRunningInstanceThenRestoresPreviousPlan() throws {
        let rig = Rig()
        rig.plan = .init(proxies: [], rules: [], defaultDestination: .block)
        let planB = rig.plan
        let provider = RouterSystemProvider(effects: rig.effects())
        _ = try provider.handle(.prepare(id: UUID(), plan: planB, profile: profile))
        _ = try provider.handle(.apply(id: rig.journal.intent!.id, credentials: []))
        XCTAssertEqual(rig.journal.phase, .active)

        // Inject a sealed previousAccepted(planA) directly into the journal history.
        let planA = planA()
        rig.advance(1)
        rig.journal.previousAccepted = RouterAcceptedConfiguration(
            plan: planA, profile: profile,
            configurationDigest: try RouterSystemProvider.digest(plan: planA, profile: profile),
            acceptanceEvidenceDigest: evidence)
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: planA, profile: profile,
            configurationDigest: rig.journal.previousAccepted!.configurationDigest,
            evidenceDigest: evidence)

        let newID = UUID()
        let outcome = try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider, newID: newID))
        XCTAssertTrue(outcome.networkModified)
        XCTAssertEqual(rig.stops, 1)
        XCTAssertEqual(rig.starts, 2)
        XCTAssertEqual(rig.journal.intent?.id, newID)
        XCTAssertEqual(rig.journal.intent?.plan, planA)
        XCTAssertEqual(rig.journal.phase, .active)
        XCTAssertNil(rig.journal.accepted) // collector nil: no acceptance claim anywhere
    }

    func testRestoreResolvesCredentialsPerReferenceAtApplyTime() throws {
        let reference = UUID()
        let (rig, provider, preview) = try rigWithRotatedSeal(planA: planA(reference: reference))
        _ = try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider))
        XCTAssertEqual(rig.credentialReads, [reference])
        XCTAssertEqual(rig.lastStageValues?.keys.first, reference)
        XCTAssertEqual(rig.lastStageValues?.count, 1)
        XCTAssertEqual(rig.journal.intent?.plan, planA(reference: reference))
    }

    func testRestoreCredentialFailurePropagatesWithoutNewStart() throws {
        let reference = UUID()
        let (rig, provider, preview) = try rigWithRotatedSeal(planA: planA(reference: reference))
        let stagesBefore = rig.stages
        rig.credentialResult = .failure(RouterCredentialError.unavailable)
        XCTAssertThrowsError(try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider)))
        XCTAssertEqual(rig.stages, stagesBefore)
        XCTAssertEqual(rig.starts, 2)
        XCTAssertEqual(rig.journal.accepted?.plan, .init(proxies: [], rules: [], defaultDestination: .block))
    }

    func testRestoreRefusesWhenSealedPointerMissing() throws {
        let rig = Rig()
        let provider = RouterSystemProvider(effects: rig.effects())
        let planA = planA()
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: planA, profile: profile,
            configurationDigest: try RouterSystemProvider.digest(plan: planA, profile: profile),
            evidenceDigest: evidence)
        XCTAssertThrowsError(try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider))) { error in
            XCTAssertEqual(error as? RouterAcceptedRollbackRestoreDriver.Failure, .sealedPointerMissing)
        }
        XCTAssertEqual(rig.starts, 0)
    }

    func testRestoreRefusesWhenSealedPointerDrifts() throws {
        let rig = Rig()
        let planA = planA()
        let digestA = try RouterSystemProvider.digest(plan: planA, profile: profile)
        rig.journal.previousAccepted = RouterAcceptedConfiguration(
            plan: planA, profile: profile,
            configurationDigest: digestA, acceptanceEvidenceDigest: evidence)
        let provider = RouterSystemProvider(effects: rig.effects())
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: planA, profile: profile,
            configurationDigest: digestA, evidenceDigest: evidence)
        // The journal seal rotates after the preview was built: the driver must
        // refuse instead of restoring over a stale preview.
        rig.journal.previousAccepted = RouterAcceptedConfiguration(
            plan: planA, profile: profile,
            configurationDigest: digestA, acceptanceEvidenceDigest: String(repeating: "9", count: 64))
        XCTAssertThrowsError(try RouterAcceptedRollbackRestoreDriver.restore(
            preview: preview, dependencies: dependencies(rig, provider: provider))) { error in
            XCTAssertEqual(error as? RouterAcceptedRollbackRestoreDriver.Failure, .sealedPointerMismatch)
        }
        XCTAssertEqual(rig.starts, 0)
    }

    func testRestoreRefusesOnForeignEnvironmentAfterStop() throws {
        let rig = Rig()
        rig.plan = .init(proxies: [], rules: [], defaultDestination: .block)
        let planB = rig.plan
        let provider = RouterSystemProvider(effects: rig.effects())
        _ = try provider.handle(.prepare(id: UUID(), plan: planB, profile: profile))
        _ = try provider.handle(.apply(id: rig.journal.intent!.id, credentials: []))

        let planA = planA()
        rig.advance(1)
        rig.journal.previousAccepted = RouterAcceptedConfiguration(
            plan: planA, profile: profile,
            configurationDigest: try RouterSystemProvider.digest(plan: planA, profile: profile),
            acceptanceEvidenceDigest: evidence)

        rig.clean = false // cleanup cannot be proven: stop path must not be torn through
        XCTAssertThrowsError(try RouterAcceptedRollbackRestoreDriver.restore(
            preview: try RouterAcceptedRollback.preview(
                source: .previousAccepted, plan: planA, profile: profile,
                configurationDigest: rig.journal.previousAccepted!.configurationDigest,
                evidenceDigest: evidence),
            dependencies: dependencies(rig, provider: provider)))
        XCTAssertEqual(rig.starts, 1) // no restore start
        XCTAssertEqual(rig.journal.intent?.plan, planB) // previous plan untouched
        XCTAssertNotEqual(rig.journal.phase, .active)
    }

    func testDriverSideEffectsThroughFullRestoreGateChain() throws {
        let (rig, provider, preview) = try rigWithRotatedSeal(planA: planA())
        let now = Date()
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "active",
            observedAt: now, fingerprint: "fp")
        let after = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "active",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp")
        let gate = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, now: now.addingTimeInterval(3))
        XCTAssertEqual(gate.decision, .allow)
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true, clearWindow: grant),
            observation: after,
            sideEffects: RouterAcceptedRollbackRestoreDriver.sideEffects(
                preview: preview, dependencies: dependencies(rig, provider: provider)))
        XCTAssertTrue(restore.executed)
        XCTAssertTrue(restore.networkModified)
        XCTAssertTrue(restore.tunEffectsWired)
        XCTAssertEqual(restore.reason, "restore_tun_effects_invoked")
        XCTAssertFalse(restore.historicalDigestTreatedAsNewSuccess)
        XCTAssertEqual(rig.starts, 3)
        XCTAssertEqual(rig.journal.intent?.plan, preview.plan)
    }
}
