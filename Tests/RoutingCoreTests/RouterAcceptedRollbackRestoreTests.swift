import XCTest
@testable import RoutingCore

final class RouterAcceptedRollbackRestoreTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func sealedPreview(now: Date,
                       source: RouterAcceptedRollback.SourceKind = .previousAccepted) throws
        -> RouterAcceptedRollback.Preview {
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        return try RouterAcceptedRollback.preview(
            source: source, plan: plan, profile: profile,
            configurationDigest: digest, evidenceDigest: evidence, now: now)
    }

    func gateAllow(preview: RouterAcceptedRollback.Preview, now: Date) throws -> (
        RouterAcceptedRollbackExecuteGate.Report, RouterAcceptedRollbackExecuteGate.Observation
    ) {
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now, fingerprint: "fp")
        let after = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp")
        let gate = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, now: now.addingTimeInterval(3))
        XCTAssertEqual(gate.decision, .allow)
        return (gate, after)
    }

    func testForeignTunnelRestoreRefusesWithoutMutation() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, systemPhase: "active",
            observedAt: now.addingTimeInterval(2))
        let gate = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: obs, after: obs, now: now.addingTimeInterval(3))
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview), observation: obs)
        XCTAssertFalse(restore.gateAllowed)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertFalse(restore.canAttemptTunRestore)
        XCTAssertFalse(restore.journalMutated)
        XCTAssertFalse(restore.historicalDigestTreatedAsNewSuccess)
        XCTAssertTrue(restore.dimensions.allSatisfy { $0.status == "refused" })
        XCTAssertNotNil(restore.dimensions.first { $0.name == "tunRestore" })
        XCTAssertTrue(restore.reason.contains("foreign_tunnel") || restore.reason.contains("refuseOwnTun")
                      || restore.reason == "foreign_tunnel_or_refuseOwnTun"
                      || restore.reason == "foreign_tunnel_or_clear_not_met_for_restore")
    }

    func testLivePathWithoutClearWindowRefusesAndDoesNotMutate() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let (gate, after) = try gateAllow(preview: preview, now: now)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: false,
                          clearWindow: .none),
            observation: after)
        XCTAssertFalse(restore.gateAllowed)
        XCTAssertFalse(restore.executed)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertFalse(restore.clearWindowGranted)
        XCTAssertTrue(restore.previousAcceptedIsOurs)
        XCTAssertEqual(restore.reason, "clear_window_not_confirmed_in_conversation")
        XCTAssertEqual(restore.dimensions.first { $0.name == "tunRestore" }?.status, "refused")
    }

    func testClearGrantWithoutNetworkConfirmStructuresAwaitingPath() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let (gate, after) = try gateAllow(preview: preview, now: now)
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: false,
                          clearWindow: grant),
            observation: after)
        XCTAssertTrue(restore.gateAllowed)
        XCTAssertFalse(restore.executed)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertFalse(restore.canAttemptTunRestore)
        XCTAssertTrue(restore.clearWindowGranted)
        XCTAssertEqual(restore.dimensions.first { $0.name == "configurationRestore" }?.status,
                       "candidate_validated_not_staged")
        XCTAssertEqual(restore.dimensions.first { $0.name == "networkCleanup" }?.status,
                       "clear_proven_awaiting_user_network_confirm")
        XCTAssertEqual(restore.dimensions.first { $0.name == "tunRestore" }?.status,
                       "awaiting_userConfirmedNetworkRestore")
        XCTAssertEqual(restore.dimensions.first { $0.name == "trafficReacceptance" }?.status,
                       "required_not_started")
        XCTAssertEqual(restore.reason, "restore_planned_awaiting_network_confirm")
    }

    func testClearGrantPlusNetworkConfirmStillUnwiredWithoutEffects() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let (gate, after) = try gateAllow(preview: preview, now: now)
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true,
                          clearWindow: grant),
            observation: after)
        XCTAssertTrue(restore.gateAllowed)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertTrue(restore.canAttemptTunRestore)
        XCTAssertEqual(restore.dimensions.first { $0.name == "networkCleanup" }?.status,
                       "preconditions_met_effects_unwired")
        XCTAssertEqual(restore.dimensions.first { $0.name == "tunRestore" }?.status,
                       "structured_ready_effects_unwired")
        XCTAssertEqual(restore.reason, "restore_structured_ready_tun_effects_unwired")
        XCTAssertFalse(restore.historicalDigestTreatedAsNewSuccess)
    }

    func testInjectedRestoreEffectsRunWhenPreconditionsMet() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let (gate, after) = try gateAllow(preview: preview, now: now)
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        final class Box: @unchecked Sendable { var count = 0 }
        let box = Box()
        let effects = RouterAcceptedRollbackRestore.SideEffects(restoreOwnTun: { intent in
            box.count += 1
            XCTAssertTrue(intent.userConfirmedNetworkRestore)
            return .init(networkModified: true, detail: "test harness simulated restore")
        })
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true,
                          clearWindow: grant),
            observation: after, sideEffects: effects)
        XCTAssertEqual(box.count, 1)
        XCTAssertTrue(restore.gateAllowed)
        XCTAssertTrue(restore.executed)
        XCTAssertTrue(restore.tunEffectsWired)
        XCTAssertTrue(restore.networkModified)
        XCTAssertEqual(restore.reason, "restore_tun_effects_invoked")
        XCTAssertFalse(restore.historicalDigestTreatedAsNewSuccess)
    }

    func testAcceptedSourceNotOursRefusesEvenWithClearGrant() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now, source: .accepted)
        let (gate, after) = try gateAllow(preview: preview, now: now)
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true,
                          clearWindow: grant),
            observation: after)
        XCTAssertFalse(restore.gateAllowed)
        XCTAssertFalse(restore.previousAcceptedIsOurs)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertEqual(restore.reason, "previousAccepted_not_ours")
    }

    func testForeignObservationAfterAllowRefusesRestore() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let preview = try sealedPreview(now: now)
        let (gate, _) = try gateAllow(preview: preview, now: now)
        let foreign = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, systemPhase: "active",
            observedAt: now.addingTimeInterval(4))
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true,
                          clearWindow: grant),
            observation: foreign)
        XCTAssertFalse(restore.gateAllowed)
        XCTAssertFalse(restore.networkModified)
        XCTAssertEqual(restore.reason, "foreign_tunnel_or_clear_not_met_for_restore")
    }
}

final class RouterFaultAcceptanceHarnessTests: XCTestCase {
    func testHarnessNeverClaimsProductComplete() {
        let report = RouterFaultAcceptanceHarness.report()
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertFalse(report.canClaimProductComplete)
        XCTAssertEqual(report.verifiedCount, 0)
        XCTAssertTrue(report.faults.contains(where: {
            $0.code == .pfArmingUnconfirmed && $0.verification == .blockedOnUserConfirm
        }))
        XCTAssertTrue(report.faults.contains(where: {
            $0.code == .realTunApplyMissing && $0.verification == .blockedOnUserConfirm
        }))
        XCTAssertTrue(report.faults.contains(where: {
            $0.code == .tunRestoreClearWindowUnconfirmed
                && $0.verification == .blockedOnUserConfirm
        }))
        XCTAssertTrue(report.summary.contains("complete=false"))
    }

    func testHarnessReflectsRollbackRestoreRefusal() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        let now = Date()
        let preview = try RouterAcceptedRollback.preview(
            source: .accepted, plan: plan, profile: profile,
            configurationDigest: digest, evidenceDigest: evidence, now: now)
        let gate = RouterAcceptedRollbackExecuteGate.Report(
            policyVersion: 1, previewID: preview.id, decision: .refuse("foreign_tunnel_or_refuseOwnTun"),
            executed: false, networkModified: false, journalMutated: false,
            historicalDigestTreatedAsNewSuccess: false, dimensions: [],
            reason: "foreign_tunnel_or_refuseOwnTun", summary: "refused")
        let obs = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, systemPhase: "active")
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview, intent: .init(preview: preview), observation: obs)
        let faults = RouterFaultAcceptanceHarness.report(rollbackRestore: restore)
        XCTAssertFalse(faults.canClaimProductComplete)
        XCTAssertTrue(faults.faults.contains(where: {
            $0.code == .rollbackRestoreUnwired && $0.verification == .blockedOnUserConfirm
        }))
        XCTAssertTrue(faults.faults.contains(where: {
            $0.code == .tunRestoreClearWindowUnconfirmed
                && $0.verification == .blockedOnUserConfirm
                && $0.evidence.contains("tunEffectsWired=false")
        }))
    }

    func testHarnessReflectsStructuredUnwiredRestore() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        let now = Date(timeIntervalSince1970: 2_000_100_000)
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: plan, profile: profile,
            configurationDigest: digest, evidenceDigest: evidence, now: now)
        let arming = try RouterAcceptedRollback.armExecute(
            preview: preview, kind: .productionGuardedExecute, now: now)
        let confirm = RouterAcceptedRollbackExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let obs = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now, fingerprint: "fp")
        let after = RouterAcceptedRollbackExecuteGate.Observation(
            refuseOwnTun: false, requireClearWouldPass: true, systemPhase: "idle",
            observedAt: now.addingTimeInterval(2), fingerprint: "fp")
        let gate = try RouterAcceptedRollbackExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: obs, after: after, now: now.addingTimeInterval(3))
        let grant = RouterTunApplyExecuteGate.ClearWindowGrant(grantedInConversation: true)
        let restore = RouterAcceptedRollbackRestore.apply(
            gate: gate, preview: preview,
            intent: .init(preview: preview, userConfirmedNetworkRestore: true, clearWindow: grant),
            observation: after)
        let faults = RouterFaultAcceptanceHarness.report(rollbackRestore: restore)
        XCTAssertFalse(faults.canClaimProductComplete)
        XCTAssertFalse(restore.networkModified)
        XCTAssertFalse(restore.tunEffectsWired)
        XCTAssertTrue(faults.faults.contains(where: {
            $0.code == .rollbackRestoreUnwired && $0.verification == .unverified
                && $0.evidence.contains("tunEffectsWired=false")
        }))
        // Clear window is granted in this fixture — that fault moves off blockedOnUserConfirm.
        XCTAssertTrue(faults.faults.contains(where: {
            $0.code == .tunRestoreClearWindowUnconfirmed
                && $0.verification == .unverified
                && $0.evidence.contains("effects_unwired")
        }))
    }

    func testHarnessReflectsTunApplyRefuseWithoutClaimingComplete() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare)
        let now = Date(timeIntervalSince1970: 1_900_200_000)
        let preview = try RouterTunApplyExecuteGate.preview(plan: plan, profile: profile, now: now)
        let arming = try RouterTunApplyExecuteGate.arm(
            preview: preview, kind: .productionGuardedApply, now: now)
        let confirm = RouterTunApplyExecuteGate.Confirmation(
            previewID: preview.id, confirmedAt: now.addingTimeInterval(1), explicitUIConfirm: true)
        let before = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, foreignTunnelPresent: true,
            systemPhase: "idle", observedAt: now)
        let after = RouterTunApplyExecuteGate.Observation(
            refuseOwnTun: true, requireClearWouldPass: false, foreignTunnelPresent: true,
            systemPhase: "idle", observedAt: now.addingTimeInterval(2))
        let tun = try RouterTunApplyExecuteGate.execute(
            preview: preview, arming: arming, confirmation: confirm,
            before: before, after: after, clearWindow: .none, now: now.addingTimeInterval(3))
        let faults = RouterFaultAcceptanceHarness.report(tunApply: tun)
        XCTAssertFalse(faults.canClaimProductComplete)
        XCTAssertFalse(tun.networkModified)
        XCTAssertFalse(tun.tunEnabled)
        XCTAssertTrue(faults.faults.contains(where: {
            $0.code == .realTunApplyMissing && $0.verification == .blockedOnUserConfirm
                && $0.evidence.contains("networkModified=false")
        }))
    }
}
