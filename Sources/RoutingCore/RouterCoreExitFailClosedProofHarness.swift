import Foundation

/// Production proof harness for core-exit fail-closed. Stays refused / unverified until
/// an independent PF layer is actually armed and post-exit reobserved.
/// This package never arms PF by itself; REJECT/probe proofs remain insufficient.
///
/// `PostExitReobservation` records a **differential** live observation
/// (blocked while armed + reachable after unload, with core absent). That clears the
/// "still required" blocker but **never** sets `routingVerified` / `accepted` /
/// `canClaimFailClosedProven` — product promotion needs a separate sealed claim path.
public enum RouterCoreExitFailClosedProofHarness {
    public static let policyVersion = 2

    public enum Outcome: String, Equatable, Sendable {
        case refused
        case unverified
        /// Differential post-exit evidence attached; still not a product seal.
        case differentiallyObserved
        /// Unit-test sealed path only — never from production UI / IPC.
        case fixtureVerified
    }

    /// Live differential observation after core exit. All bools must be independently true
    /// for the observation to count; `evidenceDigest` is a 64-hex binding to the raw record.
    public struct PostExitReobservation: Equatable, Sendable {
        public let coreProcessAbsent: Bool
        public let ownedTunAbsent: Bool
        public let destinationBlockedWhileArmed: Bool
        public let destinationReachableAfterUnload: Bool
        public let evidenceDigest: String
        public let observedAt: Date
        public let notes: [String]

        public init(coreProcessAbsent: Bool, ownedTunAbsent: Bool,
                    destinationBlockedWhileArmed: Bool, destinationReachableAfterUnload: Bool,
                    evidenceDigest: String, observedAt: Date = Date(), notes: [String] = []) {
            self.coreProcessAbsent = coreProcessAbsent
            self.ownedTunAbsent = ownedTunAbsent
            self.destinationBlockedWhileArmed = destinationBlockedWhileArmed
            self.destinationReachableAfterUnload = destinationReachableAfterUnload
            self.evidenceDigest = evidenceDigest
            self.observedAt = observedAt
            self.notes = notes
        }

        public var isDifferentiallyComplete: Bool {
            coreProcessAbsent && ownedTunAbsent
                && destinationBlockedWhileArmed && destinationReachableAfterUnload
                && evidenceDigest.count == 64
                && evidenceDigest.unicodeScalars.allSatisfy { ("0"..."9").contains($0) || ("a"..."f").contains($0) }
        }

        /// 2026-10-24 live reobservation against Anthropic public destinations.
        public static let live20261024 = PostExitReobservation(
            coreProcessAbsent: true,
            ownedTunAbsent: true,
            destinationBlockedWhileArmed: true,
            destinationReachableAfterUnload: true,
            evidenceDigest: "efe1f8bf6c55e11418df9d00dfc044c935f489c8d83d2990192a805aab040ba8",
            observedAt: Date(timeIntervalSince1970: 1_792_835_784),
            notes: [
                "web-notes/pf-failclosed-post-exit-2026-10-24.json",
                "mihomo absent; utun8 absent; helper stopped/external_environment_acknowledged",
                "armed: 160.79.104.10:443 timeout; unload: connect succeeded; then hook-restore → PF Disabled",
            ])
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let outcome: Outcome
        public let verified: Bool
        public let pfArmed: Bool
        public let pfRulesLoaded: Bool
        public let networkModified: Bool
        public let postExitDifferentiallyObserved: Bool
        public let assessment: RouterCoreExitFailClosed.Assessment
        public let blockers: [String]
        public let reason: String
        public let summary: String
        public let routingVerified: Bool
        public let accepted: Bool
        public let canClaimFailClosedProven: Bool
    }

    /// Evaluate fail-closed proof against optional PF arming gate report + post-exit evidence.
    public static func evaluate(plan: RouterPlan,
                                pfArming: RouterPFArmingExecuteGate.Report? = nil,
                                postExit: PostExitReobservation? = nil,
                                claim: RouterCoreExitFailClosed.IndependentLayerClaim = .productionGap) -> Report {
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        let assessment = RouterCoreExitFailClosed.assess(recipe: recipe, claim: claim)

        if assessment.verified, claim.authentication == .unitTestSealedAfterCoreExit {
            return .init(
                policyVersion: policyVersion, outcome: .fixtureVerified, verified: false,
                pfArmed: false, pfRulesLoaded: false, networkModified: false,
                postExitDifferentiallyObserved: false,
                assessment: assessment, blockers: [],
                reason: "unit_test_sealed_fixture_only",
                summary: "单元测试密封夹具路径；不代表本机已武装 PF 或完成退出后复验。canClaimFailClosedProven=false。",
                routingVerified: false, accepted: false, canClaimFailClosedProven: false)
        }

        var blockers = assessment.blockers
        let pfArmed = pfArming.map { report in
            if case .allow = report.decision { return report.armed } else { return false }
        } ?? false
        let pfRulesLoaded = pfArming?.pfRulesLoaded ?? false
        let networkModified = pfArming?.networkModified ?? false
        let differential = postExit?.isDifferentiallyComplete == true

        if let pfArming {
            switch pfArming.decision {
            case .refuse(let reason):
                blockers.append("pf_arming_gate_refused:\(reason)")
            case .allow:
                if !pfArming.pfEffectsWired {
                    blockers.append("pf_arming_gate_passed_but_effects_unwired")
                }
                if pfArming.pfEffectsWired && !pfArming.armed {
                    blockers.append("pf_effects_wired_but_not_armed")
                }
                if pfArming.pfRulesLoaded && !pfArming.pfEffectsWired {
                    blockers.append("unexpected_pf_rules_loaded_without_wired_effects")
                }
                if pfArming.networkModified && !pfArming.pfEffectsWired {
                    blockers.append("unexpected_network_mutation_without_wired_effects")
                }
                if pfArming.armed && pfArming.pfRulesLoaded && !differential {
                    blockers.append("post_exit_reobservation_still_required")
                }
            }
        } else if !differential {
            blockers.append("pf_arming_gate_not_run")
        }

        if let postExit {
            if !postExit.coreProcessAbsent { blockers.append("post_exit_core_still_present") }
            if !postExit.ownedTunAbsent { blockers.append("post_exit_owned_tun_still_present") }
            if !postExit.destinationBlockedWhileArmed {
                blockers.append("post_exit_destination_not_blocked_while_armed")
            }
            if !postExit.destinationReachableAfterUnload {
                blockers.append("post_exit_destination_not_restored_after_unload")
            }
            if postExit.evidenceDigest.count != 64 {
                blockers.append("post_exit_evidence_digest_invalid")
            }
            if differential {
                blockers.append("post_exit_differential_observed_not_a_product_seal")
            }
        } else if pfArmed {
            blockers.append("post_exit_reobservation_still_required")
        }

        if !pfArmed && !differential {
            blockers.append("independent_pf_layer_not_armed")
            blockers.append("post_exit_reobservation_unavailable_without_arming")
        }
        blockers.append("reject_rules_are_not_core_exit_proof")
        // Even with differential evidence, product seals stay false.
        blockers.append("routing_verified_and_accepted_remain_false")

        let unique = Array(Set(blockers)).sorted()
        let refused: Bool = {
            if pfArming == nil && !differential { return true }
            if let pfArming, case .refuse = pfArming.decision { return true }
            return false
        }()

        let outcome: Outcome
        if refused {
            outcome = .refused
        } else if differential {
            outcome = .differentiallyObserved
        } else {
            outcome = .unverified
        }

        let reason: String
        switch outcome {
        case .refused:
            reason = pfArming == nil
                ? "pf_unarmed_proof_refused"
                : "pf_arming_refused_blocks_fail_closed_proof"
        case .unverified:
            reason = "pf_gate_or_arming_incomplete_fail_closed_unproven"
        case .differentiallyObserved:
            reason = "post_exit_differential_observed_unsealed"
        case .fixtureVerified:
            reason = "unit_test_sealed_fixture_only"
        }

        return .init(
            policyVersion: policyVersion, outcome: outcome, verified: false,
            pfArmed: pfArmed || differential, pfRulesLoaded: pfRulesLoaded,
            networkModified: networkModified,
            postExitDifferentiallyObserved: differential,
            assessment: assessment, blockers: unique, reason: reason,
            summary: "内核退出断流证明：outcome=\(outcome.rawValue) verified=false · differential=\(differential) · pfArmed=\(pfArmed) · loaded=\(pfRulesLoaded)。routing_verified=false · accepted=false · canClaimFailClosedProven=false。",
            routingVerified: false, accepted: false, canClaimFailClosedProven: false)
    }
}
