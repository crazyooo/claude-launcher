import Foundation

/// Bounded claim that traffic evidence is strong enough to write journal accepted pointers.
/// Traffic receipt assessments keep `canPromoteAccepted == false` until a live collector exists;
/// this seal is a separate, explicit gate so empty/fake journal fills stay refused while tests
/// can prove the persistence path with a sealed harness fixture.
struct RouterAcceptanceEvidenceSeal: Equatable, Sendable {
    enum Authentication: Equatable, Sendable {
        /// Production default until an authenticated live collector exists.
        case liveCollectorUnavailable
        /// Unit-test-only harness. Must never be constructed from IPC, UI, or receipt decode.
        case unitTestSealedHarness
    }

    let evidenceDigest: String
    let planDigest: String
    let configurationDigest: String
    let coveragePolicy: Int
    let authentication: Authentication
    let coverageComplete: Bool
    let reportedFailure: Bool
    let blockers: [String]

    var canPromote: Bool {
        authentication == .unitTestSealedHarness
            && coverageComplete
            && !reportedFailure
            && blockers.isEmpty
            && coveragePolicy == RouterTrafficCoveragePolicy.version
            && RouterSystemProvider.validDigest(evidenceDigest)
            && RouterSystemProvider.validDigest(planDigest)
            && RouterSystemProvider.validDigest(configurationDigest)
            && evidenceDigest != configurationDigest
            && evidenceDigest != planDigest
    }

    /// Production and receipt-derived seals: never promote.
    static func fromLiveAssessment(planDigest: String, configurationDigest: String,
                                   evidenceDigest: String,
                                   assessment: RouterTrafficAssessment) -> Self {
        .init(evidenceDigest: evidenceDigest, planDigest: planDigest,
              configurationDigest: configurationDigest,
              coveragePolicy: assessment.controlPlaneCoveragePolicy,
              authentication: .liveCollectorUnavailable,
              coverageComplete: false,
              reportedFailure: assessment.status == "reported_failure",
              blockers: assessment.blockers.map(\.rawValue).sorted())
    }

    /// Explicit unit-test fixture proving the journal gate can accept when evidence is sealed.
    static func unitTestComplete(evidenceDigest: String, planDigest: String,
                                 configurationDigest: String) -> Self {
        .init(evidenceDigest: evidenceDigest, planDigest: planDigest,
              configurationDigest: configurationDigest,
              coveragePolicy: RouterTrafficCoveragePolicy.version,
              authentication: .unitTestSealedHarness,
              coverageComplete: true, reportedFailure: false, blockers: [])
    }
}

enum RouterAcceptancePromotion {
    enum Decision: Sendable {
        case refuse(String)
        case promote(RouterAcceptedConfiguration)
    }

    /// Shared gate for production and tests. Empty/fake digests and unauthenticated seals refuse.
    static func decide(plan: RouterPlan, profile: RouterSystemProfile,
                       configurationDigest: String,
                       seal: RouterAcceptanceEvidenceSeal) -> Decision {
        do {
            let planDigest = try RouterSystemProvider.digest(plan: plan, profile: profile)
            guard configurationDigest == planDigest,
                  RouterSystemProvider.validDigest(configurationDigest) else {
                return .refuse("configuration_digest_mismatch")
            }
            guard seal.planDigest == planDigest,
                  seal.configurationDigest == configurationDigest else {
                return .refuse("seal_digest_mismatch")
            }
            guard seal.canPromote else {
                if seal.authentication == .liveCollectorUnavailable {
                    return .refuse("live_collector_unavailable")
                }
                if seal.reportedFailure { return .refuse("reported_failure") }
                if !seal.coverageComplete { return .refuse("coverage_incomplete") }
                if !seal.blockers.isEmpty { return .refuse("blockers_present") }
                return .refuse("seal_cannot_promote")
            }
            try RouterSystemProvider.validateAcceptedConfiguration(
                .init(plan: plan, profile: profile, configurationDigest: configurationDigest,
                      acceptanceEvidenceDigest: seal.evidenceDigest))
            return .promote(.init(plan: plan, profile: profile, configurationDigest: configurationDigest,
                                  acceptanceEvidenceDigest: seal.evidenceDigest))
        } catch {
            return .refuse("accepted_shape_invalid")
        }
    }

    /// Mutates journal pointers only after `decide` allows. Does not change network or TUN.
    static func commit(into state: inout RouterSystemJournal, plan: RouterPlan,
                       profile: RouterSystemProfile, configurationDigest: String,
                       seal: RouterAcceptanceEvidenceSeal) throws {
        switch decide(plan: plan, profile: profile, configurationDigest: configurationDigest, seal: seal) {
        case .refuse(let reason):
            throw RouterAcceptancePromotionError.refused(reason)
        case .promote(let accepted):
            if let current = state.accepted {
                state.previousAccepted = current
            }
            state.accepted = accepted
            state.revision = UUID()
            try RouterSystemProvider.validateJournal(state)
        }
    }
}

enum RouterAcceptancePromotionError: Error, Equatable {
    case refused(String)
}
