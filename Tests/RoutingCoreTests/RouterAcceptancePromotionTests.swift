import XCTest
@testable import RoutingCore

final class RouterAcceptancePromotionTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func digests() throws -> (plan: String, evidence: String) {
        let planDigest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        XCTAssertNotEqual(evidence, planDigest)
        return (planDigest, evidence)
    }

    func testRejectsWithoutEvidenceAndUnauthenticatedLiveSeal() throws {
        let digests = try digests()
        let empty = RouterAcceptanceEvidenceSeal(
            evidenceDigest: "", planDigest: digests.plan, configurationDigest: digests.plan,
            coveragePolicy: RouterTrafficCoveragePolicy.version,
            authentication: .unitTestSealedHarness, coverageComplete: true,
            reportedFailure: false, blockers: [])
        XCTAssertFalse(empty.canPromote)
        if case .refuse(let reason) = RouterAcceptancePromotion.decide(
            plan: plan, profile: profile, configurationDigest: digests.plan, seal: empty) {
            XCTAssertFalse(reason.isEmpty)
        } else {
            XCTFail("empty evidence must refuse")
        }

        let assessment = RouterTrafficAssessment(cases: [], controlPlane: [])
        let live = RouterAcceptanceEvidenceSeal.fromLiveAssessment(
            planDigest: digests.plan, configurationDigest: digests.plan,
            evidenceDigest: digests.evidence, assessment: assessment)
        XCTAssertFalse(live.canPromote)
        if case .refuse(let reason) = RouterAcceptancePromotion.decide(
            plan: plan, profile: profile, configurationDigest: digests.plan, seal: live) {
            XCTAssertEqual(reason, "live_collector_unavailable")
        } else {
            XCTFail("live seal must refuse")
        }

        var state = RouterSystemJournal.empty()
        XCTAssertThrowsError(try RouterAcceptancePromotion.commit(
            into: &state, plan: plan, profile: profile, configurationDigest: digests.plan, seal: live)) { error in
            XCTAssertEqual(error as? RouterAcceptancePromotionError,
                           .refused("live_collector_unavailable"))
        }
        XCTAssertNil(state.accepted)
        XCTAssertNil(state.previousAccepted)
        try RouterSystemProvider.validateJournal(state)
    }

    func testValidateJournalStillRejectsFakeAcceptedFills() throws {
        var state = RouterSystemJournal.empty()
        try RouterSystemProvider.validateJournal(state)

        state.accepted = .init(plan: plan, profile: profile,
                               configurationDigest: String(repeating: "0", count: 64),
                               acceptanceEvidenceDigest: String(repeating: "1", count: 64))
        XCTAssertThrowsError(try RouterSystemProvider.validateJournal(state)) { error in
            XCTAssertEqual(error as? RouterSystemError, .journalUnknown)
        }

        let digests = try digests()
        state.accepted = .init(plan: plan, profile: profile, configurationDigest: digests.plan,
                               acceptanceEvidenceDigest: digests.plan)
        XCTAssertThrowsError(try RouterSystemProvider.validateJournal(state)) { error in
            XCTAssertEqual(error as? RouterSystemError, .journalUnknown)
        }
    }

    func testAcceptWithUnitTestFixtureEvidenceAndPreviousAcceptedRotation() throws {
        let digests = try digests()
        let seal = RouterAcceptanceEvidenceSeal.unitTestComplete(
            evidenceDigest: digests.evidence, planDigest: digests.plan,
            configurationDigest: digests.plan)
        XCTAssertTrue(seal.canPromote)

        switch RouterAcceptancePromotion.decide(plan: plan, profile: profile,
                                                configurationDigest: digests.plan, seal: seal) {
        case .refuse(let reason):
            XCTFail("fixture seal must promote, got \(reason)")
        case .promote(let accepted):
            XCTAssertEqual(accepted.configurationDigest, digests.plan)
            XCTAssertEqual(accepted.acceptanceEvidenceDigest, digests.evidence)
            try RouterSystemProvider.validateAcceptedConfiguration(accepted)
        }

        var state = RouterSystemJournal.empty()
        try RouterAcceptancePromotion.commit(into: &state, plan: plan, profile: profile,
                                             configurationDigest: digests.plan, seal: seal)
        XCTAssertEqual(state.accepted?.acceptanceEvidenceDigest, digests.evidence)
        XCTAssertNil(state.previousAccepted)
        try RouterSystemProvider.validateJournal(state)

        let secondEvidence = String(repeating: "f", count: 64)
        let second = RouterAcceptanceEvidenceSeal.unitTestComplete(
            evidenceDigest: secondEvidence, planDigest: digests.plan,
            configurationDigest: digests.plan)
        try RouterAcceptancePromotion.commit(into: &state, plan: plan, profile: profile,
                                             configurationDigest: digests.plan, seal: second)
        XCTAssertEqual(state.accepted?.acceptanceEvidenceDigest, secondEvidence)
        XCTAssertEqual(state.previousAccepted?.acceptanceEvidenceDigest, digests.evidence)
        try RouterSystemProvider.validateJournal(state)
    }

    func testTrafficReceiptFixturesStillCannotPromoteViaAssessment() throws {
        let digests = try digests()
        let sample = String(repeating: "a", count: 64)
        let boot = UUID()
        let binding = RouterTrafficBinding(
            phase: .active, installation: .init(id: UUID(), ownerUID: 501),
            instance: UUID(), revision: UUID(),
            work: .init(bootID: boot, pid: 999, birthSeconds: 1_000, birthMicroseconds: 0),
            planDigest: digests.plan, configurationDigest: sample, stageReceiptDigest: sample,
            baselineID: UUID(), baselineDigest: sample, networkFingerprint: sample,
            coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
            compilerPolicy: RouterSystemCompiler.policyVersion)
        let interval = RouterTrafficInterval(
            start: .init(bootID: boot, uptime: 100, date: Date(timeIntervalSince1970: 2_000)),
            end: .init(bootID: boot, uptime: 120, date: Date(timeIntervalSince1970: 2_020)))
        let session = UUID()
        let records = try RouterTrafficCoveragePolicy.requirements(plan).map { id in
            RouterTrafficCaseRecord(id: id, attempt: UUID(), session: session,
                bindingDigest: try binding.digest(), interval: interval,
                transcript: .init(outcome: .incomplete, requestNonce: UUID(), endpointDigest: nil,
                    expectedEgress: nil, reply: nil, rejectControlBefore: nil,
                    rejectControlAfter: nil, gaps: []))
        }
        let receipt = RouterTrafficReceipt(version: 1, coveragePolicy: 1, session: session,
            before: binding, after: binding, interval: interval, records: records)
        let assessment = try receipt.assess(plan: plan, profile: profile)
        XCTAssertFalse(assessment.canPromoteAccepted)
        let seal = RouterAcceptanceEvidenceSeal.fromLiveAssessment(
            planDigest: digests.plan, configurationDigest: digests.plan,
            evidenceDigest: digests.evidence, assessment: assessment)
        XCTAssertFalse(seal.canPromote)
        if case .refuse(let reason) = RouterAcceptancePromotion.decide(
            plan: plan, profile: profile, configurationDigest: digests.plan, seal: seal) {
            XCTAssertEqual(reason, "live_collector_unavailable")
        } else {
            XCTFail("receipt-derived seal must refuse")
        }
    }
}
