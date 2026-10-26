import XCTest
@testable import RoutingCore

final class RouterAcceptedRollbackTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .cloudflare)

    func sealed() throws -> (digest: String, evidence: String) {
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let evidence = String(repeating: "e", count: 64)
        XCTAssertNotEqual(digest, evidence)
        return (digest, evidence)
    }

    func testMissingSourceAndFakeDigestRefusePreview() throws {
        XCTAssertThrowsError(try RouterAcceptedRollback.preview(from: .empty())) { error in
            XCTAssertEqual(error as? RouterAcceptedRollback.Failure, .missingSource)
        }
        XCTAssertThrowsError(try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: plan, profile: profile,
            configurationDigest: String(repeating: "a", count: 64),
            evidenceDigest: String(repeating: "b", count: 64)))
    }

    func testPreviewSeparatesDimensionsAndForbidsHistoricalTransfer() throws {
        let digests = try sealed()
        var journal = RouterSystemJournal.empty()
        let seal = RouterAcceptanceEvidenceSeal.unitTestComplete(
            evidenceDigest: digests.evidence, planDigest: digests.digest,
            configurationDigest: digests.digest)
        try RouterAcceptancePromotion.commit(into: &journal, plan: plan, profile: profile,
                                             configurationDigest: digests.digest, seal: seal)
        let secondEvidence = String(repeating: "f", count: 64)
        try RouterAcceptancePromotion.commit(
            into: &journal, plan: plan, profile: profile, configurationDigest: digests.digest,
            seal: .unitTestComplete(evidenceDigest: secondEvidence, planDigest: digests.digest,
                                    configurationDigest: digests.digest))
        XCTAssertNotNil(journal.previousAccepted)

        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let preview = try RouterAcceptedRollback.preview(from: journal, preferPrevious: true, now: now)
        XCTAssertEqual(preview.source, .previousAccepted)
        XCTAssertEqual(preview.historicalEvidenceDigest, digests.evidence)
        XCTAssertFalse(preview.historicalSuccessTransfersToNewInstance)
        XCTAssertFalse(preview.canExecute)
        XCTAssertEqual(Set(preview.dimensions.map(\.name)),
                       ["configurationRestore", "processRestore", "networkCleanup", "trafficReacceptance"])
        XCTAssertTrue(preview.blockers.contains("historical_digest_is_not_new_success"))
        XCTAssertTrue(preview.summary.contains("旧 digest") || preview.summary.contains("≠"))
    }

    func testStalePreviewAndProductionExecuteRefuseMutation() throws {
        let digests = try sealed()
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let preview = try RouterAcceptedRollback.preview(
            source: .accepted, plan: plan, profile: profile,
            configurationDigest: digests.digest, evidenceDigest: digests.evidence,
            now: now, ttl: 30)
        XCTAssertThrowsError(try RouterAcceptedRollback.requireFresh(
            preview, now: now.addingTimeInterval(31))) { error in
            XCTAssertEqual(error as? RouterAcceptedRollback.Failure, .stalePreview)
        }
        XCTAssertThrowsError(try RouterAcceptedRollback.execute(preview: preview, arming: nil, now: now)) { error in
            XCTAssertEqual(error as? RouterAcceptedRollback.Failure, .disarmed)
        }
        let arming = try RouterAcceptedRollback.armExecute(preview: preview, kind: .productionPreviewOnly, now: now)
        let report = try RouterAcceptedRollback.execute(preview: preview, arming: arming, now: now)
        XCTAssertFalse(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.journalMutated)
        XCTAssertFalse(report.historicalDigestTreatedAsNewSuccess)
        XCTAssertEqual(report.dimensions.count, 4)
        XCTAssertTrue(report.dimensions.allSatisfy { $0.status == "blocked_pending_new_operation" })
    }

    func testUnitTestExecutePathStillRejectsHistoricalDigestAsNewSuccess() throws {
        let digests = try sealed()
        let now = Date()
        let preview = try RouterAcceptedRollback.preview(
            source: .previousAccepted, plan: plan, profile: profile,
            configurationDigest: digests.digest, evidenceDigest: digests.evidence, now: now)
        let arming = try RouterAcceptedRollback.armExecute(preview: preview, kind: .unitTestPreviewPath, now: now)
        let report = try RouterAcceptedRollback.execute(preview: preview, arming: arming, now: now)
        XCTAssertTrue(report.executed)
        XCTAssertFalse(report.networkModified)
        XCTAssertFalse(report.historicalDigestTreatedAsNewSuccess)
        XCTAssertEqual(report.dimensions.first { $0.name == "trafficReacceptance" }?.status, "not_completed")
        XCTAssertTrue(report.summary.contains("未当作新成功") || report.summary.contains("networkModified=false"))
    }
}
