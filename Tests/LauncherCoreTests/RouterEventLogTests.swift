import XCTest
@testable import LauncherCore

final class RouterEventLogTests: XCTestCase {
    func testRedactsSecretsAndPersistsBoundedEvents() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("router-events-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }

        let store = RouterEventLog(root: root)
        let dirty = RouterEventEntry(
            kind: .prepareRequested,
            summary: "password=super-secret-value token=abc",
            detail: "Authorization: Bearer aaa.bbb.ccc " + String(repeating: "A", count: 100),
            instance: UUID(),
            digest: String(repeating: "a", count: 64))
        XCTAssertFalse(dirty.summary.contains("super-secret"))
        XCTAssertTrue(dirty.summary.contains("[redacted]"))
        XCTAssertFalse(dirty.detail.contains("Bearer"))
        XCTAssertFalse(dirty.routingVerified)
        XCTAssertFalse(dirty.accepted)
        XCTAssertEqual(dirty.digestPrefix?.count, 12)

        try store.append(dirty)
        store.record(kind: .coexistenceInspected, summary: "检查现有网络", detail: "refuseOwnTun=true")
        store.record(kind: .hitCorrelationArmed, summary: "武装 TLS", detail: "tlsHeld")
        store.record(kind: .rollbackPreviewNoted, summary: "回退缺口", detail: "no sealed pointer")

        let entries = try store.entries()
        XCTAssertEqual(entries.count, 4)
        XCTAssertEqual(entries.map(\.kind), [
            .prepareRequested, .coexistenceInspected, .hitCorrelationArmed, .rollbackPreviewNoted
        ])
        XCTAssertTrue(entries.allSatisfy { !$0.routingVerified && !$0.accepted })
    }

    func testDeliveryChecklistNeverClaimsProductComplete() {
        // Checklist lives in RoutingCore; smoke via string contract here is insufficient.
        // Covered by RoutingCoreTests.RouterDeliveryChecklistTests.
        XCTAssertTrue(RouterEventKind.allCases.contains(.prepareRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.applyOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.stopOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.hitCorrelationRunRequested))
        XCTAssertTrue(RouterEventKind.allCases.contains(.hitCorrelationRunOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.hitCorrelationRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.matrixLiveRun))
        XCTAssertTrue(RouterEventKind.allCases.contains(.matrixLoopbackFillRequested))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingPreviewNoted))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.rollbackExecuteArmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.rollbackExecuteConfirmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.rollbackExecuteOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.rollbackExecuteRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.rollbackRestoreReported))
        XCTAssertTrue(RouterEventKind.allCases.contains(.faultAcceptanceEnumerated))
        XCTAssertTrue(RouterEventKind.allCases.contains(.tunApplyPreviewNoted))
        XCTAssertTrue(RouterEventKind.allCases.contains(.tunApplyExecuteArmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.tunApplyExecuteConfirmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.tunApplyExecuteOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.tunApplyExecuteRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingExecuteArmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingExecuteConfirmed))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingExecuteOutcome))
        XCTAssertTrue(RouterEventKind.allCases.contains(.pfArmingExecuteRefused))
        XCTAssertTrue(RouterEventKind.allCases.contains(.failClosedProofEnumerated))
        XCTAssertTrue(RouterEventKind.allCases.contains(.appTrafficAttestationRun))
        XCTAssertTrue(RouterEventKind.allCases.contains(.appTrafficAttestationRefused))
    }
}
