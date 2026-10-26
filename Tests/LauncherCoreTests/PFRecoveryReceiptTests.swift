import XCTest
@testable import LauncherCore

final class PFRecoveryReceiptTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let plan = String(repeating: "a", count: 32)
    private let checks = ["installed": true, "pf_enabled": true, "root_matches": true,
                          "destinations_match": true, "evidence_fresh": true]

    private func receipt(_ status: String = "passed", _ changes: [String: Any] = [:]) -> [String: Any] {
        let time = now.timeIntervalSince1970
        var value: [String: Any] = [
            "version": 1, "revision": 1, "plan_id": plan,
            "plan_sha256": String(repeating: "b", count: 64), "runtime_sha256": String(repeating: "c", count: 64),
            "service_instance": String(repeating: "d", count: 32), "request_id": String(repeating: "e", count: 32),
            "generation": String(repeating: "f", count: 32), "status": status, "reason": "checks_passed",
            "received_at": time - 3, "started_at": time - 2, "updated_at": time - 1,
            "checked_at": time - 1, "finished_at": time - 1, "request_deadline": time + 87,
            "checks": checks, "evidence_expires_at": time + 20
        ]
        if status != "passed" {
            value["checks"] = NSNull(); value["checked_at"] = NSNull(); value["evidence_expires_at"] = NSNull()
        }
        switch status {
        case "received":
            value["reason"] = "request_received"; value["updated_at"] = time - 3
            value["started_at"] = NSNull(); value["generation"] = NSNull(); value["finished_at"] = NSNull()
        case "checking":
            value["reason"] = "checks_in_progress"; value["updated_at"] = time - 2; value["finished_at"] = NSNull()
        case "failed": value["reason"] = "proxy_probe_failed"
        case "interrupted": value["reason"] = "service_restarted"
        default: break
        }
        value.merge(changes) { _, new in new }; return value
    }

    private func report(_ changes: [String: Any] = [:]) throws -> PFObservation {
        var value: [String: Any] = [
            "version": 1, "plan_id": plan, "checked_at": now.timeIntervalSince1970,
            "service_running": true, "rules_observed": true, "evidence_fresh": true,
            "manual_recheck_required": false, "status": "observed", "reason": "same_addresses_observed",
            "evidence_expires_at": now.timeIntervalSince1970 + 20,
            "protection_verified": false, "launch_authorized": false
        ]
        value.merge(changes) { _, new in new }
        return try JSONDecoder().decode(PFObservation.self, from: JSONSerialization.data(withJSONObject: value))
    }

    func testLegacyAndMalformedOptionalFieldsPreserveBaseObservation() throws {
        XCTAssertNil(try report().recovery)
        XCTAssertTrue(try report().recoveryLines(at: now).joined().contains("未提供"))
        for invalid: Any in [NSNull(), "private-secret", true, 5, []] {
            let value = try report(["recovery": invalid, "recovery_current": true])
            XCTAssertNil(value.recovery); XCTAssertTrue(value.isCurrent(at: now))
            XCTAssertEqual(value.layers(at: now).first?.status, "规则已观测")
            XCTAssertFalse(value.recoveryLines(at: now).joined().contains("private-secret"))
        }
        XCTAssertThrowsError(try report(["rules_observed": "true", "recovery": receipt()]))
    }

    func testAllFiveStatesShowSanitizedHistoryWithoutGrantingPermission() throws {
        for (state, title) in [("received", "请求已收到"), ("checking", "正在复检"),
                               ("passed", "本次复检当时通过"), ("failed", "本次复检未通过"),
                               ("interrupted", "本次复检已中断")] {
            let value = try report(["recovery": receipt(state), "recovery_current": false])
            let lines = value.recoveryLines(at: now)
            XCTAssertEqual(lines.first, title)
            XCTAssertFalse(lines.joined().contains("证据当前有效"))
            for secret in [plan, String(repeating: "b", count: 64), String(repeating: "c", count: 64),
                           String(repeating: "d", count: 32), String(repeating: "e", count: 32),
                           String(repeating: "f", count: 32)] { XCTAssertFalse(lines.joined().contains(secret)) }
            XCTAssertFalse(value.launch_authorized); XCTAssertFalse(value.protection_verified)
        }
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    func testCurrentPassRequiresTrueRootDeclarationAndFreshEvidence() throws {
        let value = try report(["recovery": receipt(), "recovery_current": true])
        XCTAssertTrue(value.recoveryLines(at: now).joined().contains("证据当前有效"))
        XCTAssertFalse(try report(["recovery": receipt()]).recoveryLines(at: now).joined().contains("证据当前有效"))
        for marker: Any in [false, NSNull(), "true", 1, [:]] {
            let history = try report(["recovery": receipt(), "recovery_current": marker])
            XCTAssertTrue(history.recoveryLines(at: now).joined().contains("历史通过"))
        }
        // Outer evidence may have renewed, while this particular attempt's evidence has expired.
        let expired = try report(["recovery": receipt("passed", ["evidence_expires_at": now.timeIntervalSince1970]),
                                  "recovery_current": true])
        XCTAssertTrue(expired.isCurrent(at: now))
        XCTAssertTrue(expired.recoveryLines(at: now).joined().contains("历史通过"))
    }

    func testUntrustedOuterReportNeverDisplaysRecoveryAsCurrentOrHistoricalSuccess() throws {
        for change: [String: Any] in [
            ["checked_at": now.timeIntervalSince1970 - 11], ["checked_at": now.timeIntervalSince1970 + 1],
            ["evidence_expires_at": now.timeIntervalSince1970], ["version": 2], ["plan_id": "invalid"],
            ["launch_authorized": true], ["protection_verified": true], ["service_running": false],
            ["rules_observed": false], ["status": "unknown"]
        ] {
            var changes: [String: Any] = ["recovery": receipt(), "recovery_current": true]
            changes.merge(change) { _, new in new }
            let value = try report(changes)
            XCTAssertFalse(value.isCurrent(at: now))
            XCTAssertEqual(value.recoveryLines(at: now), ["后台报告缺失或过期，暂不展示复检结果。"])
        }
    }

    func testNewAttemptFailureDoesNotReplaceOriginalLatchedFault() throws {
        let value = try report(["status": "fault", "evidence_fresh": false, "manual_recheck_required": true,
                                "reason": "evidence_expired", "recovery": receipt("failed"), "recovery_current": false])
        XCTAssertEqual(value.guide.title, "证据已过期")
        XCTAssertEqual(value.recoveryLines(at: now).first, "本次复检未通过")
        XCTAssertTrue(value.recoveryLines(at: now).contains("出口探测失败"))
        let historical = try report(["status": "fault", "evidence_fresh": false, "manual_recheck_required": true,
                                     "recovery": receipt(), "recovery_current": true])
        XCTAssertTrue(historical.recoveryLines(at: now).joined().contains("历史通过"))
    }

    func testPlanAndReportTimeMustMatchReceipt() throws {
        for change: [String: Any] in [["plan_id": String(repeating: "9", count: 32)],
            ["updated_at": now.timeIntervalSince1970 + 1, "finished_at": now.timeIntervalSince1970 + 1]] {
            let value = try report(["recovery": receipt("passed", change), "recovery_current": true])
            XCTAssertNotNil(value.recovery)
            XCTAssertTrue(value.recoveryLines(at: now).joined().contains("未提供有效"))
        }
    }

    func testBadSchemaIdentityAndTimesCannotUpgradeBaseObservation() throws {
        for change: [String: Any] in [
            ["version": 2], ["revision": true], ["revision": 0], ["revision": 9_007_199_254_740_992 as Int64],
            ["plan_sha256": String(repeating: "A", count: 64)], ["runtime_sha256": "private-secret"],
            ["service_instance": ""], ["request_id": "x"], ["generation": NSNull()],
            ["status": "private-secret"], ["reason": "private-secret"], ["unknown": "private-secret"],
            ["received_at": -1], ["received_at": true], ["updated_at": now.timeIntervalSince1970 - 5],
            ["request_deadline": now.timeIntervalSince1970 - 2], ["request_deadline": now.timeIntervalSince1970 + 118],
            ["started_at": now.timeIntervalSince1970 - 4], ["checked_at": now.timeIntervalSince1970 - 3],
            ["finished_at": NSNull()], ["finished_at": now.timeIntervalSince1970],
            ["evidence_expires_at": now.timeIntervalSince1970 - 1],
            ["evidence_expires_at": now.timeIntervalSince1970 + 45], ["checks": ["installed": true]]
        ] {
            let value = try report(["recovery": receipt("passed", change), "recovery_current": true])
            XCTAssertNil(value.recovery, "\(change)"); XCTAssertTrue(value.isCurrent(at: now))
            let lines = value.recoveryLines(at: now).joined()
            XCTAssertFalse(lines.contains("private-secret")); XCTAssertFalse(lines.contains("证据当前有效"))
        }
        var missing = receipt(); missing.removeValue(forKey: "checks")
        XCTAssertNil(try report(["recovery": missing]).recovery)
        for check in checks.keys {
            var invalid: [String: Any] = checks
            for wrong: Any in [false, 1, "true"] {
                invalid[check] = wrong
                XCTAssertNil(try report(["recovery": receipt("passed", ["checks": invalid])]).recovery)
            }
        }
    }

    func testPendingPastDeadlineWaitsForDaemonAndNeverInventsSuccessOrFailure() throws {
        for status in ["received", "checking"] {
            let value = try report(["recovery": receipt(status, ["request_deadline": now.timeIntervalSince1970 - 1]),
                                    "recovery_current": true])
            XCTAssertNotNil(value.recovery)
            let lines = value.recoveryLines(at: now).joined()
            XCTAssertTrue(lines.contains("等待后台确认")); XCTAssertFalse(lines.contains("本次复检未通过"))
            XCTAssertFalse(lines.contains("证据当前有效"))
        }
    }

    func testTerminalReasonsAreRestrictedToTheirStateAndExpiry() throws {
        for (status, reason) in [("received", "checks_passed"), ("checking", "request_received"),
                                 ("failed", "service_stopped"), ("interrupted", "proxy_probe_failed")] {
            XCTAssertNil(try report(["recovery": receipt(status, ["reason": reason])]).recovery)
        }
        XCTAssertNil(try report(["recovery": receipt("failed", ["reason": "request_expired"])]).recovery)
        let expired = try report(["recovery": receipt("failed", ["reason": "request_expired",
                                              "request_deadline": now.timeIntervalSince1970 - 1])])
        XCTAssertTrue(expired.recoveryLines(at: now).contains("本次请求超过完成期限。"))
        for status in ["received", "checking", "failed", "interrupted"] {
            XCTAssertNil(try report(["recovery": receipt(status, ["checks": checks])]).recovery)
        }
    }

    func testNonfiniteTimestampRejectedWithPermissiveDecoder() throws {
        let decoder = JSONDecoder()
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN")
        for key in ["received_at", "updated_at", "request_deadline", "started_at", "checked_at", "finished_at", "evidence_expires_at"] {
            for value in ["Infinity", "-Infinity", "NaN"] {
                let data = try JSONSerialization.data(withJSONObject: receipt("passed", [key: value]))
                XCTAssertThrowsError(try decoder.decode(PFRecoveryReceipt.self, from: data))
            }
        }
    }
}
