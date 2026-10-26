import XCTest
@testable import LauncherCore

final class PFObservationTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private func report(_ changes: [String: Any] = [:]) throws -> PFObservation {
        var value: [String: Any] = [
            "version": 1, "plan_id": String(repeating: "a", count: 32),
            "checked_at": now.timeIntervalSince1970, "service_running": true,
            "rules_observed": true, "evidence_fresh": true, "manual_recheck_required": false,
            "status": "observed", "reason": "same_addresses_observed",
            "evidence_expires_at": now.timeIntervalSince1970 + 20,
            "protection_verified": false, "launch_authorized": false
        ]
        value.merge(changes) { _, new in new }
        return try JSONDecoder().decode(PFObservation.self, from: JSONSerialization.data(withJSONObject: value))
    }

    func testCurrentObservationDisplaysRulesWithoutGrantingLaunch() throws {
        let value = try report()
        XCTAssertTrue(value.isCurrent(at: now))
        XCTAssertEqual(value.layers(at: now).first?.status, "规则已观测")
        XCTAssertEqual(value.layers(at: now).last?.status, "检查运行中")
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    func testStaleFutureOrInvalidReportsAreUnavailable() throws {
        for changes: [String: Any] in [
            ["checked_at": now.timeIntervalSince1970 - 11],
            ["checked_at": now.timeIntervalSince1970 + 1],
            ["evidence_expires_at": now.timeIntervalSince1970 - 1],
            ["evidence_expires_at": NSNull()], ["version": 2], ["plan_id": "invalid"],
            ["launch_authorized": true], ["protection_verified": true], ["status": "unknown"],
            ["service_running": false], ["rules_observed": false], ["manual_recheck_required": true]
        ] {
            let value = try report(changes)
            XCTAssertFalse(value.isCurrent(at: now), "\(changes)")
            XCTAssertEqual(value.layers(at: now).first?.status, "当前未核验")
        }
    }

    func testFaultAndStoppedCannotDisplayHealthyGuard() throws {
        let fault = try report(["status": "fault", "evidence_fresh": false,
                                "manual_recheck_required": true, "reason": "proxy_exit_mismatch"])
        XCTAssertTrue(fault.isCurrent(at: now))
        XCTAssertEqual(fault.layers(at: now).last?.status, "需手动复检")
        let stopped = try report(["status": "stopped", "service_running": false,
                                  "rules_observed": false, "evidence_fresh": false,
                                  "manual_recheck_required": true])
        XCTAssertTrue(stopped.isCurrent(at: now))
        XCTAssertEqual(stopped.layers(at: now).last?.status, "已停止")
    }

    private func timing(_ changes: [String: Any] = [:]) -> [String: Any] {
        var value: [String: Any] = ["phase": "query_return", "evidence_kind": "dns",
            "host": "api.anthropic.com", "record_type": 28, "lifetime_seconds": 1,
            "request_seconds": 2, "remaining_seconds": -1, "age_seconds": 2,
            "http_age_seconds": 0, "checked_at": now.timeIntervalSince1970 - 60]
        value.merge(changes) { _, new in new }; return value
    }

    func testOptionalDiagnosticsPreserveLegacyAndMalformedReportCompatibility() throws {
        XCTAssertNil(try report().fault_diagnostic)
        XCTAssertNil(try report().sampling_diagnostic)
        for invalid: Any in [NSNull(), "private-data", 12, true, [],
                             ["phase": "unknown", "evidence_kind": "dns"],
                             ["phase": "query_return", "evidence_kind": "unknown"]] {
            let value = try report(["fault_diagnostic": invalid, "sampling_diagnostic": invalid])
            XCTAssertTrue(value.isCurrent(at: now))
            XCTAssertNil(value.fault_diagnostic); XCTAssertNil(value.sampling_diagnostic)
            XCTAssertTrue(value.diagnosticLines(at: now).isEmpty)
            XCTAssertEqual(value.layers(at: now).last?.status, "检查运行中")
        }
        XCTAssertThrowsError(try report(["rules_observed": "true", "fault_diagnostic": timing()]))
    }

    func testDiagnosticAllowlistAndNumericBounds() throws {
        let value = try report(["fault_diagnostic": timing([
            "host": "private-data", "record_type": 16, "request_seconds": 86401,
            "remaining_seconds": -86401, "age_seconds": true,
            "checked_at": 100_000_000_001.0, "http_age_seconds": 2_147_483_649,
            "unknown": "private-data"])])
        let diagnostic = try XCTUnwrap(value.fault_diagnostic)
        XCTAssertNil(diagnostic.host); XCTAssertNil(diagnostic.recordType)
        XCTAssertEqual(diagnostic.values, ["lifetime_seconds": 1])
        XCTAssertFalse(diagnostic.lines.joined().contains("private-data"))
        for badAge: Any in [true, -1, 1.5, "0"] {
            XCTAssertNil(try report(["fault_diagnostic": timing(["http_age_seconds": badAge])])
                .fault_diagnostic?.values["http_age_seconds"])
        }
    }

    func testNonFiniteValuesAreDiscardedEvenWithPermissiveDecoder() throws {
        let decoder = JSONDecoder()
        decoder.nonConformingFloatDecodingStrategy = .convertFromString(
            positiveInfinity: "Infinity", negativeInfinity: "-Infinity", nan: "NaN")
        for number in ["NaN", "Infinity", "-Infinity", "private-data"] {
            let data = try JSONSerialization.data(withJSONObject: timing(["request_seconds": number]))
            let value = try decoder.decode(PFTimingDiagnostic.self, from: data)
            XCTAssertNil(value.values["request_seconds"])
            XCTAssertFalse(value.lines.joined().contains(number))
        }
    }

    func testFaultRecordIsHistoricalAndVanishesWithStaleReport() throws {
        let value = try report(["status": "fault", "evidence_fresh": false,
            "manual_recheck_required": true, "reason": "evidence_expired",
            "fault_diagnostic": timing(), "sampling_diagnostic": ["dns_attempts": 1]])
        let text = value.diagnosticLines(at: now).joined(separator: "\n")
        XCTAssertTrue(text.contains("不是当前重新测量")); XCTAssertTrue(text.contains("query_return"))
        XCTAssertTrue(text.contains("AAAA")); XCTAssertTrue(text.contains("-1.000"))
        XCTAssertFalse(text.contains("本轮 DNS 采样 1 次"))
        XCTAssertTrue(value.diagnosticLines(at: now.addingTimeInterval(11)).isEmpty)
        XCTAssertEqual(value.layers(at: now).last?.status, "需手动复检")
        XCTAssertFalse(value.launch_authorized); XCTAssertFalse(StrictProtection.verified)
    }

    func testResamplingOnlyDisplaysInCurrentObservedState() throws {
        let value = try report(["sampling_diagnostic": ["dns_attempts": 2, "prior_expiry": timing()],
                                "fault_diagnostic": timing(["phase": "publication"])])
        let text = value.diagnosticLines(at: now).joined()
        XCTAssertTrue(text.contains("本轮 DNS 采样 2 次")); XCTAssertTrue(text.contains("第一次 DNS 采样的过期记录"))
        XCTAssertFalse(text.contains("publication")); XCTAssertTrue(value.isCurrent(at: now))
        XCTAssertTrue(value.diagnosticLines(at: now.addingTimeInterval(21)).isEmpty)
        let checking = try report(["status": "checking", "evidence_fresh": false,
                                  "sampling_diagnostic": ["dns_attempts": 1]])
        XCTAssertTrue(checking.diagnosticLines(at: now).isEmpty)
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    func testInvalidSamplingCombinationsAreIgnored() throws {
        let invalid: [[String: Any]] = [["dns_attempts": true], ["dns_attempts": 3],
            ["dns_attempts": 1, "prior_expiry": timing()], ["dns_attempts": 2],
            ["dns_attempts": 2, "prior_expiry": timing(["phase": "active_evidence"])],
            ["dns_attempts": 2, "prior_expiry": timing(["evidence_kind": "proxy"])]]
        for sample in invalid {
            let value = try report(["sampling_diagnostic": sample])
            XCTAssertNil(value.sampling_diagnostic); XCTAssertTrue(value.isCurrent(at: now))
            XCTAssertTrue(value.diagnosticLines(at: now).isEmpty)
        }
    }

    func testAcceptanceCycleRetryStagesRemainDiagnosticOnly() throws {
        for phase in ["worker_queue", "pf_check", "publication"] {
            let value = try report(["sampling_diagnostic": ["dns_attempts": 2,
                "prior_expiry": timing(["phase": phase])]])
            XCTAssertEqual(value.sampling_diagnostic?.priorExpiry?.phase, phase)
            XCTAssertTrue(value.diagnosticLines(at: now).joined().contains(phase))
            XCTAssertTrue(value.diagnosticLines(at: now.addingTimeInterval(21)).isEmpty)
            XCTAssertFalse(value.launch_authorized)
            XCTAssertFalse(StrictProtection.verified)
        }
    }

    func testFixedStagesDoNotAlterBaseState() throws {
        for phase in ["query_return", "dns_batch", "exit_wait", "worker_queue", "pf_check", "active_evidence", "publication"] {
            let value = try report(["fault_diagnostic": timing(["phase": phase])])
            XCTAssertEqual(value.fault_diagnostic?.phase, phase)
            XCTAssertTrue(value.isCurrent(at: now)); XCTAssertTrue(value.diagnosticLines(at: now).isEmpty)
        }
    }
}
