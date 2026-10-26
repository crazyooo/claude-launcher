import XCTest
@testable import LauncherCore

/// P1 display copy: wording must never imply full protection, expired/unverified must stay distinct.
final class DisplayCopyTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    /// Words that would read as "Claude is protected" while StrictProtection.verified == false.
    private let banned = ["已保护", "已受保护", "已开启保护", "保护已开启", "安全", "正常", "全部通过", "已就绪"]

    private var settings: PreflightSettings { var v = PreflightSettings(); v.expectedIP = "203.0.113.43"; return v }
    private func preflight() -> PreflightReport {
        let target = CheckTarget.desktop
        let ids = ["baseline", "client", "transport", "service", "unchanged"] + target.hosts.map { "exit:" + $0 }
        let observations = target.hosts.map {
            DomainObservation(host: $0, ip: "203.0.113.43", country: "US", transport: "http://127.0.0.1:1082",
                              milliseconds: 10, check: .init("exit:" + $0, $0, .passed, "fixture"))
        }
        return .init(target: target, startedAt: now, completedAt: now, context: "known",
                     checks: ids.map { .init($0, $0, .passed, "fixture") }, observations: observations)
    }
    private func pf(_ changes: [String: Any] = [:]) throws -> PFObservation {
        var value: [String: Any] = [
            "version": 1, "plan_id": String(repeating: "a", count: 32), "checked_at": now.timeIntervalSince1970,
            "service_running": true, "rules_observed": true, "evidence_fresh": true, "manual_recheck_required": false,
            "status": "observed", "reason": "same_addresses_observed", "evidence_expires_at": now.timeIntervalSince1970 + 20,
            "protection_verified": false, "launch_authorized": false]
        value.merge(changes) { _, new in new }
        return try JSONDecoder().decode(PFObservation.self, from: JSONSerialization.data(withJSONObject: value))
    }
    private func assertClean(_ text: String, _ context: String, file: StaticString = #filePath, line: UInt = #line) {
        for word in banned { XCTAssertFalse(text.contains(word), "“\(word)” in \(context): \(text)", file: file, line: line) }
    }
    private let details = ["proxy_doh_failed", "proxy_doh_timeout", "proxy_doh_connect_failed", "proxy_doh_tls_failed",
                           "proxy_doh_http_failed", "proxy_doh_too_large", "proxy_doh_json_invalid", "proxy_doh_exec_failed",
                           "proxy_doh_headers_invalid", "proxy_doh_age_invalid", "proxy_doh_cleanup_failed",
                           "dns_question_or_status_invalid", "dns_answers_invalid", "dns_cname_loop", "dns_owner_ambiguous",
                           "dns_ttl_invalid", "dns_address_invalid", "dns_family_mismatch", "dns_cname_invalid",
                           "dns_cname_too_deep", "destination_evidence_expired", "query_evidence_expired_or_invalid",
                           "incomplete_query_evidence", "query_answer_count_mismatch", "unexpected_dns_source",
                           "renewal_requires_host_addresses", "proxy_evidence_stale", "dns_ttl_shorter_than_sample"]

    func testNoWordingImpliesProtectionWhileUnverified() throws {
        XCTAssertFalse(StrictProtection.verified)
        for state in DisplayState.allCases { assertClean(state.label + state.meaning, "DisplayState.\(state)") }
        for reason in PFObservation.knownReasons {
            for detail in [nil] + details.map(Optional.some) {
                let guide = PFObservation.guide(reason: reason, detail: detail)
                assertClean(guide.title + guide.explanation + guide.nextStep, "guide \(reason)/\(detail ?? "-")")
                XCTAssertFalse(guide.nextStep.isEmpty)
            }
        }
        let unavailable = PFObservation.unavailableGuide
        assertClean(unavailable.title + unavailable.explanation + unavailable.nextStep, "unavailableGuide")
        let gates = ConsoleProjection.gates(report: preflight(), settings: settings, target: .desktop, checking: false,
                                            now: now, firewall: try pf(), controller: nil, endpoint: "")
        assertClean(ConsoleGate.overall(gates), "overall")
        for gate in gates { assertClean(gate.summary, "gate \(gate.id)") }
        for (date, context, checking) in [(now, "known", false), (now.addingTimeInterval(31), "known", false),
                                          (now, "changed", false), (now, "known", true)] {
            let status = ProtectionStatus(report: preflight(), settings: settings, context: context, checking: checking,
                                          now: date, firewall: try pf())
            assertClean(status.networkStatus + status.explanation, "preflight \(context)")
        }
        let empty = ProtectionStatus(report: nil, settings: settings, context: nil, checking: false, now: now)
        assertClean(empty.networkStatus + empty.explanation, "preflight empty")
        for report in [try pf(), try pf(["status": "fault", "evidence_fresh": false, "manual_recheck_required": true,
                                         "reason": "evidence_expired", "evidence_expires_at": NSNull()])] {
            assertClean(PFObservation.statusLine(report, now: now), "statusLine")
        }
        assertClean(PFObservation.statusLine(nil, now: now), "statusLine nil")
    }

    func testPassingProbeIsScopedAndLaunchStaysLocked() {
        let status = ProtectionStatus(report: preflight(), settings: settings, context: "known", checking: false, now: now)
        XCTAssertTrue(status.networkPassed)
        XCTAssertEqual(status.networkStatus, "出口探测匹配（仅本轮）")
        XCTAssertTrue(status.explanation.contains("受保护启动仍锁定"))
        XCTAssertEqual(status.validUntil, now.addingTimeInterval(30))
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    func testExpiredAndUnverifiedStayDistinct() {
        XCTAssertEqual(DisplayState(.stale), .expired)
        XCTAssertEqual(DisplayState(.unknown), .unverified)
        XCTAssertNotEqual(DisplayState.expired.label, DisplayState.unverified.label)
        let late = ProtectionStatus(report: preflight(), settings: settings, context: "known", checking: false,
                                    now: now.addingTimeInterval(31))
        XCTAssertTrue(late.networkStatus.hasPrefix("已过期"))
        XCTAssertNil(late.validUntil)
        let none = ProtectionStatus(report: nil, settings: settings, context: nil, checking: false, now: now)
        XCTAssertTrue(none.networkStatus.hasPrefix("未验证"))
        let gates = ConsoleProjection.gates(report: preflight(), settings: settings, target: .desktop, checking: false,
                                            now: now.addingTimeInterval(31), firewall: nil, controller: nil, endpoint: "")
        XCTAssertFalse(gates.flatMap(\.evidence).contains { $0.state == .observed && $0.id == "probe-exit" })
        XCTAssertTrue(gates.flatMap(\.evidence).contains { $0.state == .expired })
        XCTAssertTrue(gates.flatMap(\.evidence).contains { $0.state == .unverified })
    }

    func testEveryGateKeepsUnacceptedItemsUnverified() {
        let gates = ConsoleProjection.gates(report: preflight(), settings: settings, target: .desktop, checking: false,
                                            now: now, firewall: nil, controller: nil, endpoint: "")
        for gate in gates {
            XCTAssertNotEqual(gate.state, .observed, gate.id)
            XCTAssertGreaterThan(gate.count(.unverified) + gate.count(.expired) + gate.count(.failed), 0, gate.id)
            XCTAssertFalse(gate.summary.isEmpty)
        }
        XCTAssertTrue(ConsoleGate.overall(gates).contains("未验证"))
    }

    func testStaleOrFaultReportNeverShowsEvidenceExpiry() throws {
        XCTAssertEqual(PFObservation.statusLine(try pf(["checked_at": now.timeIntervalSince1970 - 11]), now: now), "后台报告不可用")
        XCTAssertEqual(PFObservation.statusLine(nil, now: now), "后台报告不可用")
        let fault = try pf(["status": "fault", "evidence_fresh": false, "manual_recheck_required": true,
                            "reason": "dns_refresh_failed", "fault_detail": "destination_evidence_expired",
                            "evidence_expires_at": NSNull()])
        XCTAssertNil(fault.evidenceExpiresDate)
        XCTAssertTrue(PFObservation.statusLine(fault, now: now).hasPrefix("需手动复检"))
        XCTAssertTrue(fault.guide.nextStep.contains("recheck_command"))
        let fresh = try pf()
        XCTAssertEqual(fresh.evidenceExpiresDate, now.addingTimeInterval(20))
        XCTAssertTrue(PFObservation.statusLine(fresh, now: now).contains("仅限批准地址"))
        XCTAssertTrue(fresh.guide.explanation.contains("只覆盖"))
        XCTAssertFalse(fresh.launch_authorized)
    }

    func testAddressChangeNeverSuggestsPlainRecheck() {
        let guide = PFObservation.guide(reason: "address_or_proxy_policy_changed", detail: nil)
        XCTAssertTrue(guide.explanation.contains("没有被拦截"))
        XCTAssertTrue(guide.nextStep.contains("不要只做复检"))
    }

    // MARK: P2 layout copy and topology

    private func topology(at time: Date? = nil, report: PreflightReport?, selected: CheckTarget = .desktop,
                          checking: Bool = false, firewall: PFObservation?) -> Topology {
        let at = time ?? now
        var statuses: [CheckTarget: ProtectionStatus] = [:]
        for target in CheckTarget.allCases {
            let sample = report?.target == target ? report : nil
            statuses[target] = ProtectionStatus(report: sample, settings: settings, context: sample?.context,
                                                checking: checking, now: at, firewall: firewall)
        }
        let bound = report?.target == selected ? report : nil
        var connector = ConnectorSnapshot(); connector.port = 1; connector.state = "blocked"; connector.sampledAt = at
        let gates = ConsoleProjection.gates(report: bound, settings: settings, target: selected, checking: checking,
                                            now: at, firewall: firewall, controller: nil, endpoint: "", connector: connector)
        return Topology.build(selected: selected, statuses: statuses, report: bound, gates: gates, firewall: firewall,
                              connector: connector, controller: nil, endpoint: "", now: at)
    }
    private func scenarios() throws -> [(String, Topology)] {
        let fault = try pf(["status": "fault", "evidence_fresh": false, "manual_recheck_required": true,
                            "reason": "dns_refresh_failed", "fault_detail": "dns_ttl_shorter_than_sample", "evidence_expires_at": NSNull()])
        return [("fresh", topology(report: preflight(), firewall: try pf())),
                ("late", topology(at: now.addingTimeInterval(31), report: preflight(), firewall: try pf())),
                ("none", topology(report: nil, firewall: nil)),
                ("checking", topology(report: preflight(), checking: true, firewall: try pf())),
                ("other-entry", topology(report: preflight(), selected: .vscode, firewall: try pf())),
                ("pf-fault", topology(report: preflight(), firewall: fault)),
                ("pf-stale", topology(at: now.addingTimeInterval(11), report: preflight(), firewall: try pf()))]
    }

    func testP2DetailCopyIsClean() throws {
        for id in GateCopy.ids {
            assertClean(GateCopy.scope(id) + GateCopy.limitation(id), "GateCopy \(id)")
            XCTAssertFalse(GateCopy.limitation(id).isEmpty, id)
        }
        assertClean(Topology.footnote, "footnote")
        assertClean(TopologyEdge.Kind.observedPath.legend + TopologyEdge.Kind.dependency.legend, "edge legend")
        XCTAssertTrue(TopologyEdge.Kind.dependency.legend.contains("不代表流量经过"))
        for column in TopologyNode.Column.allCases { assertClean(column.title, "column") }
        for (name, topo) in try scenarios() {
            for node in topo.nodes {
                let text = ([node.title, node.subtitle, node.scope, node.limitation, GateCopy.nextStep(node)] + node.facts).joined()
                assertClean(text, "\(name)/\(node.id)")
                XCTAssertFalse(node.limitation.isEmpty, node.id)
            }
        }
        let guide = PFObservation.guide(reason: "dns_refresh_failed", detail: "dns_ttl_shorter_than_sample")
        for at in [now, now.addingTimeInterval(31)] {
            for gate in ConsoleProjection.gates(report: preflight(), settings: settings, target: .desktop, checking: false,
                                                now: at, firewall: nil, controller: nil, endpoint: "") {
                let step = GateCopy.nextStep(gate, pfGuide: guide)
                XCTAssertFalse(step.isEmpty, gate.id)
                assertClean(step, "nextStep \(gate.id)")
            }
        }
    }

    func testTopologySolidEdgesOnlyFromCurrentPassingPreflight() throws {
        let all = Dictionary(uniqueKeysWithValues: try scenarios().map { ($0.0, $0.1) })
        let fresh = all["fresh"]!.edges.filter { $0.kind == .observedPath }
        XCTAssertTrue(fresh.contains { $0.from == "app-desktop" && $0.to == "infra-proxy" })
        XCTAssertEqual(Set(fresh.filter { $0.from == "infra-proxy" }.map(\.to)), Set(CheckTarget.desktop.hosts.map { "svc-" + $0 }))
        for name in ["late", "none", "checking", "other-entry"] {
            XCTAssertFalse(all[name]!.edges.contains { $0.kind == .observedPath }, name)
            XCTAssertFalse(all[name]!.nodes.contains { $0.column == .service && $0.state == .observed }, name)
        }
        for (name, topo) in all {
            for edge in topo.edges {
                if edge.to.hasPrefix("svc-") || edge.from.hasPrefix("app-") && edge.to == "infra-proxy" {
                    XCTAssertEqual(edge.kind, .observedPath, "\(name) \(edge.id)")
                }
                if edge.from.hasPrefix("gate-") { XCTAssertEqual(edge.kind, .dependency, "\(name) \(edge.id)") }
                XCTAssertNotNil(topo.node(edge.from), edge.id); XCTAssertNotNil(topo.node(edge.to), edge.id)
            }
        }
    }

    func testTopologyNeverUpgradesStaleOrMissingEvidence() throws {
        let all = Dictionary(uniqueKeysWithValues: try scenarios().map { ($0.0, $0.1) })
        XCTAssertEqual(all["fresh"]!.node("infra-pf")?.state, .observed)
        XCTAssertEqual(all["pf-stale"]!.node("infra-pf")?.state, .expired)
        XCTAssertEqual(all["pf-stale"]!.node("infra-observer")?.state, .expired)
        XCTAssertEqual(all["none"]!.node("infra-pf")?.state, .unverified)
        XCTAssertEqual(all["pf-fault"]!.node("infra-observer")?.state, .failed)
        XCTAssertEqual(all["none"]!.node("infra-mihomo")?.state, .unverified)
        XCTAssertEqual(all["late"]!.node("app-desktop")?.state, .expired)
        XCTAssertEqual(all["none"]!.node("app-desktop")?.state, .unverified)
        for (name, topo) in all {
            for node in topo.nodes(in: .gate) { XCTAssertNotEqual(node.state, .observed, "\(name)/\(node.id)") }
        }
        XCTAssertFalse(StrictProtection.verified)
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }

    // MARK: P3 topology polish

    func testP3NodeDetailCopyAndTimesAreClean() throws {
        for (name, topo) in try scenarios() {
            assertClean(topo.pathNote, "\(name) pathNote")
            for node in topo.nodes {
                assertClean(node.times.joined(), "\(name)/\(node.id) times")
                for edge in topo.edges(touching: node.id) { assertClean(topo.describe(edge, from: node.id), "\(name) \(edge.id)") }
                XCTAssertTrue(DisplayState.legend.contains(node.state), node.id)
            }
        }
        assertClean(Topology.noEdgesNote, "noEdgesNote")
        XCTAssertTrue(TopologyEdge.Kind.observedPath.legend.contains("仅在预检有效期内"))
        XCTAssertTrue(TopologyEdge.Kind.dependency.legend.contains("不代表流量经过"))
    }

    func testP3TimesNeverClaimValidityForStaleSamples() throws {
        let all = Dictionary(uniqueKeysWithValues: try scenarios().map { ($0.0, $0.1) })
        XCTAssertTrue(all["fresh"]!.node("app-desktop")!.times.contains { $0.hasPrefix("预检有效至") })
        XCTAssertTrue(all["fresh"]!.node("infra-observer")!.times.contains { $0.hasPrefix("DNS 证据有效至") })
        let late = all["late"]!
        XCTAssertFalse(late.nodes.flatMap(\.times).contains { $0.hasPrefix("预检有效至") })
        XCTAssertTrue(late.node("app-desktop")!.times.contains("预检已失效（不再作为当前证据）"))
        for name in ["late", "pf-stale", "none", "pf-fault"] {
            XCTAssertFalse(all[name]!.nodes.flatMap(\.times).contains { $0.hasPrefix("DNS 证据有效至") }, name)
        }
        XCTAssertTrue(all["none"]!.nodes.allSatisfy { $0.id.hasPrefix("gate-") || $0.id == "infra-connector" || $0.times.isEmpty })
        XCTAssertTrue(all["checking"]!.node("app-desktop")!.times.isEmpty)
        XCTAssertTrue(all["late"]!.pathNote.hasPrefix("当前没有实线"))
        XCTAssertFalse(all["fresh"]!.pathNote.hasPrefix("当前没有实线"))
    }

    func testP3NoProcessNodesNoBypassEdgesAndHighlightStaysLocal() throws {
        let prefixes = ["app-", "gate-", "infra-", "svc-"]
        for (name, topo) in try scenarios() {
            for node in topo.nodes { XCTAssertTrue(prefixes.contains { node.id.hasPrefix($0) }, "\(name)/\(node.id)") }
            let infra = Set(topo.nodes(in: .infra).map(\.id))
            XCTAssertEqual(infra, ["infra-proxy", "infra-connector", "infra-pf", "infra-observer", "infra-mihomo"], name)
            let solid = topo.edges.filter { $0.kind == .observedPath }
            XCTAssertLessThanOrEqual(solid.count, 1 + CheckTarget.desktop.hosts.count, name)
            for edge in solid {
                XCTAssertTrue(edge.from == "infra-proxy" || edge.to == "infra-proxy", "\(name) \(edge.id)")
                XCTAssertEqual(topo.node(edge.from)?.state, .observed, "\(name) \(edge.id)")
                XCTAssertEqual(topo.node(edge.to)?.state, .observed, "\(name) \(edge.id)")
            }
            XCTAssertFalse(topo.edges.contains { $0.from.hasPrefix("svc-") || $0.to.hasPrefix("gate-") && !$0.from.hasPrefix("app-") }, name)
            for node in topo.nodes {
                let hood = topo.neighborhood(of: node.id)
                XCTAssertTrue(hood.contains(node.id))
                for id in hood where id != node.id {
                    XCTAssertTrue(topo.edges.contains { ($0.from == node.id && $0.to == id) || ($0.to == node.id && $0.from == id) })
                }
            }
        }
        XCTAssertFalse(StrictProtection.verified)
    }

    func testTimingDetailsFollowFreshnessWithoutChangingTopologyStatesOrEdges() throws {
        let base: [String: Any] = ["status": "fault", "evidence_fresh": false,
                                  "manual_recheck_required": true, "reason": "evidence_expired"]
        var extended = base
        extended["fault_diagnostic"] = ["phase": "query_return", "evidence_kind": "dns",
                                        "remaining_seconds": -1, "request_seconds": 2]
        let before = topology(report: preflight(), firewall: try pf(base))
        let after = topology(report: preflight(), firewall: try pf(extended))
        XCTAssertEqual(before.nodes.map(\.state), after.nodes.map(\.state))
        XCTAssertEqual(before.edges.map(\.id), after.edges.map(\.id))
        let text = after.node("infra-observer")!.facts.joined()
        XCTAssertTrue(text.contains("query_return")); assertClean(text, "diagnostic facts")
        let stale = topology(at: now.addingTimeInterval(11), report: preflight(), firewall: try pf(extended))
        XCTAssertFalse(stale.node("infra-observer")!.facts.joined().contains("query_return"))
        XCTAssertEqual(stale.node("infra-observer")?.state, .expired)
        XCTAssertFalse(StrictProtection.verified)
    }

    func testQueryCleanupAndExecutionGuidanceDoesNotBlameProxy() {
        for detail in ["proxy_doh_cleanup_failed", "proxy_doh_exec_failed"] {
            let guide = PFObservation.guide(reason: "dns_refresh_failed", detail: detail)
            XCTAssertFalse(guide.nextStep.contains("你的代理客户端"))
            XCTAssertTrue(guide.explanation.contains("不能"))
            XCTAssertNotNil(guide.technical)
            assertClean(guide.title + guide.explanation + guide.nextStep, detail)
        }
    }
}
