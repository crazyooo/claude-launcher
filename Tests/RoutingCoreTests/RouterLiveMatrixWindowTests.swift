import XCTest
@testable import RoutingCore

/// Clear-window live matrix probes (2026-10-24 window). Read-only unless noted.
/// Never invents accepted/routing_verified; refusals and faults are recorded honestly.
final class RouterLiveMatrixWindowTests: XCTestCase {
    private var repoRoot: String {
        let file = #filePath
        guard let range = file.range(of: "/Tests/") else { fatalError("unexpected test path") }
        return String(file[..<range.lowerBound])
    }

    private var evidencePath: String {
        repoRoot + "/web-notes/matrix-clear-window-20261024/live-matrix-evidence.json"
    }

    private var coreExitEvidencePath: String {
        repoRoot + "/web-notes/matrix-clear-window-20261024/core-exit-failclosed-20261025.json"
    }

    private func client() throws -> RouterSystemClient {
        let client = RouterSystemClient()
        _ = try client.request(.status(id: nil)) // throws unavailable → skip upstream
        return client
    }

    /// Bounded probe runner — never uses Process.waitUntilExit (2026-10-25 hang:
    /// Foundation dropped the exit notification with no child/zombie left).
    private func curl(_ arguments: [String], timeout: TimeInterval = 12) -> (exit: Int32, output: String, timedOut: Bool) {
        do {
            let (result, data) = try RouterRuntimeProcess.capture("/usr/bin/curl", arguments, timeout: timeout)
            let text = String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            return (result.exitCode, text, result.timedOut)
        } catch {
            return (-1, "capture_failed", true)
        }
    }

    private func mihomoPIDs() -> [Int32] {
        do {
            let (result, data) = try RouterRuntimeProcess.capture("/usr/bin/pgrep", ["-x", "mihomo"], timeout: 3)
            guard result.settled, !result.timedOut, result.exitCode == 0 else { return [] }
            return String(decoding: data, as: UTF8.self)
                .split(whereSeparator: \.isNewline)
                .compactMap { Int32($0.trimmingCharacters(in: .whitespaces)) }
        } catch {
            return []
        }
    }

    /// Flush evidence as soon as each milestone completes so a later hang cannot erase probes.
    @discardableResult
    private func writeEvidence(_ evidence: [String: Any], to path: String? = nil) -> Bool {
        let target = path ?? evidencePath
        let dir = (target as NSString).deletingLastPathComponent
        do {
            try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            let data = try JSONSerialization.data(withJSONObject: evidence, options: [.prettyPrinted, .sortedKeys])
            try data.write(to: URL(fileURLWithPath: target), options: .atomic)
            print("EVIDENCE_FLUSH \(target)")
            return true
        } catch {
            print("EVIDENCE_FLUSH_FAILED \(error)")
            return false
        }
    }

    /// Step 1 — read-only: helper journal phase + live network observation.
    func testLiveClearWindowReadonlyProbe() throws {
        let client = try client()
        let status = try client.request(.status(id: nil))
        print("STATUS phase=\(status.phase) reason=\(status.reason) instance=\(status.instance?.uuidString.prefix(8) ?? "nil") digest=\(status.planDigest?.prefix(16) ?? "nil")")
        let obs = RouterSystemObservation.collect()
        print("OBS complete=\(obs.complete) capture=\(obs.tunnelCaptureInterfaces) scoped=\(obs.scopedTunnelInterfaces) vpn=\(String(describing: obs.connectedVPN)) appProxy=\(String(describing: obs.applicationProxyEnabled)) autoProxy=\(String(describing: obs.automaticProxyEnabled)) userCore=\(String(describing: obs.userCoreJobPresent))")
        print("FINGERPRINT \(obs.fingerprint)")
    }

    /// Step 1.5 — retry stop after external_environment_changed: owned resources are
    /// actually gone (capture empty, no orphan utun), so a second cleanup sample can
    /// prove completion and flip the journal to stopped (2026-10-23 precedent).
    func testLiveRetryStopAfterExternalChange() throws {
        let client = try client()
        let before = try client.request(.status(id: nil))
        print("BEFORE phase=\(before.phase) reason=\(before.reason) instance=\(before.instance?.uuidString.prefix(8) ?? "nil")")
        guard let id = before.instance else { return XCTFail("no instance") }
        let obs = RouterSystemObservation.collect()
        print("OBS capture=\(obs.tunnelCaptureInterfaces) vpn=\(String(describing: obs.connectedVPN))")
        let stopped = try client.request(.stop(id: id))
        print("STOP phase=\(stopped.phase) reason=\(stopped.reason)")
    }

    /// Step 2 — apply the matrix plan (block example.com, direct default), probe real
    /// traffic through the own TUN, correlate loopback control plane, record evidence,
    /// then stop the instance. Network mutation is inside the granted clear window.
    func testLiveMatrixWindowApplyProbeRecord() throws {
        let client = try client()
        let before = try client.request(.status(id: nil))
        print("BEFORE phase=\(before.phase) reason=\(before.reason)")
        if let id = before.instance, ["prepared", "active", "applying", "fault", "stopping"].contains(before.phase) {
            let stopped = try client.request(.stop(id: id))
            print("PRE_STOP phase=\(stopped.phase) reason=\(stopped.reason)")
        }

        let observation = RouterSystemObservation.collect()
        try RouterSystemProvider.requireClear(observation) // refuse instead of mutating
        print("CLEAR ok fingerprint=\(observation.fingerprint)")

        // Matrix plan: default direct + explicit block of a neutral target so the
        // block path has a real semantic to verify. No proxy line ⇒ no credentials.
        // Profile .plain: LAN-viable UDP resolvers — the DoH archetypes' upstream
        // (Cloudflare/Quad9 + 1.1.1.1 bootstrap) is unreachable on this LAN and a
        // dead core-side resolver blackholes every hostname during takeover
        // (live evidence 2026-10-25 matrix window).
        let blockRule = RouterRule(id: UUID(), selector: .init(domain: .init(kind: .exact, value: "example.com")),
                                   destination: .block)
        let plan = RouterPlan(proxies: [], rules: [blockRule], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .plain)
        let id = UUID()
        var evidence: [String: Any] = [
            "date": "2026-10-25",
            "window": RouterTunApplyExecuteGate.clearWindowID,
            "instance": id.uuidString,
            "plan": ["defaultDestination": "direct", "rules": ["example.com=block"]],
            "profile": "plain",
            "accepted": false,
            "routing_verified": false,
            "canPromoteAccepted": false,
            "canClaimMatrixComplete": false,
            "provenance": "bounded RouterRuntimeProcess.capture; incremental evidence flush; default route from observation (no route waitUntilExit)",
        ]
        writeEvidence(evidence)

        let prepared = try client.request(.prepare(id: id, plan: plan, profile: profile))
        XCTAssertEqual(prepared.phase, "prepared")
        let applied = try client.request(.apply(id: id, credentials: []))
        print("APPLY phase=\(applied.phase) reason=\(applied.reason)")

        var last = applied
        for _ in 0..<40 {
            Thread.sleep(forTimeInterval: 0.25)
            last = try client.request(.status(id: id))
            if ["active", "fault", "stopped"].contains(last.phase) { break }
        }
        print("ACTIVE phase=\(last.phase) reason=\(last.reason) routingVerified=\(last.routingVerified)")
        evidence["phase"] = last.phase
        evidence["reason"] = last.reason
        writeEvidence(evidence)
        XCTAssertEqual(last.phase, "active", "instance must be active for probes")

        // Real system probes through the own TUN (curl as a controlled test process).
        // NOTE: PF fail-closed anchor expected armed (160.79.104.10) after operator re-arm.
        let directProbe = curl(["-4", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", "https://www.apple.com/"])
        evidence["probes"] = [
            "direct_apple": ["exit": Int(directProbe.exit), "http": directProbe.output, "timedOut": directProbe.timedOut],
        ]
        writeEvidence(evidence)
        print("PROBE direct(apple) exit=\(directProbe.exit) out=\(directProbe.output) timedOut=\(directProbe.timedOut)")

        let blockProbe = curl(["-4", "-sS", "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}", "http://example.com/"])
        var probes = evidence["probes"] as? [String: Any] ?? [:]
        probes["block_example"] = ["exit": Int(blockProbe.exit), "http": blockProbe.output, "timedOut": blockProbe.timedOut]
        evidence["probes"] = probes
        writeEvidence(evidence)
        print("PROBE block(example.com) exit=\(blockProbe.exit) out=\(blockProbe.output) timedOut=\(blockProbe.timedOut)")

        // 1.1.1.1 is a known-bad TLS control on this LAN (exit 35 pre-existing, 2026-10-24/25).
        // Record honestly; do not assert exit==0 (that would force a false green).
        let remoteIPProbe = curl(["-4", "-sS", "--max-time", "8", "-k", "-o", "/dev/null", "-w", "%{http_code}", "https://1.1.1.1/"])
        probes = evidence["probes"] as? [String: Any] ?? [:]
        probes["remote_ip_cloudflare"] = [
            "exit": Int(remoteIPProbe.exit),
            "http": remoteIPProbe.output,
            "timedOut": remoteIPProbe.timedOut,
            "verdict": remoteIPProbe.exit == 0
                ? "PASS"
                : "ENV_LAN_TLS - known broken control on this LAN; not a routing failure",
        ]
        evidence["probes"] = probes
        writeEvidence(evidence)
        print("PROBE remote-ip(1.1.1.1) exit=\(remoteIPProbe.exit) out=\(remoteIPProbe.output) timedOut=\(remoteIPProbe.timedOut)")

        let pfGuardProbe = curl(["-4", "-sS", "--noproxy", "*", "--max-time", "6", "-o", "/dev/null", "-w", "%{http_code}", "https://160.79.104.10/"], timeout: 10)
        probes = evidence["probes"] as? [String: Any] ?? [:]
        probes["pf_guard_anthropic"] = [
            "exit": Int(pfGuardProbe.exit),
            "http": pfGuardProbe.output,
            "timedOut": pfGuardProbe.timedOut,
            "verdict": pfGuardProbe.exit == 28 ? "PASS - armed drop" : "FAIL - PF not armed or unexpected exit",
        ]
        evidence["probes"] = probes
        writeEvidence(evidence)
        print("PROBE pf-guard(anthropic-ip) exit=\(pfGuardProbe.exit) out=\(pfGuardProbe.output) timedOut=\(pfGuardProbe.timedOut)")

        XCTAssertEqual(directProbe.exit, 0, "direct cell must pass through own TUN")
        XCTAssertFalse(directProbe.timedOut, "direct cell must settle within bound")
        XCTAssertNotEqual(blockProbe.exit, 0, "blocked domain must be refused by plan rule")
        XCTAssertEqual(pfGuardProbe.exit, 28, "PF guard stays independently armed")

        // Loopback control-plane correlation with explicit one-shot arming.
        let arming = RouterHitCorrelationEntry.arm(mode: .tcpNumeric)
        let gate = RouterHitCorrelationGate.decide(arming: arming, mode: .tcpNumeric,
                                                   systemPhase: last.phase, systemInstance: last.instance,
                                                   refuseOwnTun: false)
        guard case .allow(let instance) = gate else {
            evidence["hitCorrelation_loopback"] = ["outcome": "notRun", "reason": "gate_refused"]
            writeEvidence(evidence)
            return XCTFail("gate refused")
        }
        let reply = try client.hitCorrelation(.init(request: UUID(), instance: instance,
                                                    mode: .tcpNumeric, arming: arming,
                                                    address: "127.0.0.1", port: RouterSystemCompiler.controllerPort,
                                                    serverName: nil))
        evidence["hitCorrelation_loopback"] = [
            "outcome": reply.outcome,
            "reason": reply.reason,
            "relation": (reply.relation as Any?) ?? NSNull(),
            "collectorAuthenticated": reply.collectorAuthenticated,
        ]
        writeEvidence(evidence)
        print("HITCORR outcome=\(reply.outcome) reason=\(reply.reason) relation=\(reply.relation ?? "nil") collectorAuthenticated=\(reply.collectorAuthenticated)")

        // Default route via re-observation — avoids /usr/sbin/route waitUntilExit hang.
        let postObs = RouterSystemObservation.collect()
        evidence["route_default"] = [
            "ipv4": postObs.defaultIPv4Interfaces,
            "ipv6": postObs.defaultIPv6Interfaces,
            "capture": postObs.tunnelCaptureInterfaces,
        ]
        writeEvidence(evidence)
        print("ROUTE ipv4=\(postObs.defaultIPv4Interfaces) capture=\(postObs.tunnelCaptureInterfaces)")

        let stopped = try client.request(.stop(id: id))
        evidence["stop"] = ["phase": stopped.phase, "reason": stopped.reason]
        writeEvidence(evidence)
        print("STOP phase=\(stopped.phase) reason=\(stopped.reason)")
    }

    /// #8 — armed + kill core differential (2026-10-24 post-exit precedent).
    /// Proves PF destination drop survives core death; never claims canClaimFailClosedProven.
    /// PF unload/hook-restore remains an operator sudo step after this test.
    func testLiveCoreExitFailClosedDifferential() throws {
        let client = try client()
        let before = try client.request(.status(id: nil))
        print("BEFORE phase=\(before.phase) reason=\(before.reason)")
        if let existing = before.instance, ["prepared", "active", "applying", "fault", "stopping"].contains(before.phase) {
            let stopped = try client.request(.stop(id: existing))
            print("PRE_STOP phase=\(stopped.phase) reason=\(stopped.reason)")
        }

        let observation = RouterSystemObservation.collect()
        try RouterSystemProvider.requireClear(observation)
        print("CLEAR ok fingerprint=\(observation.fingerprint)")

        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .plain)
        let id = UUID()
        var evidence: [String: Any] = [
            "date": "2026-10-25",
            "event": "core_exit_failclosed_differential",
            "window": RouterTunApplyExecuteGate.clearWindowID,
            "instance": id.uuidString,
            "profile": "plain",
            "accepted": false,
            "routing_verified": false,
            "protection_verified": false,
            "canClaimFailClosedProven": false,
            "note": "REJECT≠proof; differential curl only. PF unload/hook-restore is a separate operator step.",
        ]
        writeEvidence(evidence, to: coreExitEvidencePath)

        _ = try client.request(.prepare(id: id, plan: plan, profile: profile))
        let applied = try client.request(.apply(id: id, credentials: []))
        var last = applied
        for _ in 0..<40 {
            Thread.sleep(forTimeInterval: 0.25)
            last = try client.request(.status(id: id))
            if ["active", "fault", "stopped"].contains(last.phase) { break }
        }
        print("ACTIVE phase=\(last.phase) reason=\(last.reason)")
        evidence["lifecycle"] = ["apply_phase": last.phase, "apply_reason": last.reason]
        writeEvidence(evidence, to: coreExitEvidencePath)
        XCTAssertEqual(last.phase, "active")

        let coresAlive = mihomoPIDs()
        print("CORE_ALIVE pids=\(coresAlive)")
        XCTAssertFalse(coresAlive.isEmpty, "mihomo must be running before kill")

        let armedAliveAnthropic = curl(["-4", "-sS", "--noproxy", "*", "--max-time", "6",
                                        "-o", "/dev/null", "-w", "%{http_code}", "https://160.79.104.10/"], timeout: 10)
        let armedAliveApple = curl(["-4", "-sS", "--noproxy", "*", "--max-time", "8",
                                    "-o", "/dev/null", "-w", "%{http_code}", "https://www.apple.com/"])
        evidence["probes_core_alive"] = [
            "mihomo_pids": coresAlive.map(Int.init),
            "anthropic": ["exit": Int(armedAliveAnthropic.exit), "http": armedAliveAnthropic.output],
            "apple": ["exit": Int(armedAliveApple.exit), "http": armedAliveApple.output],
        ]
        writeEvidence(evidence, to: coreExitEvidencePath)
        print("PROBE_ALIVE anthropic=\(armedAliveAnthropic.exit) apple=\(armedAliveApple.exit)/\(armedAliveApple.output)")
        XCTAssertEqual(armedAliveAnthropic.exit, 28, "PF must drop anthropic while core alive")
        XCTAssertEqual(armedAliveApple.exit, 0)
        XCTAssertEqual(armedAliveApple.output, "200")

        // Kill core via helper stop (user cannot SIGKILL root-owned mihomo — 2026-10-25
        // live evidence). Helper signals its direct child; no respawn. PF stays armed.
        let stopped = try client.request(.stop(id: id))
        print("STOP phase=\(stopped.phase) reason=\(stopped.reason)")
        let killDeadline = ProcessInfo.processInfo.systemUptime + 8
        while ProcessInfo.processInfo.systemUptime < killDeadline, !mihomoPIDs().isEmpty {
            Thread.sleep(forTimeInterval: 0.15)
        }
        let coresGone = mihomoPIDs()
        let postObs = RouterSystemObservation.collect()
        print("CORE_GONE remaining=\(coresGone) capture=\(postObs.tunnelCaptureInterfaces)")
        evidence["kill"] = [
            "method": "helper_stop",
            "stop_phase": stopped.phase,
            "stop_reason": stopped.reason,
            "signaled_pids": coresAlive.map(Int.init),
            "remaining": coresGone.map(Int.init),
            "capture_after": postObs.tunnelCaptureInterfaces,
        ]
        writeEvidence(evidence, to: coreExitEvidencePath)
        XCTAssertTrue(coresGone.isEmpty, "mihomo must be gone after helper stop")

        let armedGoneAnthropic = curl(["-4", "-sS", "--noproxy", "*", "--max-time", "6",
                                       "-o", "/dev/null", "-w", "%{http_code}", "https://160.79.104.10/"], timeout: 10)
        let armedGoneApple = curl(["-4", "-sS", "--noproxy", "*", "--max-time", "8",
                                   "-o", "/dev/null", "-w", "%{http_code}", "https://www.apple.com/"])
        let differentialOK = coresGone.isEmpty && armedGoneAnthropic.exit == 28
            && armedGoneApple.exit == 0 && armedGoneApple.output == "200"
        evidence["probes_core_gone"] = [
            "mihomo_pids": coresGone.map(Int.init),
            "anthropic": ["exit": Int(armedGoneAnthropic.exit), "http": armedGoneAnthropic.output],
            "apple": ["exit": Int(armedGoneApple.exit), "http": armedGoneApple.output],
            "verdict": differentialOK
                ? "PASS_differential_armed_core_gone"
                : "FAIL_unexpected_exits",
        ]
        evidence["stop"] = ["phase": stopped.phase, "reason": stopped.reason]
        evidence["operator_next"] = [
            "unload": "sudo /opt/homebrew/bin/python3 -S tools/router_pf_failclosed.py unload --i-confirm-unload",
            "hook_restore": "sudo /opt/homebrew/bin/python3 -S tools/router_pf_root_hook.py restore --journal-dir /var/root/claude-router-fc-journal-20261025 --i-confirm-restore-hook",
            "post_unload_expect": "anthropic should no longer exit 28 (differential unload side)",
        ]
        writeEvidence(evidence, to: coreExitEvidencePath)
        print("PROBE_GONE anthropic=\(armedGoneAnthropic.exit) apple=\(armedGoneApple.exit)/\(armedGoneApple.output) verdict=\(differentialOK)")
        XCTAssertEqual(armedGoneAnthropic.exit, 28, "PF drop must survive core death")
        XCTAssertEqual(armedGoneApple.exit, 0)
        XCTAssertEqual(armedGoneApple.output, "200")
        print("OPERATOR_NEXT unload then hook-restore; then re-probe anthropic")
    }
}
