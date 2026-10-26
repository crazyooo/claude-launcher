import XCTest
@testable import LauncherCore

final class CurrentPathPortraitTests: XCTestCase {
    func testProxyChannelParsingAndListenerClassification() {
        let object: [String: Any] = [
            "HTTPEnable": 1, "HTTPProxy": "127.0.0.1", "HTTPPort": 1082,
            "HTTPSEnable": 0, "HTTPSProxy": "127.0.0.1", "HTTPSPort": 1082,
            "SOCKSEnable": 1, "SOCKSProxy": "10.0.0.2", "SOCKSPort": 1080
        ]
        let channels = CurrentPathPortrait.parseProxyChannels(object) { host, port in
            if host == "127.0.0.1", port == 1082 { return "refused" }
            return "not_local"
        }
        XCTAssertEqual(channels.map(\.id), ["http", "https", "socks"])
        XCTAssertEqual(channels[0].enabled, true)
        XCTAssertEqual(channels[0].listener, "refused")
        XCTAssertEqual(channels[1].enabled, false)
        XCTAssertEqual(channels[1].listener, "inactive")
        XCTAssertEqual(channels[2].listener, "not_local")
    }

    func testFindingsKeepAcceptanceFalseAndDescribeTunnelConflict() {
        let id = UUID()
        let targets: [CurrentPathPortrait.TargetObservation] = [
            .init(host: "chatgpt.com", resolved: "1.2.3.4", routeInterface: "en0", routeKind: "physical", reachability: "timed_out"),
            .init(host: "claude.ai", resolved: "198.18.0.56", routeInterface: "utun8", routeKind: "tunnel", reachability: "reached_403")
        ]
        let lines: [CurrentPathPortrait.LineObservation] = [
            .init(lineID: id, name: "mei", host: "203.0.113.43", port: 9034,
                  routeInterface: "utun8", routeKind: "tunnel", note: "经隧道")
        ]
        let proxies: [CurrentPathPortrait.SystemProxyChannel] = [
            .init(id: "http", title: "HTTP", enabled: true, host: "127.0.0.1", port: 1082, listener: "refused"),
            .init(id: "https", title: "HTTPS", enabled: false, host: nil, port: nil, listener: "inactive"),
            .init(id: "socks", title: "SOCKS", enabled: false, host: nil, port: nil, listener: "inactive")
        ]
        let findings = CurrentPathPortrait.composeFindings(
            proxies: proxies,
            candidates: [.init(name: "en0", index: 15, address: "192.168.3.121")],
            targets: targets, lines: lines)
        XCTAssertTrue(CurrentPathPortrait.isFakeMappedIPv4("198.18.0.56"))
        XCTAssertTrue(CurrentPathPortrait.isFakeMappedIPv4("198.19.1.2"))
        XCTAssertFalse(CurrentPathPortrait.isFakeMappedIPv4("1.2.3.4"))
        XCTAssertTrue(findings.contains(where: { $0.contains("端口拒绝连接") }))
        XCTAssertTrue(findings.contains(where: { $0.contains("chatgpt.com") && $0.contains("不经系统代理") && $0.contains("超时") }))
        XCTAssertTrue(findings.contains(where: { $0.contains("假地址") && $0.contains("不代表你没开代理") }))
        XCTAssertTrue(findings.contains(where: { $0.contains("mei") && $0.contains("路径对照") }))
        XCTAssertTrue(findings.contains(where: { $0.contains("routing_verified") || $0.contains("accepted") }))
        let steps = CurrentPathPortrait.composeNextSteps(proxies: proxies, targets: targets, lines: lines)
        XCTAssertTrue(steps.contains(where: { $0.contains("路径对照") }))
        XCTAssertTrue(steps.contains(where: { $0.contains("不经系统代理") }))
        XCTAssertTrue(steps.contains(where: { $0.contains("检查现有网络") && $0.contains("requireClear") }))
        XCTAssertFalse(targets[1].detail.contains("直连有回应"))
        XCTAssertTrue(targets[1].detail.contains("假地址"))
        XCTAssertTrue(targets[1].detail.contains("不经系统代理有回应"))
        let snapshot = CurrentPathPortrait.Snapshot(
            capturedAt: Date(timeIntervalSince1970: 1), summary: "x", findings: findings, nextSteps: steps,
            candidates: [], proxies: [], targets: [], lines: [],
            routingVerified: true, accepted: true)
        XCTAssertFalse(snapshot.routingVerified)
        XCTAssertFalse(snapshot.accepted)
    }

    func testCaptureUsesInjectedEffectsAndDoesNotInventAcceptance() {
        let lineID = UUID()
        let effects = CurrentPathPortrait.Effects(
            proxies: { ["HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0] },
            listen: { _, _ in XCTFail("disabled proxy should not listen"); return "inactive" },
            resolve: { host in host == "chatgpt.com" ? "203.0.113.10" : "203.0.113.11" },
            route: { address in
                address == "203.0.113.10"
                    ? .init(interface: "en0", kind: "physical")
                    : .init(interface: "utun8", kind: "tunnel")
            },
            reach: { host in host == "chatgpt.com" ? "timed_out" : "reached_403" },
            candidates: { [.init(name: "en0", index: 4, address: "192.168.1.2")] },
            lineReport: { host in
                .init(summary: "到该入口的当前系统路由接口是 utun8（隧道）。", candidates: [],
                      routeKind: "tunnel", ownTunEnablement: "blockedWhileForeignCapture", comparisonIsAcceptance: false)
            }
        )
        let snapshot = CurrentPathPortrait.capture(
            lines: [.init(id: lineID, name: "mei", host: "203.0.113.43", port: 9034)],
            effects: effects, now: Date(timeIntervalSince1970: 42))
        XCTAssertEqual(snapshot.candidates.map(\.name), ["en0"])
        XCTAssertEqual(snapshot.targets.count, CurrentPathPortrait.observationHosts.count)
        XCTAssertEqual(snapshot.lines.first?.routeKind, "tunnel")
        XCTAssertTrue(snapshot.findings.contains(where: { $0.contains("路径对照") }))
        XCTAssertTrue(snapshot.summary.contains("不是分流验收") || snapshot.findings.contains(where: { $0.contains("accepted") }))
        XCTAssertFalse(snapshot.routingVerified)
        XCTAssertFalse(snapshot.accepted)
        XCTAssertFalse(snapshot.summary.contains("检查通过"))
    }

    func testHostnameSavedLineDoesNotCallLineReport() {
        var reported = 0
        let effects = CurrentPathPortrait.Effects(
            proxies: { ["HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0] },
            listen: { _, _ in "inactive" },
            resolve: { _ in nil },
            route: { _ in nil },
            reach: { _ in "unresolved" },
            candidates: { [] },
            lineReport: { _ in
                reported += 1
                return .init(summary: "", candidates: [], routeKind: "unknown", ownTunEnablement: "unknown")
            }
        )
        let snapshot = CurrentPathPortrait.capture(
            lines: [.init(id: UUID(), name: "x", host: "proxy.example", port: 443)],
            effects: effects)
        XCTAssertEqual(reported, 0)
        XCTAssertEqual(snapshot.lines.first?.routeKind, "hostname")
        XCTAssertTrue(snapshot.lines.first?.note.contains("不是 IPv4") == true)
    }
}
