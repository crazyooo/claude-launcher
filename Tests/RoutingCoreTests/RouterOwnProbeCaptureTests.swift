import XCTest
import Darwin
@testable import RoutingCore

final class RouterOwnProbeCaptureTests: XCTestCase {
    private final class Harness {
        let base: RouterSystemDispatchFixture
        var state: RouterSystemJournal
        var bodies = 0, contexts = 0, verifications = 0, closes = 0, opens = 0
        var secret = String(repeating: "a", count: 64)
        var listener: UInt64 = 8
        var processUID: UInt32 = 0
        var ownPath = "/test/owned-probe"
        var customRows: [[String: Any]]?
        var connectHook: (() throws -> Void)?
        var clockOverride: (() -> RouterSystemClock)?
        var openOverride: ((String, UInt16, TimeInterval) throws -> RouterOwnedTCPProbe)?
        var io: RouterOwnedTCPIO.Effects?
        var targetPort: UInt16 = 443
        var clock: RouterSystemClock { clockOverride?() ?? base.clock }
        var localAddress = "192.0.2.2", targetAddress = "203.0.113.1"
        let intent: RouterSystemIntent
        var bodyHook: ((Int) throws -> Void)?
        var contextHook: ((Int) throws -> Void)?
        var verifyHook: ((Int) throws -> Void)?
        var malformed = false, rowCount = 0
        var events: [String] = []
        init(plan: RouterPlan? = nil, boot: UUID = UUID()) throws {
            base = try RouterSystemDispatchFixture(boot: boot)
            let original = base.intent, plan = plan ?? original.plan
            intent = .init(id: original.id, plan: plan, profile: original.profile,
                digest: try RouterSystemCompiler.digest(plan: plan, profile: original.profile),
                networkFingerprint: original.networkFingerprint, issued: original.issued,
                expiresAt: original.expiresAt, deadlineUptime: original.deadlineUptime)
            let fence = try base.baseline.create(intent: intent, configurationDigest: base.digest,
                                                 host: base.host, snapshot: base.snapshot())
            state = .empty(); state.installation = base.identity; state.intent = intent
            state.phase = .active; state.reason = "capture_observed_traffic_acceptance_pending"
            state.work = base.work; state.dispatch = fence; state.configurationDigest = base.digest
            state.footprint = .init(instance: base.intent.id, work: base.work, configurationDigest: base.digest,
                interfaceName: "utun9", interfaceIndex: 9, addresses: ["198.18.0.1"], routeSignatures: ["fixture"])
        }
        func body() throws -> Data {
            if malformed { return Data("{}".utf8) }
            let rows: [[String: Any]] = customRows ?? (0..<rowCount).map { _ in
                ["id": UUID().uuidString, "start": "1970-01-01T00:16:42.001Z", "upload": 1, "download": 1,
                 "rule": "Match", "rulePayload": "", "chains": ["DIRECT"],
                 "metadata": ["network": "tcp", "type": "Tun", "process": "owned-probe", "processPath": "/test/owned-probe",
                    "sourceIP": localAddress, "sourcePort": "45000", "destinationIP": targetAddress,
                    "destinationPort": "443", "host": "", "sniffHost": "", "dnsMode": "normal",
                    "specialProxy": "", "specialRules": "", "rematchName": ""]]
            }
            return try JSONSerialization.data(withJSONObject: ["uploadTotal": 1, "downloadTotal": 1, "connections": rows])
        }
        func run() throws -> RouterSystemConnections.OwnProbeObservation {
            try sampler().observeOwnTCP(address: targetAddress, port: targetPort)
        }
        func echo() throws -> RouterSystemConnections.OwnEchoObservation {
            try sampler().observeOwnTCPEchoFixture(address: targetAddress, port: targetPort)
        }
        func sampler() -> RouterSystemConnections {
            let readers = RouterSystemConnections.Readers(load: { _ in self.state },
                material: { _ in .init(secret: self.secret, redactions: [self.secret]) },
                process: { _ in .init(work: self.base.work, uid: self.processUID, realUID: self.processUID,
                                     parentPID: self.base.host.pid, processGroup: self.base.host.pid) },
                listeners: { _, _ in .observed([.init(descriptor: 8, generation: self.listener)]) },
                body: { _, _ in
                    self.bodies += 1; self.events.append("body"); try self.bodyHook?(self.bodies)
                    return try self.body()
                }, clock: { let now = self.clock; return (now.date, now.uptime) })
            let probe = RouterSystemConnections.ProbeReaders(clock: { self.clock },
                open: { address, port, deadline in
                    self.opens += 1; self.events.append("open")
                    if let open = self.openOverride { return try open(address, port, deadline) }
                    return try .fixture(endpoint: .init(address: address, port: port), until: deadline, effects: .init(
                        clock: { self.clock }, process: {
                            .init(identity: .init(work: self.base.host, uid: 501, realUID: 501,
                                                  parentPID: 1, processGroup: self.base.host.pid), path: self.ownPath)
                        }, create: { _ in 42 }, configure: { _, _ in }, connect: { _, _, _ in try self.connectHook?() },
                        tuple: { _ in
                            self.events.append("tuple")
                            return try .init(local: .init(address: self.localAddress, port: 45000),
                                             peer: .init(address: self.targetAddress, port: self.targetPort))
                        }, close: { _ in self.closes += 1; self.events.append("close") }, io: self.io))
                }, context: { state, _ in
                    self.contexts += 1; self.events.append("context"); try self.contextHook?(self.contexts)
                    let fence = try XCTUnwrap(state.dispatch)
                    let binding = RouterTrafficBinding(phase: .active, installation: self.base.identity,
                        instance: self.base.intent.id, revision: state.revision, work: self.base.work,
                        planDigest: self.intent.digest, configurationDigest: self.base.digest,
                        stageReceiptDigest: String(repeating: "c", count: 64), baselineID: fence.baselineID,
                        baselineDigest: fence.baselineDigest, networkFingerprint: self.base.intent.networkFingerprint,
                        coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
                        compilerPolicy: RouterSystemCompiler.policyVersion)
                    return .init(binding: binding, network: self.base.snapshot(captured: self.clock), verify: {
                        self.verifications += 1; self.events.append("verify")
                        XCTAssertEqual(self.closes, 0, "descriptor must remain held through every source verification")
                        try self.verifyHook?(self.verifications)
                    })
                })
            return RouterSystemConnections(identity: base.identity, readers: readers, fixtureProbe: probe)
        }
    }

    private func echoHarness() throws -> Harness {
        let h = try Harness()
        h.localAddress = "127.0.0.1"; h.targetAddress = "127.0.0.1"
        var response = Data()
        h.io = .init(send: { fd, bytes in
            XCTAssertEqual(fd, 42)
            let nonce = try! RouterTCPEchoWire.parseRequest(Data(bytes.dropFirst(4)))
            response = try! RouterTCPEchoWire.response(nonce, actualPeerIP: "127.0.0.1")
            h.events.append("send")
            h.base.uptime += 0.1; h.base.seconds += 0.1
            return (bytes.count, 0)
        }, receive: { fd, maximum in
            XCTAssertEqual(fd, 42)
            h.events.append("receive")
            let bytes = Data(response.prefix(maximum)); response = response.dropFirst(bytes.count)
            h.base.uptime += 0.1; h.base.seconds += 0.1
            return (bytes, 0)
        }, poll: { _, _, _ in XCTFail("script is ready"); return (-1, EIO, 0) })
        return h
    }
    func testEchoUsesOriginalCaptureSequenceAndCannotPromoteAcceptance() throws {
        let h = try echoHarness()
        let result = try h.echo()
        XCTAssertEqual(h.bodies, 3); XCTAssertEqual(h.contexts, 2); XCTAssertEqual(h.verifications, 5)
        XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1); XCTAssertEqual(h.events.last, "close")
        XCTAssertTrue(result.socketObservation.socketInterval.contains(result.exchange.interval))
        XCTAssertLessThanOrEqual(result.exchange.interval.end.uptime, result.socketObservation.controllerInterval.start.uptime)
        XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
        XCTAssertNil(h.state.accepted); XCTAssertNil(h.state.previousAccepted)
    }
    func testCompletedEchoCannotBypassSourceNetworkOrTupleMutation() throws {
        for kind in 0..<4 {
            let h = try echoHarness()
            h.bodyHook = { count in
                guard count == 2 else { return }
                XCTAssertTrue(h.events.contains("receive"))
                switch kind {
                case 0: h.state.revision = UUID()
                case 1: h.secret = String(repeating: "d", count: 64)
                case 2: h.localAddress = "127.0.0.2"
                default: h.base.dns += "\nchanged\n"
                }
            }
            XCTAssertThrowsError(try h.echo(), "\(kind)")
            XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
        }
    }
    func testEchoExternalTargetRejectedBeforeReadersOrOpen() throws {
        for address in ["203.0.113.1", "::1%en0"] {
            let h = try Harness()
            h.targetAddress = address
            XCTAssertThrowsError(try h.echo())
            XCTAssertEqual(h.bodies, 0); XCTAssertEqual(h.opens, 0)
        }
    }
    func testNoPayloadCaptureDoesNotCallInjectedIO() throws {
        let h = try echoHarness()
        _ = try h.run()
        XCTAssertFalse(h.events.contains("send")); XCTAssertFalse(h.events.contains("receive"))
    }
    func testRealLoopbackExchangeInsideExplicitFixtureController() throws {
        for family in [AF_INET, AF_INET6] {
            let server = try RouterLoopbackEchoFixture(family: family)
            defer { server.stop() }
            let boot = try RouterSystemKernelObservation.clock().bootID
            let h = try Harness(boot: boot)
            h.clockOverride = { .init(bootID: boot, uptime: ProcessInfo.processInfo.systemUptime, date: Date()) }
            h.targetAddress = server.target.address; h.targetPort = server.target.port
            h.openOverride = { address, port, deadline in
                try .loopbackFixture(endpoint: .init(address: address, port: port), until: deadline)
            }
            let result = try h.echo()
            let serverResult = try server.finish()
            XCTAssertEqual(result.exchange.reply.nonce, serverResult.0)
            XCTAssertEqual(result.exchange.reply.serverReportedPeerIP, serverResult.1)
            XCTAssertEqual(result.socketObservation.socket.process.identity.work.pid, getpid())
            XCTAssertEqual(h.bodies, 3); XCTAssertEqual(h.contexts, 2); XCTAssertEqual(h.verifications, 5)
            XCTAssertTrue(result.socketObservation.trackers.isEmpty, "fixture must not invent Tun rows for loopback")
            XCTAssertFalse(result.collectorAuthenticated)
            XCTAssertEqual(try RouterTrafficCorrelator.evaluateOwn(result.socketObservation,
                plan: h.intent.plan, profile: h.intent.profile).relation, .insufficient)
        }
    }

    private func ownRow(ipv6: Bool = false) -> [String: Any] {
        ["id": UUID().uuidString, "start": "1970-01-01T00:16:42.250Z", "upload": 1, "download": 1,
         "rule": "Match", "rulePayload": "", "chains": ["DIRECT"],
         "metadata": ["network": "tcp", "type": "Tun", "process": "owned-probe", "processPath": "/test/owned-probe",
            "sourceIP": ipv6 ? "2001:db8::2" : "192.0.2.2", "sourcePort": "45000",
            "destinationIP": ipv6 ? "2001:db8::1" : "203.0.113.1", "destinationPort": "443",
            "host": "", "sniffHost": "", "dnsMode": "normal", "specialProxy": "", "specialRules": "", "rematchName": ""]]
    }
    private func metadata(_ row: [String: Any], _ key: String, _ value: Any) -> [String: Any] {
        var row = row
        var fields = row["metadata"] as! [String: Any]
        fields[key] = value; row["metadata"] = fields
        return row
    }
    private func captureOwn(_ rows: [[String: Any]], prior: [[String: Any]] = [],
                            plan: RouterPlan? = nil, ipv6: Bool = false) throws ->
        (RouterSystemConnections.OwnProbeObservation, RouterSystemIntent, Harness) {
        let h = try Harness(plan: plan)
        if ipv6 { h.localAddress = "2001:db8::2"; h.targetAddress = "2001:db8::1" }
        h.connectHook = { h.base.uptime += 0.5; h.base.seconds += 0.5 }
        h.bodyHook = { count in
            h.customRows = count == 1 ? prior : rows
            if count > 1 { h.base.uptime += 0.25; h.base.seconds += 0.25 }
        }
        let result = try h.run()
        XCTAssertEqual(h.closes, 1)
        XCTAssertNil(h.state.accepted); XCTAssertNil(h.state.previousAccepted)
        return (result, h.intent, h)
    }
    private func correlateOwn(_ rows: [[String: Any]], prior: [[String: Any]] = [],
                              plan: RouterPlan? = nil, ipv6: Bool = false) throws -> RouterTrafficCorrelationResult {
        let (observed, intent, _) = try captureOwn(rows, prior: prior, plan: plan, ipv6: ipv6)
        return try RouterTrafficCorrelator.evaluateOwn(observed, plan: intent.plan, profile: intent.profile)
    }

    func testOwnTrackerCreatedDuringConnectUsesStartNotReady() throws {
        let row = ownRow(), (observed, intent, _) = try captureOwn([row])
        XCTAssertEqual(observed.connectStartedAt.uptime, 12)
        XCTAssertEqual(observed.socketInterval.start.uptime, 12.5)
        XCTAssertLessThan(try XCTUnwrap(observed.trackers.first).startedAt, observed.socketInterval.start.date)
        let result = try RouterTrafficCorrelator.evaluateOwn(observed, plan: intent.plan, profile: intent.profile)
        XCTAssertEqual(result.relation, .candidateUnverified)
        XCTAssertEqual(result.reason, "own_tcp_candidate_incomplete")
        XCTAssertEqual(result.connection?.uuidString, row["id"] as? String)
        XCTAssertEqual(result.compiledOrdinal, 0)
        let encoded = try RouterTrafficCodec.encode(result)
        let publicResult = try JSONSerialization.jsonObject(with: encoded) as! [String: Any]
        XCTAssertEqual(publicResult["collectorAuthenticated"] as? Bool, false)
        XCTAssertEqual(publicResult["canPromoteAccepted"] as? Bool, false)
        XCTAssertEqual(Set(publicResult["gaps"] as! [String]), ["ruleUncorrelated", "liveCollectorUnavailable"])
        XCTAssertFalse(String(decoding: encoded, as: UTF8.self).contains("/test/owned-probe"))
    }
    func testOwnOldBoundaryAndPreexistingTrackersStayUncertain() throws {
        for time in ["41.999", "42.000", "42.750", "42.751"] {
            var row = ownRow(); row["start"] = "1970-01-01T00:16:" + time + "Z"
            XCTAssertEqual(try correlateOwn([row]).reason, "no_current_probe_tracker", time)
        }
        let current = ownRow()
        var old = current; old["start"] = "1970-01-01T00:16:41.000Z"
        XCTAssertEqual(try correlateOwn([current], prior: [old]).reason, "tracker_predates_own_connect")
        XCTAssertEqual(try correlateOwn([current, ownRow()], prior: [old]).reason, "ambiguous_probe_tracker")
        var rows = (0..<100).map { _ in metadata(ownRow(), "sourcePort", "45001") }
        rows += [current, ownRow()]
        XCTAssertEqual(try correlateOwn(rows).reason, "ambiguous_probe_tracker")
    }
    func testOwnPlanAndResolverMustMatchObservedBinding() throws {
        let (observed, intent, _) = try captureOwn([ownRow()])
        var otherPlan = intent.plan; otherPlan.defaultDestination = .block
        XCTAssertThrowsError(try RouterTrafficCorrelator.evaluateOwn(observed, plan: otherPlan, profile: intent.profile))
        XCTAssertThrowsError(try RouterTrafficCorrelator.evaluateOwn(observed, plan: intent.plan,
            profile: .init(resolver: .cloudflare)))
    }
    func testOwnNumericRequestCannotSkipUnknownEarlierDomain() throws {
        let plan = RouterPlan(proxies: [], rules: [.init(id: UUID(),
            selector: .init(domain: .init(kind: .suffix, value: "example.com")), destination: .block)],
            defaultDestination: .direct)
        XCTAssertEqual(try correlateOwn([ownRow()], plan: plan).reason, "earlier_rule_identity_unknown")
        XCTAssertEqual(try correlateOwn([metadata(ownRow(), "host", "example.com")]).reason, "probe_domain_mismatch")
        XCTAssertEqual(try correlateOwn([metadata(ownRow(), "dnsMode", "fake-ip")]).reason, "fake_ip_dns_mapping_not_bound")
    }
    func testOwnTupleProcessAndIngressMustMatch() throws {
        let row = ownRow()
        for (key, value) in [("sourcePort", "45001"), ("sourceIP", "192.0.2.3"),
                             ("destinationPort", "80"), ("network", "udp"), ("type", "HTTP")] {
            XCTAssertEqual(try correlateOwn([metadata(row, key, value)]).reason, "no_current_probe_tracker", key)
        }
        XCTAssertEqual(try correlateOwn([metadata(row, "destinationIP", "203.0.113.2")]).reason, "probe_destination_not_bound")
        XCTAssertEqual(try correlateOwn([metadata(row, "processPath", "/other/app")]).reason, "full_process_path_missing_or_changed")
        XCTAssertEqual(try correlateOwn([metadata(row, "specialProxy", "DIRECT")]).reason, "unmodelled_override_or_sniff_domain")
        XCTAssertEqual(try correlateOwn([metadata(row, "sniffHost", "example.com")]).reason, "unmodelled_override_or_sniff_domain")
    }
    func testOwnRuleOrderAndFullSignatureAreChecked() throws {
        let proxy = UUID()
        let plan = RouterPlan(proxies: [.init(id: proxy, name: "Local", kind: .http, host: "127.0.0.1", port: 1082)],
            rules: [.init(id: UUID(), selector: .init(processPath: "/other/app", domain: .init(kind: .exact, value: "example.com")), destination: .block),
                    .init(id: UUID(), selector: .init(processPath: "/test/owned-probe"), destination: .proxy(proxy))],
            defaultDestination: .direct)
        var row = ownRow()
        row["rule"] = "ProcessPath"; row["rulePayload"] = "/test/owned-probe"
        row["chains"] = ["route_" + proxy.uuidString.lowercased()]
        let result = try correlateOwn([row], plan: plan)
        XCTAssertEqual(result.relation, .candidateUnverified)
        XCTAssertEqual(result.compiledOrdinal, 2, "earlier AND rule and UDP guard retain compiler order")
        for (key, value) in [("rule", "Match" as Any), ("rulePayload", "/other/app" as Any),
                             ("chains", ["DIRECT"] as Any), ("chains", ["extra", "route_" + proxy.uuidString.lowercased()] as Any)] {
            var changed = row; changed[key] = value
            XCTAssertEqual(try correlateOwn([changed], plan: plan).reason, "compiled_rule_or_chain_mismatch")
        }
    }
    func testOwnRejectCandidateNeverProvesBlocking() throws {
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .block)
        var row = ownRow(); row["chains"] = ["REJECT"]
        let result = try correlateOwn([row], plan: plan)
        XCTAssertEqual(result.reason, "own_tcp_reject_controls_still_required")
        XCTAssertEqual(result.relation, .candidateUnverified)
        XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
        XCTAssertEqual(try correlateOwn([], plan: plan).relation, .insufficient)
    }
    func testOwnIPv6AddressesCompareAsBytes() throws {
        let row = metadata(ownRow(ipv6: true), "sourceIP", "2001:0db8:0:0:0:0:0:2")
        XCTAssertEqual(try correlateOwn([row], ipv6: true).relation, .candidateUnverified)
    }

    func testWholePrivateObservationHoldsSocketThroughLastSourceChecks() throws {
        let h = try Harness(), revision = h.state.revision
        h.rowCount = 101
        let result = try h.run()
        XCTAssertEqual(result.source, .fixture)
        XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
        XCTAssertEqual(result.trackers.count, 101, "public UI truncation cannot discard private candidates")
        XCTAssertEqual(result.socket.process.path, "/test/owned-probe")
        XCTAssertEqual(result.binding.instance, h.base.intent.id)
        XCTAssertEqual(h.bodies, 3); XCTAssertEqual(h.contexts, 2); XCTAssertEqual(h.verifications, 5)
        XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
        XCTAssertEqual(h.events.last, "close")
        XCTAssertEqual(h.state.revision, revision)
        XCTAssertNil(h.state.accepted); XCTAssertNil(h.state.previousAccepted)
    }
    func testEveryEvidenceMutationBetweenCapturesDiscardsResultAndCloses() throws {
        for kind in 0..<5 {
            let h = try Harness()
            h.bodyHook = { count in
                if count == 2 {
                    switch kind {
                    case 0: h.state.revision = UUID()
                    case 1: h.secret = String(repeating: "d", count: 64)
                    case 2: h.listener += 1
                    case 3: h.processUID = 501
                    default: h.ownPath = "/changed/image"
                    }
                }
            }
            XCTAssertThrowsError(try h.run(), "\(kind)")
            XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
        }
    }
    func testSelectedControllerBodyIsInsideNetworkBracketNotFinalPostcheck() throws {
        let h = try Harness()
        h.bodyHook = { count in
            h.rowCount = count
            h.base.uptime += 0.25; h.base.seconds += 0.25
        }
        let result = try h.run()
        XCTAssertEqual(result.trackers.count, 2, "last body is outside the network bracket")
        XCTAssertEqual(result.controllerInterval.end.uptime, 12.5)
        XCTAssertEqual(result.socketInterval.start.uptime, 12.25)
        XCTAssertEqual(result.interval.start.uptime, 12)
        XCTAssertEqual(result.interval.end.uptime, 12.75)
        XCTAssertTrue(result.socketInterval.contains(result.controllerInterval))
        XCTAssertEqual(h.closes, 1)
    }
    func testStageAndBaselineVerificationFailuresDiscardResultBeforeClose() throws {
        for failureAt in 1...5 {
            let h = try Harness()
            h.verifyHook = { count in
                if count == failureAt { throw RouterTrafficEvidenceError.sourceChanged }
            }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.closes, failureAt == 1 ? 0 : 1)
        }
    }
    func testSmallWallClockReversalCannotBreakControllerNetworkBracket() throws {
        let h = try Harness()
        h.bodyHook = { count in
            if count == 2 { h.base.uptime += 1; h.base.seconds += 1 }
        }
        h.contextHook = { count in if count == 2 { h.base.seconds -= 0.5 } }
        XCTAssertThrowsError(try h.run())
        XCTAssertEqual(h.closes, 1)
    }
    func testInitialNetworkSampleCannotFollowConnectStart() throws {
        let h = try Harness()
        h.contextHook = { count in
            if count == 1 { h.base.uptime += 0.5; h.base.seconds += 0.5 }
        }
        h.verifyHook = { count in
            if count == 1 { h.base.uptime -= 0.25; h.base.seconds -= 0.25 }
        }
        h.connectHook = { h.base.uptime += 0.5; h.base.seconds += 0.5 }
        // Total operation and ready/controller intervals remain ordered. Only
        // the initial network sample is later than this connection's start.
        XCTAssertThrowsError(try h.run()) {
            XCTAssertEqual($0 as? RouterTrafficEvidenceError, .sourceChanged)
        }
        XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
    }
    func testDNSRoutesInterfacesAndDeadlineChangesDiscardResult() throws {
        for kind in 0..<5 {
            let h = try Harness()
            h.contextHook = { count in
                guard count == 2 else { return }
                switch kind {
                case 0: h.base.dns = h.base.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54")
                case 1: h.base.v4 = h.base.v4.replacingOccurrences(of: "192.0.2.1", with: "192.0.2.3")
                case 2: h.base.devices = []
                case 3: h.base.uptime += 60; h.base.seconds += 60
                default: h.base.seconds -= 5
                }
            }
            XCTAssertThrowsError(try h.run(), "\(kind)")
            XCTAssertEqual(h.closes, 1)
        }
    }
    func testMalformedControllerAtEveryStageNeverReturnsPartialObservation() throws {
        for failureAt in 1...3 {
            let h = try Harness()
            h.bodyHook = { count in if count == failureAt { h.malformed = true } }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.opens, failureAt == 1 ? 0 : 1)
            XCTAssertEqual(h.closes, h.opens)
        }
    }
    func testContextFailureAfterConnectionClosesAndNoAutomaticRetry() throws {
        let h = try Harness()
        h.contextHook = { count in if count == 2 { throw RouterOwnedProbeError.unavailable } }
        XCTAssertThrowsError(try h.run())
        XCTAssertEqual(h.contexts, 2); XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
    }
    func testCancellationWhileSocketHeldClosesWithoutReturningObservation() async throws {
        let h = try Harness()
        let error = await Task { () -> RouterOwnedProbeError? in
            h.bodyHook = { count in
                if count == 2 { withUnsafeCurrentTask { $0?.cancel() } }
            }
            do { _ = try h.run(); return nil }
            catch { return error as? RouterOwnedProbeError }
        }.value
        XCTAssertEqual(error, .cancelled)
        XCTAssertEqual(h.opens, 1); XCTAssertEqual(h.closes, 1)
    }

    func testAcceptanceCollectorAssemblesOnlyCorrelatedAttemptAndStillRefusesSeal() throws {
        let (observed, intent, h) = try captureOwn([ownRow()])
        let collection = try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: intent.plan, profile: intent.profile,
            observations: [observed], source: .fixtureHarness)

        XCTAssertEqual(collection.receipt.records.count, 1)
        let record = try XCTUnwrap(collection.receipt.records.first)
        XCTAssertNil(record.id.rule)
        XCTAssertEqual(record.id.variation, .fallback)
        XCTAssertEqual(record.id.transport, .tcp)
        XCTAssertEqual(record.id.family, .ipv4)
        XCTAssertEqual(record.bindingDigest, try observed.binding.digest())
        XCTAssertEqual(collection.assessment.cases.count, 12)
        XCTAssertFalse(collection.assessment.canPromoteAccepted)
        XCTAssertEqual(collection.assessment.status, "incomplete")
        let assessed = try XCTUnwrap(collection.assessment.cases.first { $0.id == record.id })
        XCTAssertTrue(assessed.gaps.contains(.notRun))
        XCTAssertTrue(assessed.gaps.contains(.ruleUncorrelated))
        XCTAssertTrue(RouterSystemProvider.validDigest(collection.evidenceDigest))
        XCTAssertNotEqual(collection.evidenceDigest, intent.digest)

        let seal = collection.evidenceSeal()
        XCTAssertFalse(seal.canPromote)
        if case .refuse(let reason) = RouterAcceptancePromotion.decide(
            plan: intent.plan, profile: intent.profile, configurationDigest: intent.digest, seal: seal) {
            XCTAssertEqual(reason, "live_collector_unavailable")
        } else {
            XCTFail("collector receipt must not promote")
        }
        XCTAssertNil(h.state.accepted); XCTAssertNil(h.state.previousAccepted)
    }

    func testAcceptanceCollectorRejectsSourceAndBindingDrift() throws {
        let (observed, intent, h) = try captureOwn([ownRow()])
        XCTAssertThrowsError(try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: intent.plan, profile: intent.profile,
            observations: [observed], source: .installedReaders)) { error in
            XCTAssertEqual(error as? RouterTrafficEvidenceError, .sourceChanged)
        }

        h.state.revision = UUID()
        XCTAssertThrowsError(try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: intent.plan, profile: intent.profile,
            observations: [observed], source: .fixtureHarness)) { error in
            XCTAssertEqual(error as? RouterTrafficEvidenceError, .sourceChanged)
        }
    }

    func testAcceptanceCollectorNeverFillsUnobservedOrWrongPlanCoverage() throws {
        let (observed, intent, h) = try captureOwn([ownRow()])
        var wrongPlan = intent.plan
        wrongPlan.defaultDestination = .block
        XCTAssertThrowsError(try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: wrongPlan, profile: intent.profile,
            observations: [observed], source: .fixtureHarness)) { error in
            XCTAssertEqual(error as? RouterTrafficEvidenceError, .invalidReceipt)
        }
        XCTAssertThrowsError(try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: intent.plan, profile: intent.profile,
            observations: [], source: .fixtureHarness)) { error in
            XCTAssertEqual(error as? RouterTrafficEvidenceError, .invalidReceipt)
        }

        let collection = try RouterSystemAcceptanceCollector.collect(
            state: h.state, plan: intent.plan, profile: intent.profile,
            observations: [observed], source: .fixtureHarness)
        XCTAssertEqual(collection.receipt.records.count, 1)
        XCTAssertEqual(collection.assessment.cases.filter { $0.gaps == [.notRun] }.count, 11)
        XCTAssertTrue(collection.assessment.cases.allSatisfy { !$0.gaps.isEmpty })
    }
}
