import XCTest
import Darwin
@testable import RoutingCore

final class RouterTLSCaptureTests: XCTestCase {
    private typealias Capture = RouterSystemConnections.OwnTLSObservation
    private final class Harness {
        let base: RouterSystemDispatchFixture
        let peer: RouterTLSFixture
        var state: RouterSystemJournal
        var bodies = 0, contexts = 0, verifications = 0, opens = 0
        var heldDeadline: TimeInterval?
        var heldReaderDeadlines: [TimeInterval] = []
        var sample: RouterTLSConnection.Sample?
        var bodyHook: ((Int) throws -> Void)?
        var contextHook: ((Int) throws -> Void)?
        var verifyHook: ((Int) throws -> Void)?
        var rowsHook: ((Int, [[String: Any]]) -> [[String: Any]])?
        var secret = String(repeating: "a", count: 64)
        var generation: UInt64 = 8
        let tracker = UUID(), lastTracker = UUID()
        var priorTracker = false
        init(_ peer: RouterTLSFixture) throws {
            self.peer = peer
            base = try RouterSystemDispatchFixture(boot: RouterSystemKernelObservation.clock().bootID)
            let fence = try base.baseline.create(intent: base.intent, configurationDigest: base.digest,
                                                 host: base.host, snapshot: base.snapshot())
            state = .empty(); state.installation = base.identity; state.intent = base.intent
            state.phase = .active; state.reason = "capture_observed_traffic_acceptance_pending"
            state.work = base.work; state.dispatch = fence; state.configurationDigest = base.digest
            state.footprint = .init(instance: base.intent.id, work: base.work, configurationDigest: base.digest,
                interfaceName: "utun9", interfaceIndex: 9, addresses: ["198.18.0.1"], routeSignatures: ["fixture"])
        }
        deinit {
            do { try FileManager.default.trashItem(at: base.url, resultingItemURL: nil) }
            catch { XCTFail("Cannot trash owned capture fixture directory") }
        }
        func rows() throws -> [[String: Any]] {
            guard let sample else {
                guard priorTracker else { return [] }
                return [row(id: tracker, path: "/test/prior", local: "127.0.0.1", localPort: 44000,
                            remote: peer.ready.host, remotePort: peer.ready.port, at: Date())]
            }
            let tuple = sample.socket.socket.tuple
            return [row(id: bodies == 3 ? lastTracker : tracker, path: sample.socket.process.path,
                        local: tuple.local.address, localPort: tuple.local.port,
                        remote: tuple.peer.address, remotePort: tuple.peer.port, at: sample.socket.interval.end.date)]
        }
        private func row(id: UUID, path: String, local: String, localPort: UInt16,
                         remote: String, remotePort: UInt16, at: Date) -> [String: Any] {
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            return ["id": id.uuidString, "start": formatter.string(from: at), "upload": 1, "download": 1,
                "rule": "Match", "rulePayload": "", "chains": ["DIRECT"], "metadata": [
                    "network": "tcp", "type": "Tun", "process": "test", "processPath": path,
                    "sourceIP": local, "sourcePort": String(localPort), "destinationIP": remote,
                    "destinationPort": String(remotePort), "host": "", "sniffHost": "", "dnsMode": "normal",
                    "specialProxy": "", "specialRules": "", "rematchName": ""]]
        }
        func deadline(_ value: TimeInterval) {
            if heldDeadline != nil { heldReaderDeadlines.append(value) }
        }
        func sampler(includeTLS: Bool = true) -> RouterSystemConnections {
            let readers = RouterSystemConnections.Readers(load: { limit in
                self.deadline(limit); return self.state
            }, material: { _ in .init(secret: self.secret, redactions: [self.secret]) },
            process: { _ in .init(work: self.base.work, uid: 0, realUID: 0,
                                 parentPID: self.base.host.pid, processGroup: self.base.host.pid) },
            listeners: { _, limit in
                self.deadline(limit); return .observed([.init(descriptor: 8, generation: self.generation)])
            }, body: { _, limit in
                self.deadline(limit); self.bodies += 1; try self.bodyHook?(self.bodies)
                let rows = try self.rows()
                return try JSONSerialization.data(withJSONObject: ["uploadTotal": 1, "downloadTotal": 1,
                    "connections": self.rowsHook?(self.bodies, rows) ?? rows])
            }, clock: { (Date(), ProcessInfo.processInfo.systemUptime) })
            var probe = RouterSystemConnections.ProbeReaders(clock: RouterSystemKernelObservation.clock,
                open: { _, _, _ in throw RouterOwnedProbeError.unavailable }, context: { state, limit in
                    self.deadline(limit); self.contexts += 1; try self.contextHook?(self.contexts)
                    let fence = try XCTUnwrap(state.dispatch)
                    let binding = RouterTrafficBinding(phase: .active, installation: self.base.identity,
                        instance: self.base.intent.id, revision: state.revision, work: self.base.work,
                        planDigest: self.base.intent.digest, configurationDigest: self.base.digest,
                        stageReceiptDigest: String(repeating: "c", count: 64), baselineID: fence.baselineID,
                        baselineDigest: fence.baselineDigest, networkFingerprint: self.base.intent.networkFingerprint,
                        coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
                        compilerPolicy: RouterSystemCompiler.policyVersion)
                    return .init(binding: binding,
                        network: self.base.snapshot(captured: try RouterSystemKernelObservation.clock()), verify: {
                            self.verifications += 1; try self.verifyHook?(self.verifications)
                        })
                })
            if includeTLS {
                probe.openTLS = { target, name, limit in
                    self.opens += 1; self.heldDeadline = limit
                    let owner = try await RouterTLSConnection.loopbackFixture(target: target, serverName: name,
                        anchorDER: self.peer.anchor, until: limit)
                    // The scripted tracker timestamp must be strictly after connect even at millisecond precision.
                    try await Task.sleep(nanoseconds: 2_000_000)
                    self.sample = try await owner.sample()
                    return owner
                }
            }
            return .init(identity: base.identity, readers: readers, fixtureProbe: probe)
        }
        func capture() async throws -> Capture {
            try await sampler().observeOwnTLS(target: peer.target, serverName: "tls-fixture.invalid")
        }
        func correlate(_ value: Capture) throws -> RouterTrafficCorrelationResult {
            try RouterTrafficCorrelator.evaluateOwnTLS(value, plan: base.intent.plan, profile: base.intent.profile)
        }
    }

    func testActualDualStackTLSRetainsOwnerAcrossThreeTwoFiveAndSelectsMiddleBody() async throws {
        for family in [4, 6] {
            let peer = try RouterTLSFixture(family: family); defer { peer.stop() }
            let h = try Harness(peer)
            let result = try await h.capture()
            try result.validate()
            XCTAssertEqual(h.bodies, 3); XCTAssertEqual(h.contexts, 2)
            XCTAssertEqual(h.verifications, 5); XCTAssertEqual(h.opens, 1)
            XCTAssertEqual(result.source, .fixture); XCTAssertEqual(result.after.trust, .fixtureAnchor)
            XCTAssertEqual(result.trackers.map(\.id), [h.tracker])
            XCTAssertFalse(result.trackers.contains { $0.id == h.lastTracker })
            XCTAssertTrue(result.priorTrackerIDs.isEmpty)
            XCTAssertEqual(result.requestNonce, result.exchange.reply.nonce)
            XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
            XCTAssertNil(h.state.accepted); XCTAssertNil(h.state.previousAccepted)
            let limit = try XCTUnwrap(h.heldDeadline)
            XCTAssertFalse(h.heldReaderDeadlines.isEmpty)
            XCTAssertTrue(h.heldReaderDeadlines.allSatisfy { $0 <= limit })
            let relation = try h.correlate(result)
            XCTAssertEqual(relation.relation, .candidateUnverified); XCTAssertFalse(relation.canPromoteAccepted)
            let report = try await peer.finish()
            XCTAssertTrue(report.eof); XCTAssertEqual(report.nonce, result.requestNonce.uuidString.lowercased())
            print("TLS fixture preflight=\(result.before.connectStartedAt.uptime - result.interval.start.uptime) held=\(result.interval.end.uptime - result.before.connectStartedAt.uptime)")
        }
    }

    func testHitCorrelationEntryWiresCaptureWithoutAcceptedWrite() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer)
        let now = Date()
        do {
            _ = try await RouterHitCorrelationEntry.captureAndCorrelateTLS(
                arming: nil, connections: h.sampler(), target: peer.target,
                serverName: "tls-fixture.invalid", plan: h.base.intent.plan,
                profile: h.base.intent.profile, now: now)
            XCTFail("disarmed entry must refuse")
        } catch {
            XCTAssertEqual(error as? RouterHitCorrelationEntry.Failure, .disarmed)
        }
        let arming = RouterHitCorrelationEntry.arm(mode: .tlsHeld, now: now, ttl: 60)
        let report = try await RouterHitCorrelationEntry.captureAndCorrelateTLS(
            arming: arming, connections: h.sampler(), target: peer.target,
            serverName: "tls-fixture.invalid", plan: h.base.intent.plan,
            profile: h.base.intent.profile, now: now)
        XCTAssertEqual(report.relation, "candidateUnverified")
        XCTAssertFalse(report.canPromoteAccepted)
        XCTAssertFalse(report.collectorAuthenticated)
        XCTAssertFalse(report.journalMutated)
        XCTAssertNil(h.state.accepted)
        XCTAssertNil(h.state.previousAccepted)
        let finished = try await peer.finish()
        XCTAssertTrue(finished.eof)
    }

    func testEverySourceVerificationFailureClosesTransportOrPreventsOpen() async throws {
        for failure in 1...5 {
            let peer = try RouterTLSFixture(); defer { peer.stop() }
            let h = try Harness(peer)
            h.verifyHook = { if $0 == failure { throw RouterTrafficEvidenceError.sourceChanged } }
            do { _ = try await h.capture(); XCTFail("Source failure accepted") }
            catch { XCTAssertEqual(error as? RouterTrafficEvidenceError, .sourceChanged) }
            XCTAssertEqual(h.verifications, failure)
            if failure == 1 { XCTAssertEqual(h.opens, 0) }
            else { let report = try await peer.finish(); XCTAssertTrue(report.eof) }
        }
    }

    func testControllerAndNetworkChangesRejectCapture() async throws {
        for kind in 0..<5 {
            let peer = try RouterTLSFixture(); defer { peer.stop() }
            let h = try Harness(peer)
            h.bodyHook = { [unowned h] count in
                guard count == 2 else { return }
                switch kind {
                case 0: h.secret = String(repeating: "z", count: 64)
                case 1: h.generation += 1
                case 2: h.state.revision = UUID()
                case 3: h.state.configurationDigest = String(repeating: "d", count: 64)
                default: h.base.dns = h.base.dns.replacingOccurrences(of: "192.0.2.53", with: "192.0.2.54")
                }
            }
            do { _ = try await h.capture(); XCTFail("Changed source accepted") }
            catch {
                if kind == 4 { XCTAssertEqual(error as? RouterTrafficEvidenceError, .sourceChanged) }
                else if kind == 3 { XCTAssertEqual(error as? RouterSystemError, .journalUnknown) }
                else { XCTAssertEqual(error as? RouterConnectionFailure, .identityChanged) }
            }
            XCTAssertEqual(h.opens, 1)
            let report = try await peer.finish(); XCTAssertTrue(report.eof)
            XCTAssertNil(h.state.accepted)
        }
    }

    func testWrongNonceAndEchoCancellationCannotReachSecondController() async throws {
        for cancel in [false, true] {
            let peer = try RouterTLSFixture(mode: cancel ? "silent_echo" : "wrong_nonce"); defer { peer.stop() }
            let h = try Harness(peer)
            let task = Task { try await h.capture() }
            if cancel { try await peer.awaitEvent("request.json"); task.cancel() }
            do { _ = try await task.value; XCTFail("Bad echo accepted") }
            catch { if !cancel { XCTAssertEqual(error as? RouterTCPEchoError, .wrongNonce) } }
            XCTAssertEqual(h.bodies, 1); XCTAssertEqual(h.contexts, 1); XCTAssertEqual(h.opens, 1)
            let report = try await peer.finish(); XCTAssertTrue(report.eof)
        }
    }

    func testHeldDeadlineCannotBeRenewedBySecondControllerRead() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer)
        h.bodyHook = { [unowned h] count in
            if count == 2 {
                let deadline = try XCTUnwrap(h.heldDeadline)
                Thread.sleep(forTimeInterval: max(0, deadline - ProcessInfo.processInfo.systemUptime) + 0.03)
            }
        }
        do { _ = try await h.capture(); XCTFail("Late controller accepted") }
        catch { XCTAssertEqual(error as? RouterConnectionFailure, .stale) }
        XCTAssertEqual(h.bodies, 2); XCTAssertEqual(h.contexts, 1); XCTAssertEqual(h.opens, 1)
        let report = try await peer.finish(); XCTAssertTrue(report.eof)
    }

    func testMissingTLSAndInvalidTargetsFailBeforeAnyReader() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer)
        for kind in 0..<3 {
            do {
                let target = try RouterTLSConnection.Endpoint(address: kind == 1 ? "203.0.113.1" : "127.0.0.1", port: 443)
                _ = try await h.sampler(includeTLS: kind != 0).observeOwnTLS(target: target,
                    serverName: kind == 2 ? "bad name" : "tls-fixture.invalid")
                XCTFail("Invalid collector opened")
            } catch { }
        }
        XCTAssertEqual(h.bodies, 0); XCTAssertEqual(h.contexts, 0); XCTAssertEqual(h.opens, 0)
    }

    private func copy(_ original: Capture, nonce: UUID? = nil,
                      interval: RouterTrafficInterval? = nil, held: RouterTrafficInterval? = nil,
                      before: RouterTLSConnection.Sample? = nil, after: RouterTLSConnection.Sample? = nil,
                      exchange: RouterTLSConnection.Exchange? = nil,
                      controller: RouterTrafficInterval? = nil, prior: Set<UUID>? = nil,
                      trackers: [RouterTrafficTracker]? = nil) -> Capture {
        .init(source: original.source, binding: original.binding, interval: interval ?? original.interval,
              priorTrackerIDs: prior ?? original.priorTrackerIDs, requestNonce: nonce ?? original.requestNonce,
              heldInterval: held ?? original.heldInterval, before: before ?? original.before,
              after: after ?? original.after, exchange: exchange ?? original.exchange,
              controllerInterval: controller ?? original.controllerInterval, trackers: trackers ?? original.trackers)
    }
    private func differentPort(_ value: UInt16) -> UInt16 { value == UInt16.max ? value - 1 : value + 1 }
    private func shifted(_ value: RouterSystemClock, by delta: Double) -> RouterSystemClock {
        .init(bootID: value.bootID, uptime: value.uptime + delta, date: value.date.addingTimeInterval(delta))
    }
    private func sample(_ original: RouterTLSConnection.Sample, kind: Int = -1,
                        interval: RouterTrafficInterval? = nil) throws -> RouterTLSConnection.Sample {
        let socket = original.socket.socket
        let tuple = try RouterOwnedTCPProbe.Tuple(local: socket.tuple.local,
            peer: .init(address: socket.tuple.peer.address, port: kind == 6 ? differentPort(socket.tuple.peer.port) : socket.tuple.peer.port))
        let process = RouterSystemOutboundSocket.Process(identity: original.socket.process.identity,
            path: kind == 7 ? "/changed/image" : original.socket.process.path)
        let evidence = RouterSystemOutboundSocket.Evidence(source: original.socket.source, process: process,
            socket: .init(descriptor: kind == 4 ? socket.descriptor + 1 : socket.descriptor,
                          generation: kind == 5 ? socket.generation + 1 : socket.generation, tuple: tuple),
            interval: interval ?? original.socket.interval)
        return .init(source: kind == 0 ? .installedHelper : original.source,
                     trust: kind == 1 ? .system : original.trust,
                     serverName: kind == 2 ? "other.invalid" : original.serverName,
                     protocolVersion: kind == 3 ? 0x0302 : original.protocolVersion,
                     connectStartedAt: kind == 8 ? shifted(original.connectStartedAt, by: -0.001) : original.connectStartedAt,
                     socket: evidence)
    }

    func testRecordValidationRejectsNonceLineageAndIntervalsOutsideTheirLifetime() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer)
        let value = try await h.capture()
        _ = try await peer.finish()
        var invalid = [copy(value, nonce: UUID())]
        for kind in 0...8 { invalid.append(copy(value, after: try sample(value.after, kind: kind))) }
        let early = RouterTrafficInterval(start: shifted(value.before.connectStartedAt, by: -0.0001),
                                          end: value.before.socket.interval.end)
        invalid.append(copy(value, before: try sample(value.before, interval: early)))
        let beforeEcho = try sample(value.exchange.before, interval: .init(
            start: shifted(value.exchange.interval.start, by: -0.0001), end: value.exchange.before.socket.interval.end))
        invalid.append(copy(value, exchange: .init(reply: value.exchange.reply, before: beforeEcho,
            after: value.exchange.after, interval: value.exchange.interval)))
        let afterEcho = try sample(value.exchange.after, interval: .init(start: value.exchange.after.socket.interval.start,
            end: shifted(value.exchange.interval.end, by: 0.0001)))
        invalid.append(copy(value, exchange: .init(reply: value.exchange.reply, before: value.exchange.before,
            after: afterEcho, interval: value.exchange.interval)))
        invalid.append(copy(value, exchange: .init(reply: value.exchange.reply, before: value.exchange.after,
            after: value.exchange.before, interval: value.exchange.interval)))
        invalid.append(copy(value, controller: value.exchange.before.socket.interval))
        invalid.append(copy(value, after: try sample(value.after, interval: value.exchange.after.socket.interval)))
        invalid.append(copy(value, held: .init(start: value.before.socket.interval.start, end: value.interval.end)))
        let late = shifted(value.before.connectStartedAt, by: 5.1)
        invalid.append(copy(value, interval: .init(start: value.interval.start, end: late),
            held: .init(start: value.heldInterval.start, end: late)))
        let wrongBoot = RouterSystemClock(bootID: UUID(), uptime: value.interval.end.uptime, date: value.interval.end.date)
        invalid.append(copy(value, interval: .init(start: value.interval.start, end: wrongBoot)))
        for (index, record) in invalid.enumerated() {
            XCTAssertThrowsError(try record.validate(), "mutation \(index)") {
                XCTAssertEqual($0 as? RouterTrafficEvidenceError, .invalidReceipt)
            }
            XCTAssertThrowsError(try h.correlate(record), "correlation mutation \(index)")
        }
    }

    private func tracker(_ original: RouterTrafficTracker, id: UUID? = nil, started: Date? = nil,
                         path: String? = nil, source: String? = nil, sourcePort: UInt16? = nil,
                         destination: String? = nil, port: UInt16? = nil, host: String? = nil,
                         sniff: String? = nil, dns: String? = nil, rule: String? = nil,
                         chains: [String]? = nil, override: Bool? = nil) -> RouterTrafficTracker {
        .init(id: id ?? original.id, startedAt: started ?? original.startedAt, transport: original.transport,
              origin: original.origin, processPath: path ?? original.processPath,
              sourceIP: source ?? original.sourceIP, sourcePort: sourcePort ?? original.sourcePort,
              destinationIP: destination ?? original.destinationIP, destinationPort: port ?? original.destinationPort,
              host: host ?? original.host, sniffHost: sniff ?? original.sniffHost, dnsMode: dns ?? original.dnsMode,
              rule: rule ?? original.rule, payload: original.payload, chains: chains ?? original.chains,
              hasOverride: override ?? original.hasOverride)
    }

    func testTLSCorrelationRejectsOldAmbiguousAndUnprovenDomainTrackers() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer); h.priorTracker = true
        let value = try await h.capture()
        _ = try await peer.finish()
        let row = try XCTUnwrap(value.trackers.first)
        XCTAssertEqual(value.priorTrackerIDs, [row.id])
        XCTAssertEqual(try h.correlate(value).reason, "tracker_predates_own_connect")
        let current = copy(value, prior: [])
        XCTAssertEqual(try h.correlate(current).relation, .candidateUnverified)
        let duplicate = tracker(row, id: UUID())
        XCTAssertEqual(try h.correlate(copy(value, trackers: [row, duplicate])).reason, "ambiguous_probe_tracker")
        let mutations: [(RouterTrafficTracker, String)] = [
            (tracker(row, started: value.before.connectStartedAt.date), "no_current_probe_tracker"),
            (tracker(row, source: "127.0.0.2"), "no_current_probe_tracker"),
            (tracker(row, sourcePort: differentPort(row.sourcePort)), "no_current_probe_tracker"),
            (tracker(row, destination: "127.0.0.2"), "probe_destination_not_bound"),
            (tracker(row, port: differentPort(row.destinationPort)), "no_current_probe_tracker"),
            (tracker(row, path: "/other/image"), "full_process_path_missing_or_changed"),
            (tracker(row, host: "tls-fixture.invalid"), "probe_domain_mismatch"),
            (tracker(row, sniff: "tls-fixture.invalid"), "unmodelled_override_or_sniff_domain"),
            (tracker(row, override: true), "unmodelled_override_or_sniff_domain"),
            (tracker(row, dns: "fake-ip"), "fake_ip_dns_mapping_not_bound"),
            (tracker(row, rule: "Domain"), "compiled_rule_or_chain_mismatch"),
            (tracker(row, chains: ["REJECT"]), "compiled_rule_or_chain_mismatch")]
        for (row, reason) in mutations {
            let result = try h.correlate(copy(current, trackers: [row]))
            XCTAssertEqual(result.reason, reason)
            XCTAssertFalse(result.canPromoteAccepted)
            XCTAssertNotEqual(result.relation, .candidateUnverified)
        }
    }

    /// Blocking belongs to the synchronous test reader, never the async test executor.
    private final class ReaderGate {
        private let lock = NSLock()
        private var entered = false
        private let semaphore = DispatchSemaphore(value: 0)
        var hasEntered: Bool {
            lock.lock(); defer { lock.unlock() }
            return entered
        }
        func enterAndWait() throws {
            lock.lock(); entered = true; lock.unlock()
            guard semaphore.wait(timeout: .now() + 10) == .success else { throw RouterConnectionFailure.stale }
        }
        func release() { semaphore.signal() }
    }

    func testCancellationClosesTLSWhileSynchronousControllerIsStillBlocked() async throws {
        let peer = try RouterTLSFixture(); defer { peer.stop() }
        let h = try Harness(peer)
        let gate = ReaderGate()
        defer { gate.release() }
        h.bodyHook = { count in
            guard count == 2 else { return }
            try gate.enterAndWait()
        }
        let task = Task { try await h.capture() }
        do {
            let limit = ProcessInfo.processInfo.systemUptime + 3
            while !gate.hasEntered {
                guard ProcessInfo.processInfo.systemUptime < limit else { throw RouterTLSConnection.Failure.timedOut }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
            let cancelledAt = ProcessInfo.processInfo.systemUptime
            let deadline = try XCTUnwrap(h.heldDeadline)
            guard deadline - cancelledAt > 1.5 else {
                XCTFail("Insufficient budget to distinguish cancellation from natural expiry")
                throw RouterTLSConnection.Failure.timedOut
            }
            task.cancel()
            // Keep the controller blocked until transport EOF, well before natural expiry.
            let report = try await peer.finish()
            let observedAt = ProcessInfo.processInfo.systemUptime
            XCTAssertTrue(report.eof)
            XCTAssertLessThan(observedAt - cancelledAt, 1)
            XCTAssertLessThan(observedAt, deadline - 0.5)
            gate.release()
            do { _ = try await task.value; XCTFail("Cancelled read returned an observation") }
            catch { XCTAssertEqual(error as? RouterOwnedProbeError, .cancelled) }
        } catch {
            task.cancel(); gate.release()
            _ = try? await task.value
            throw error
        }
        XCTAssertEqual(h.bodies, 2); XCTAssertEqual(h.contexts, 1)
        XCTAssertEqual(h.verifications, 1); XCTAssertEqual(h.opens, 1)
    }
}
