import XCTest
@testable import RoutingCore

final class RouterTrafficCorrelationTests: XCTestCase {
    private let path = "/Applications/Test.app/Contents/MacOS/Test"
    private let profile = RouterSystemProfile(resolver: .quad9)
    private let direct = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)

    struct Fixture {
        let binding: RouterTrafficBinding
        let record: RouterTrafficCaseRecord
        let facts: RouterTrafficAttemptFacts
        let snapshot: RouterTrafficInterval
    }
    private func fixture(_ plan: RouterPlan? = nil, rule: UUID? = nil,
                         variation: RouterTrafficVariation = .fallback,
                         transport: RouterTrafficTransport = .tcp, family: RouterTrafficFamily = .ipv4,
                         domain: String? = nil, destination: String? = nil,
                         processPath: String? = nil, outcome: RouterTrafficTranscript.Outcome = .incomplete) throws -> Fixture {
        let plan = plan ?? direct, boot = UUID(), session = UUID(), attempt = UUID(), nonce = UUID()
        let sample = String(repeating: "a", count: 64)
        let binding = RouterTrafficBinding(phase: .active, installation: .init(id: UUID(), ownerUID: 501),
            instance: UUID(), revision: UUID(), work: .init(bootID: boot, pid: 999, birthSeconds: 1000, birthMicroseconds: 0),
            planDigest: try RouterSystemCompiler.digest(plan: plan, profile: profile), configurationDigest: sample,
            stageReceiptDigest: sample, baselineID: UUID(), baselineDigest: sample, networkFingerprint: sample,
            coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
            compilerPolicy: RouterSystemCompiler.policyVersion)
        func time(_ second: Double) -> RouterSystemClock {
            .init(bootID: boot, uptime: second - 1900, date: Date(timeIntervalSince1970: second))
        }
        let window = RouterTrafficInterval(start: time(2000), end: time(2010))
        let snapshot = RouterTrafficInterval(start: time(2004), end: time(2005))
        let address = destination ?? (family == .ipv4 ? "203.0.113.1" : "2001:db8::1")
        let target = RouterTrafficProbeTarget(host: domain ?? address, port: 443, transport: transport)
        let id = RouterTrafficCase(rule: rule, variation: variation, transport: transport, family: family)
        let record = RouterTrafficCaseRecord(id: id, attempt: attempt, session: session,
            bindingDigest: try binding.digest(), interval: window,
            transcript: .init(outcome: outcome, requestNonce: nonce, endpointDigest: try target.digest(),
                expectedEgress: nil, reply: nil, rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
        let facts = RouterTrafficAttemptFacts(id: id, attempt: attempt, session: session, bindingDigest: try binding.digest(),
            nonce: nonce, interval: window, process: .init(bootID: boot, pid: 1001, birthSeconds: 1500, birthMicroseconds: 0),
            processPath: processPath ?? path, sourceIP: family == .ipv4 ? "192.0.2.2" : "2001:db8::2",
            sourcePort: 45000, destinationIP: address, destinationPort: 443, domain: domain, target: target)
        return .init(binding: binding, record: record, facts: facts, snapshot: snapshot)
    }
    private func row(_ f: Fixture, type: String = "Match", payload: String = "", chain: String = "DIRECT") -> [String: Any] {
        ["id": UUID().uuidString, "start": "1970-01-01T00:33:21.123456789Z",
         "upload": 1, "download": 1, "rule": type, "rulePayload": payload, "chains": [chain],
         "metadata": ["network": f.record.id.transport.rawValue, "type": "Tun", "processPath": f.facts.processPath,
                      "sourceIP": f.facts.sourceIP, "sourcePort": String(f.facts.sourcePort),
                      "destinationIP": f.facts.destinationIP, "destinationPort": "443",
                      "host": f.facts.domain ?? "", "sniffHost": "", "dnsMode": "normal",
                      "specialProxy": "", "specialRules": "", "rematchName": ""]]
    }
    private func body(_ rows: [[String: Any]]) throws -> Data {
        try JSONSerialization.data(withJSONObject: ["uploadTotal": 0, "downloadTotal": 0, "connections": rows])
    }
    private func evaluate(_ f: Fixture, _ rows: [[String: Any]], plan: RouterPlan? = nil,
                          dns: RouterTrafficDNSMapping? = nil) throws -> RouterTrafficCorrelationResult {
        try f.record.correlate(binding: f.binding, plan: plan ?? direct, profile: profile,
            attempt: f.facts, snapshotBinding: f.binding, snapshotInterval: f.snapshot, body: body(rows), dns: dns)
    }
    private func metadata(_ row: [String: Any], _ key: String, _ value: Any) -> [String: Any] {
        var row = row, fields = row["metadata"] as! [String: Any]
        fields[key] = value; row["metadata"] = fields
        return row
    }

    func testCatalogMatchesPinnedDisplayGrammarAndCompilerOrderIncludingUDPGuards() throws {
        let proxy = UUID(), rule = UUID()
        let plan = RouterPlan(proxies: [.init(id: proxy, name: "Private", kind: .http, host: "127.0.0.1", port: 1082,
                                             credentialReference: UUID())],
            rules: [.init(id: rule, selector: .init(processPath: path, domain: .init(kind: .suffix, value: "Example.COM")),
                          destination: .proxy(proxy))], defaultDestination: .proxy(proxy))
        let catalog = try RouterTrafficRuleCatalog.make(plan)
        XCTAssertEqual(catalog.count, 4)
        XCTAssertEqual(catalog.map(\.ordinal), [0, 1, 2, 3])
        XCTAssertEqual(catalog[0].payload, "((ProcessPath,\(path)) && (DomainSuffix,example.com) && (Network,udp))")
        XCTAssertEqual(catalog[0].type, "AND"); XCTAssertEqual(catalog[0].chain, "REJECT")
        XCTAssertEqual(catalog[1].payload, "((ProcessPath,\(path)) && (DomainSuffix,example.com))")
        XCTAssertEqual(catalog[1].chain, "route_" + proxy.uuidString.lowercased())
        XCTAssertEqual(catalog[2].type, "Network"); XCTAssertEqual(catalog[2].payload, "udp")
        XCTAssertEqual(catalog[3].type, "Match"); XCTAssertEqual(catalog[3].payload, "")
    }

    func testPrivateParserRetainsAllRowsAndFractionalTrackerTime() throws {
        let f = try fixture()
        var rows = (0..<101).map { _ in row(f) }
        for index in 0..<100 { rows[index] = metadata(rows[index], "sourcePort", "45001") }
        let parsed = try RouterTrafficTrackerParser.parse(body(rows))
        XCTAssertEqual(parsed.count, 101)
        XCTAssertEqual(try evaluate(f, rows).relation, .candidateUnverified)
        rows[0] = row(f)
        XCTAssertEqual(try evaluate(f, rows).reason, "ambiguous_probe_tracker")
        var early = row(f), late = row(f)
        early["start"] = "1970-01-01T00:33:21.123000001Z"
        late["start"] = "1970-01-01T00:33:21.123999999Z"
        let times = try RouterTrafficTrackerParser.parse(body([early, late])).map(\.startedAt)
        XCTAssertGreaterThan(times[1].timeIntervalSince(times[0]), 0.0009)
        XCTAssertEqual(times[0].timeIntervalSince1970, 2001.123000001, accuracy: 0.0000001)
    }

    func testParserRejectsMissingRequiredFieldsDuplicateIDsMalformedPortsAndOversize() throws {
        let f = try fixture(), good = row(f)
        var missing = good, fields = good["metadata"] as! [String: Any]
        fields.removeValue(forKey: "processPath"); missing["metadata"] = fields
        var wrongDate = good; wrongDate["start"] = "1970-01-01 00:33:21"
        for rows in [[missing], [wrongDate], [good, good], [metadata(good, "sourcePort", "045000")],
                     [metadata(good, "destinationPort", "65536")], [metadata(good, "processPath", path + "\u{0000}")]] {
            XCTAssertThrowsError(try RouterTrafficTrackerParser.parse(body(rows)))
        }
        XCTAssertThrowsError(try RouterTrafficTrackerParser.parse(Data(repeating: 0, count: 524_289)))
        let duplicateKey = Data(#"{"uploadTotal":0,"downloadTotal":0,"connections":null,"connections":[]}"#.utf8)
        XCTAssertThrowsError(try RouterTrafficTrackerParser.parse(duplicateKey))
        XCTAssertEqual(try RouterTrafficTrackerParser.parse(Data(#"{"uploadTotal":0,"downloadTotal":0,"connections":null}"#.utf8)).count, 0)
    }

    func testOldWrongTupleWrongTransportAndOtherIngressCannotFillAttempt() throws {
        let f = try fixture(), good = row(f)
        var old = good; old["start"] = "1970-01-01T00:33:19.999999999Z"
        var future = good; future["start"] = "1970-01-01T00:33:25.000000001Z"
        for candidate in [old, future, metadata(good, "sourcePort", "45001"), metadata(good, "sourceIP", "192.0.2.9"),
                          metadata(good, "destinationPort", "80"), metadata(good, "network", "udp"),
                          metadata(good, "type", "Inner"), metadata(good, "type", "HTTP")] {
            XCTAssertEqual(try evaluate(f, [candidate]).reason, "no_current_probe_tracker")
        }
        XCTAssertEqual(try evaluate(f, [good, row(f)]).reason, "ambiguous_probe_tracker")
        XCTAssertEqual(try evaluate(f, [metadata(good, "processPath", "Test")]).reason, "full_process_path_missing_or_changed")
        XCTAssertEqual(try evaluate(f, [metadata(good, "specialProxy", "DIRECT")]).reason, "unmodelled_override_or_sniff_domain")
    }

    func testPayloadChainDomainAndDeclaredOutcomeContradictionsAreDistinct() throws {
        let f = try fixture()
        XCTAssertEqual(try evaluate(f, [row(f, payload: "different")]).relation, .contradictory)
        XCTAssertEqual(try evaluate(f, [row(f, chain: "REJECT")]).reason, "compiled_rule_or_chain_mismatch")
        XCTAssertEqual(try evaluate(f, [metadata(row(f), "host", "example.com")]).reason, "probe_domain_mismatch")
        let rejected = try fixture(outcome: .rejected)
        XCTAssertEqual(try evaluate(rejected, [row(rejected)]).reason, "transcript_route_outcome_mismatch")
        let block = RouterPlan(proxies: [], rules: [], defaultDestination: .block)
        let forwarded = try fixture(block, outcome: .forwarded)
        XCTAssertEqual(try evaluate(forwarded, [row(forwarded, chain: "REJECT")], plan: block).relation, .contradictory)
        let rejection = try fixture(block, outcome: .rejected)
        XCTAssertEqual(try evaluate(rejection, [row(rejection, chain: "REJECT")], plan: block).reason,
                       "candidate_reject_controls_still_required")
        XCTAssertEqual(try evaluate(rejection, [], plan: block).relation, .insufficient)
    }

    func testSuffixRootDescendantBoundaryAndWholePlanPrecedenceAreSeparate() throws {
        let id = UUID()
        let plan = RouterPlan(proxies: [], rules: [.init(id: id, selector: .init(domain: .init(kind: .suffix, value: "example.com")),
                                                       destination: .direct)], defaultDestination: .block)
        let root = try fixture(plan, rule: id, variation: .selected, domain: "example.com")
        XCTAssertEqual(try evaluate(root, [row(root, type: "DomainSuffix", payload: "example.com")], plan: plan).relation, .candidateUnverified)
        let wrongRoot = try fixture(plan, rule: id, variation: .selected, domain: "sub.example.com")
        XCTAssertEqual(try evaluate(wrongRoot, [], plan: plan).reason, "case_selector_or_shadowing_gap")
        let child = try fixture(plan, rule: id, variation: .suffixDescendant, domain: "sub.example.com")
        XCTAssertEqual(try evaluate(child, [row(child, type: "DomainSuffix", payload: "example.com")], plan: plan).relation, .candidateUnverified)
        let boundary = try fixture(plan, rule: id, variation: .suffixBoundaryOutside, domain: "notexample.com")
        XCTAssertEqual(try evaluate(boundary, [row(boundary, chain: "REJECT")], plan: plan).relation, .candidateUnverified)
        let unknown = try fixture(plan)
        XCTAssertEqual(try evaluate(unknown, [], plan: plan).reason, "earlier_rule_identity_unknown")
        var shadowed = plan
        shadowed.rules.insert(.init(id: UUID(), selector: .init(domain: .init(kind: .suffix, value: "com")), destination: .block), at: 0)
        let shadow = try fixture(shadowed, rule: id, variation: .selected, domain: "example.com")
        XCTAssertEqual(try evaluate(shadow, [], plan: shadowed).reason, "case_selector_or_shadowing_gap")
    }

    func testRecordBindingSessionNonceEndpointAndWindowCannotBeMixed() throws {
        let f = try fixture(), other = try fixture()
        XCTAssertThrowsError(try f.record.correlate(binding: f.binding, plan: direct, profile: profile,
            attempt: other.facts, snapshotBinding: f.binding, snapshotInterval: f.snapshot, body: body([])))
        let bytes = try RouterTrafficCodec.encode(f.record)
        let edits: [(String, Any)] = [("session", UUID().uuidString), ("attempt", UUID().uuidString),
                                     ("bindingDigest", String(repeating: "b", count: 64))]
        for (key, value) in edits {
            var object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
            object[key] = value
            let record = try JSONDecoder().decode(RouterTrafficCaseRecord.self, from: JSONSerialization.data(withJSONObject: object))
            XCTAssertThrowsError(try record.correlate(binding: f.binding, plan: direct, profile: profile,
                attempt: f.facts, snapshotBinding: f.binding, snapshotInterval: f.snapshot, body: body([])), key)
        }
        for (key, value) in [("requestNonce", UUID().uuidString), ("endpointDigest", String(repeating: "b", count: 64))] {
            var object = try JSONSerialization.jsonObject(with: bytes) as! [String: Any]
            var transcript = object["transcript"] as! [String: Any]; transcript[key] = value; object["transcript"] = transcript
            let record = try JSONDecoder().decode(RouterTrafficCaseRecord.self, from: JSONSerialization.data(withJSONObject: object))
            XCTAssertThrowsError(try record.correlate(binding: f.binding, plan: direct, profile: profile,
                attempt: f.facts, snapshotBinding: f.binding, snapshotInterval: f.snapshot, body: body([])), key)
        }
        XCTAssertThrowsError(try f.record.correlate(binding: f.binding, plan: direct, profile: profile,
            attempt: f.facts, snapshotBinding: other.binding, snapshotInterval: f.snapshot, body: body([])))
        XCTAssertThrowsError(try f.record.correlate(binding: f.binding, plan: direct, profile: profile,
            attempt: f.facts, snapshotBinding: f.binding, snapshotInterval: .init(start: f.snapshot.end, end: f.snapshot.start), body: body([])))
    }

    func testUnknownDNSFakeIPWithoutMappingAndIPv6AreNotInferredAsUpstreamSuccess() throws {
        let f = try fixture(domain: "example.com", destination: "198.18.0.9")
        let fake = metadata(metadata(row(f), "destinationIP", ""), "dnsMode", "fake-ip")
        XCTAssertEqual(try evaluate(f, [fake]).reason, "fake_ip_dns_mapping_not_bound")
        XCTAssertEqual(try evaluate(f, [row(f)]).reason, "probe_destination_not_bound")
        let dns = try fixture(variation: .dnsAAAA)
        XCTAssertEqual(try evaluate(dns, []).reason, "dns_exchange_semantics_required")
        let v6 = try fixture(family: .ipv6)
        let result = try evaluate(v6, [metadata(row(v6), "sourceIP", "2001:0db8:0:0::2")])
        XCTAssertEqual(result.relation, .candidateUnverified)
        let output = try JSONSerialization.jsonObject(with: RouterTrafficCodec.encode(result)) as! [String: Any]
        XCTAssertEqual(output["collectorAuthenticated"] as? Bool, false)
        XCTAssertEqual(output["canPromoteAccepted"] as? Bool, false)
        XCTAssertEqual(Set(output["gaps"] as! [String]), ["ruleUncorrelated", "liveCollectorUnavailable"])
        XCTAssertFalse(String(decoding: try RouterTrafficCodec.encode(result), as: UTF8.self).contains(path))
    }

    func testTargetDigestCanonicalizesIPAndDomainWithoutHidingPortOrTransport() throws {
        XCTAssertEqual(try RouterTrafficProbeTarget(host: "2001:db8::1", port: 443, transport: .tcp).digest(),
                       try RouterTrafficProbeTarget(host: "2001:0db8:0:0::1", port: 443, transport: .tcp).digest())
        XCTAssertEqual(try RouterTrafficProbeTarget(host: "EXAMPLE.COM", port: 443, transport: .tcp).digest(),
                       try RouterTrafficProbeTarget(host: "example.com", port: 443, transport: .tcp).digest())
        XCTAssertNotEqual(try RouterTrafficProbeTarget(host: "example.com", port: 443, transport: .tcp).digest(),
                          try RouterTrafficProbeTarget(host: "example.com", port: 443, transport: .udp).digest())
        XCTAssertNotEqual(try RouterTrafficProbeTarget(host: "example.com", port: 443, transport: .tcp).digest(),
                          try RouterTrafficProbeTarget(host: "example.com", port: 80, transport: .tcp).digest())
    }

    func testANDNegativeCasesUseWholePlanAndUDPUsesCompiledCapabilityGuard() throws {
        let first = UUID(), second = UUID()
        let plan = RouterPlan(proxies: [], rules: [
            .init(id: first, selector: .init(processPath: path, domain: .init(kind: .exact, value: "example.com")), destination: .block),
            .init(id: second, selector: .init(domain: .init(kind: .exact, value: "example.com")), destination: .direct)
        ], defaultDestination: .block)
        let outside = try fixture(plan, rule: first, variation: .processOutside, domain: "example.com", processPath: "/usr/bin/Other")
        XCTAssertEqual(try evaluate(outside, [row(outside, type: "Domain", payload: "example.com")], plan: plan).relation, .candidateUnverified)
        XCTAssertEqual(try evaluate(outside, [row(outside, type: "Domain", payload: "other.com")], plan: plan).relation, .contradictory)
        let otherDomain = try fixture(plan, rule: first, variation: .domainOutside, domain: "other.com")
        XCTAssertEqual(try evaluate(otherDomain, [row(otherDomain, chain: "REJECT")], plan: plan).relation, .candidateUnverified)
        for (kind, udp) in [(RouterProxy.Kind.http, false), (.socks5, false), (.socks5, true)] {
            let proxy = UUID(), rule = UUID()
            let plan = RouterPlan(proxies: [.init(id: proxy, name: "Proxy", kind: kind, host: "127.0.0.1", port: 1082, udp: udp)],
                rules: [.init(id: rule, selector: .init(processPath: path), destination: .proxy(proxy))], defaultDestination: .direct)
            let f = try fixture(plan, rule: rule, variation: .selected, transport: .udp)
            let tracker = udp ? row(f, type: "ProcessPath", payload: path, chain: "route_" + proxy.uuidString.lowercased()) :
                row(f, type: "AND", payload: "((ProcessPath,\(path)) && (Network,udp))", chain: "REJECT")
            let result = try evaluate(f, [tracker], plan: plan)
            XCTAssertEqual(result.relation, .candidateUnverified)
            XCTAssertEqual(result.compiledOrdinal, 0)
            XCTAssertFalse(result.canPromoteAccepted)
        }
    }
}
