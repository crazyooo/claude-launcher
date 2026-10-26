import XCTest
@testable import RoutingCore

final class RouterTrafficDNSWireTests: XCTestCase {
    private let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    private let profile = RouterSystemProfile(resolver: .cloudflare)
    private let boot = UUID()
    private let attempt = UUID()

    private func clock(_ seconds: Double) -> RouterSystemClock {
        .init(bootID: boot, uptime: seconds - 1900, date: Date(timeIntervalSince1970: seconds))
    }
    private func binding(plan selected: RouterPlan? = nil) throws -> RouterTrafficBinding {
        let digest = String(repeating: "a", count: 64)
        return .init(phase: .active, installation: .init(id: UUID(), ownerUID: 501), instance: UUID(), revision: UUID(),
            work: .init(bootID: boot, pid: 999, birthSeconds: 1000, birthMicroseconds: 0),
            planDigest: try RouterSystemCompiler.digest(plan: selected ?? plan, profile: profile), configurationDigest: digest,
            stageReceiptDigest: digest, baselineID: UUID(), baselineDigest: digest, networkFingerprint: digest,
            coreSHA256: RouterCoreRelease.executableSHA256, coreVersion: RouterCoreRelease.version,
            compilerPolicy: RouterSystemCompiler.policyVersion)
    }
    private func number(_ value: UInt16) -> [UInt8] { [UInt8(value >> 8), UInt8(value & 255)] }
    private func packet(response: Bool, domain: String = "example.com", type: UInt16 = 1,
                        addresses: [(String, UInt32)] = [("198.18.0.9", 60)]) -> Data {
        var bytes = number(0x1234) + number(response ? 0x8180 : 0x0100) + number(1)
        bytes += number(response ? UInt16(addresses.count) : 0) + number(0) + number(0)
        for label in domain.split(separator: ".") { bytes += [UInt8(label.utf8.count)] + Array(label.utf8) }
        bytes += [0] + number(type) + number(1)
        if response {
            for (address, ttl) in addresses {
                let data = Array(RouterTrafficAddress.bytes(address)!)
                bytes += [0xc0, 0x0c] + number(type) + number(1) + number(UInt16(ttl >> 16)) + number(UInt16(ttl & 65535))
                bytes += number(UInt16(data.count)) + data
            }
        }
        return Data(bytes)
    }
    private func frame(_ data: Data) -> Data { Data(number(UInt16(data.count))) + data }
    private func parse(_ response: Data? = nil, query: Data? = nil, transport: RouterTrafficTransport = .udp,
                       family: RouterTrafficFamily = .ipv4, binding supplied: RouterTrafficBinding? = nil,
                       sourceIP: String = "192.0.2.53", sourcePort: UInt16 = 53,
                       exchange: RouterTrafficInterval? = nil) throws -> [RouterTrafficDNSMapping] {
        try RouterTrafficDNSWire.mappings(query: query ?? packet(response: false),
            response: response ?? packet(response: true), transport: transport,
            queryDestinationIP: "192.0.2.53", queryDestinationPort: 53,
            responseSourceIP: sourceIP, responseSourcePort: sourcePort, domain: "example.com", family: family,
            attempt: attempt, binding: supplied ?? binding(), exchange: exchange ?? .init(start: clock(1990), end: clock(1991)))
    }
    private func facts(_ binding: RouterTrafficBinding, family: RouterTrafficFamily = .ipv4,
                       address: String = "198.18.0.9", attempt other: UUID? = nil,
                       transport: RouterTrafficTransport = .tcp, interval: RouterTrafficInterval? = nil) throws -> RouterTrafficAttemptFacts {
        .init(id: .init(rule: nil, variation: .fallback, transport: transport, family: family), attempt: other ?? attempt,
            session: UUID(), bindingDigest: try binding.digest(), nonce: UUID(),
            interval: interval ?? .init(start: clock(2000), end: clock(2010)),
            process: .init(bootID: boot, pid: 1001, birthSeconds: 1500, birthMicroseconds: 0),
            processPath: "/Applications/Test.app/Contents/MacOS/Test",
            sourceIP: family == .ipv4 ? "192.0.2.2" : "2001:db8::2", sourcePort: 45000,
            destinationIP: address, destinationPort: 443, domain: "example.com",
            target: .init(host: "example.com", port: 443, transport: transport))
    }

    func testCompressedUDPAndFramedTCPMappingsBindAttemptFamilyAndBothClocks() throws {
        let bound = try binding()
        for transport in [RouterTrafficTransport.udp, .tcp] {
            let query = packet(response: false), response = packet(response: true)
            let mappings = try parse(transport == .tcp ? frame(response) : response,
                query: transport == .tcp ? frame(query) : query, transport: transport, binding: bound)
            XCTAssertEqual(mappings.count, 1); XCTAssertEqual(mappings[0].answerIP, "198.18.0.9")
            XCTAssertTrue(mappings[0].matches(attempt: try facts(bound), binding: bound))
            XCTAssertFalse(mappings[0].matches(attempt: try facts(bound, attempt: UUID()), binding: bound))
            XCTAssertFalse(mappings[0].matches(attempt: try facts(bound, address: "198.18.0.10"), binding: bound))
            XCTAssertFalse(mappings[0].matches(attempt: try facts(bound), binding: try binding()))
            XCTAssertEqual(mappings[0].expiresAt.timeIntervalSince1970, 2050)
            XCTAssertEqual(mappings[0].expiresUptime, 150)
        }
        let v6 = try parse(packet(response: true, type: 28, addresses: [("fdfe:dcba:9876::9", 60)]),
            query: packet(response: false, type: 28), family: .ipv6, binding: bound)
        XCTAssertTrue(v6[0].matches(attempt: try facts(bound, family: .ipv6, address: "fdfe:dcba:9876:0::9"), binding: bound))
    }

    func testWrongIDQuestionTypeClassResponderAndTruncationDoNotProduceMapping() throws {
        let good = packet(response: true)
        var wrongID = good; wrongID[1] ^= 1
        var truncated = good; truncated[2] |= 2
        var nxdomain = good; nxdomain[3] |= 3
        var wrongClass = good; wrongClass[28] = 3
        for response in [wrongID, truncated, nxdomain, wrongClass, good.dropLast(),
                         packet(response: true, domain: "other.com"),
                         packet(response: true, addresses: [])] {
            XCTAssertThrowsError(try parse(response))
        }
        // This response is a structurally valid AAAA answer, so the failure must
        // come from the question mismatch with the original A query.
        XCTAssertThrowsError(try parse(packet(response: true, type: 28, addresses: [("fdfe:dcba:9876::9", 60)]))) {
            XCTAssertEqual($0 as? RouterTrafficDNSWireError, .invalidWire)
        }
        XCTAssertThrowsError(try parse(sourceIP: "192.0.2.54")) { XCTAssertEqual($0 as? RouterTrafficDNSWireError, .endpointMismatch) }
        XCTAssertThrowsError(try parse(sourcePort: 5353))
        XCTAssertThrowsError(try parse(good + Data([0])))
        XCTAssertThrowsError(try parse(frame(good) + Data([0]), query: frame(packet(response: false)), transport: .tcp))
        XCTAssertThrowsError(try parse(Data(repeating: 0, count: 4099)))
    }

    func testAliasesNonFakeAnswersAndMalformedCompressionAreExplicitlyRejected() throws {
        let good = packet(response: true)
        var alias = good; alias[32] = 5
        var dname = good; dname[32] = 39
        for value in [alias, dname] {
            XCTAssertThrowsError(try parse(value)) { XCTAssertEqual($0 as? RouterTrafficDNSWireError, .unsupportedAlias) }
        }
        for address in ["198.19.0.9", "203.0.113.1"] {
            XCTAssertThrowsError(try parse(packet(response: true, addresses: [(address, 60)]))) {
                XCTAssertEqual($0 as? RouterTrafficDNSWireError, .unsupportedAnswer)
            }
        }
        var selfPointer = good; selfPointer[30] = 29
        var middleLabel = good; middleLabel[30] = 13
        var forwardPointer = good; forwardPointer[30] = 40
        for value in [selfPointer, middleLabel, forwardPointer] { XCTAssertThrowsError(try parse(value)) }
        // A literal dot inside a wire label must not become two domain labels.
        var dottedQuery = packet(response: false); dottedQuery[14] = 46
        XCTAssertThrowsError(try parse(query: dottedQuery))
    }

    func testMinimumTTLNoGraceAndBoundedLifetime() throws {
        let bound = try binding()
        for ttl: UInt32 in [0, 1] {
            XCTAssertThrowsError(try parse(packet(response: true, addresses: [("198.18.0.9", ttl)]))) {
                XCTAssertEqual($0 as? RouterTrafficDNSWireError, .expired)
            }
        }
        let duplicates = try parse(packet(response: true, addresses: [("198.18.0.9", 60), ("198.18.0.9", 2)]), binding: bound)
        XCTAssertEqual(duplicates.count, 1)
        XCTAssertEqual(duplicates[0].expiresUptime, 92)
        XCTAssertFalse(duplicates[0].matches(attempt: try facts(bound), binding: bound))
        XCTAssertThrowsError(try parse(packet(response: true, addresses: [("198.18.0.9", UInt32.max)])))
        let huge = try parse(packet(response: true, addresses: [("198.18.0.9", UInt32(Int32.max))]))
        XCTAssertEqual(huge[0].expiresUptime, 3690)
        let boundary = try parse(packet(response: true, addresses: [("198.18.0.9", 20)]), binding: bound)
        XCTAssertFalse(boundary[0].matches(attempt: try facts(bound), binding: bound)) // TTL equals probe end.
        for (date, uptime) in [(2009.0, 110.0), (2010.0, 109.0)] {
            let interval = RouterTrafficInterval(start: clock(2000),
                end: .init(bootID: boot, uptime: uptime, date: Date(timeIntervalSince1970: date)))
            XCTAssertNoThrow(try interval.validate(boot: boot, maximumDuration: 60))
            XCTAssertFalse(boundary[0].matches(attempt: try facts(bound, interval: interval), binding: bound))
        }
        let badClock = RouterTrafficInterval(start: clock(1990),
            end: .init(bootID: boot, uptime: 100, date: Date(timeIntervalSince1970: 1991)))
        XCTAssertThrowsError(try parse(exchange: badClock))
    }

    func testEDNSVersionExtendedErrorDuplicateOPTAndBrokenOptionsFail() throws {
        var valid = packet(response: true); valid[11] = 1
        // Root owner, OPT, UDP size 4096, zero extended RCODE/version, no options.
        let opt: [UInt8] = [0, 0, 41, 16, 0, 0, 0, 0, 0, 0, 0]
        let good = valid + Data(opt)
        XCTAssertEqual(try parse(good).count, 1)
        for field in [5, 6] {
            var invalid = good; invalid[valid.count + field] = 1
            XCTAssertThrowsError(try parse(invalid))
        }
        var duplicate = good + Data(opt); duplicate[11] = 2
        XCTAssertThrowsError(try parse(duplicate))
        var broken = valid + Data(opt.dropLast(2)) + Data([0, 3, 0, 1, 0])
        XCTAssertThrowsError(try parse(broken))
        broken[11] = 0
        XCTAssertThrowsError(try parse(broken))
    }

    func testParsedMappingCorrelatesFakeIPOnlyWithoutPromotingReceipt() throws {
        let bound = try binding(), facts = try facts(bound)
        let mapping = try XCTUnwrap(parse(binding: bound).first)
        let record = RouterTrafficCaseRecord(id: facts.id, attempt: attempt, session: facts.session,
            bindingDigest: try bound.digest(), interval: facts.interval,
            transcript: .init(outcome: .incomplete, requestNonce: facts.nonce, endpointDigest: try facts.target.digest(),
                expectedEgress: nil, reply: nil, rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
        let row: [String: Any] = [
            "id": UUID().uuidString, "start": "1970-01-01T00:33:21.123456789Z", "upload": 0, "download": 0,
            "rule": "Match", "rulePayload": "", "chains": ["DIRECT"],
            "metadata": ["network": "tcp", "type": "Tun", "processPath": facts.processPath,
                         "sourceIP": "192.0.2.2", "sourcePort": "45000", "destinationIP": "", "destinationPort": "443",
                         "host": "example.com", "sniffHost": "", "dnsMode": "fake-ip",
                         "specialProxy": "", "specialRules": "", "rematchName": ""]
        ]
        let body = try JSONSerialization.data(withJSONObject: ["connections": [row], "uploadTotal": 0, "downloadTotal": 0])
        let result = try record.correlate(binding: bound, plan: plan, profile: profile, attempt: facts,
            snapshotBinding: bound, snapshotInterval: .init(start: clock(2004), end: clock(2005)), body: body, dns: mapping)
        XCTAssertEqual(result.relation, .candidateUnverified)
        XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
        let receipt = RouterTrafficReceipt(version: 1, coveragePolicy: 1, session: facts.session, before: bound, after: bound,
            interval: facts.interval, records: [record])
        let assessment = try receipt.assess(plan: plan, profile: profile)
        XCTAssertEqual(assessment.status, "incomplete")
        XCTAssertTrue(assessment.cases.allSatisfy { !$0.gaps.isEmpty })
        XCTAssertFalse(assessment.canPromoteAccepted)
    }

    func testIPv6FakeIPUDPRejectSentinelNeedsMappingAndStillCannotProveRejection() throws {
        let block = RouterPlan(proxies: [], rules: [], defaultDestination: .block)
        let bound = try binding(plan: block)
        let facts = try facts(bound, family: .ipv6, address: "fdfe:dcba:9876::9", transport: .udp)
        let mapping = try XCTUnwrap(parse(packet(response: true, type: 28, addresses: [("fdfe:dcba:9876::9", 60)]),
            query: packet(response: false, type: 28), family: .ipv6, binding: bound).first)
        let record = RouterTrafficCaseRecord(id: facts.id, attempt: attempt, session: facts.session,
            bindingDigest: try bound.digest(), interval: facts.interval,
            transcript: .init(outcome: .rejected, requestNonce: facts.nonce, endpointDigest: try facts.target.digest(),
                expectedEgress: nil, reply: nil, rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
        let row: [String: Any] = [
            "id": UUID().uuidString, "start": "1970-01-01T00:33:21.1Z", "upload": 0, "download": 0,
            "rule": "Match", "rulePayload": "", "chains": ["REJECT"],
            "metadata": ["network": "udp", "type": "Tun", "processPath": facts.processPath,
                         "sourceIP": facts.sourceIP, "sourcePort": "45000", "destinationIP": "0.0.0.0", "destinationPort": "443",
                         "host": "example.com", "sniffHost": "", "dnsMode": "fake-ip",
                         "specialProxy": "", "specialRules": "", "rematchName": ""]
        ]
        let body = try JSONSerialization.data(withJSONObject: ["connections": [row], "uploadTotal": 0, "downloadTotal": 0])
        for dns in [nil, mapping] {
            let result = try record.correlate(binding: bound, plan: block, profile: profile, attempt: facts,
                snapshotBinding: bound, snapshotInterval: .init(start: clock(2004), end: clock(2005)), body: body, dns: dns)
            XCTAssertEqual(result.reason, dns == nil ? "fake_ip_dns_mapping_not_bound" : "candidate_reject_controls_still_required")
            XCTAssertEqual(result.relation, dns == nil ? .insufficient : .candidateUnverified)
            XCTAssertFalse(result.collectorAuthenticated); XCTAssertFalse(result.canPromoteAccepted)
        }
    }
}
