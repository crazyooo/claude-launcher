import XCTest
@testable import RoutingCore

final class RouterTrafficEvidenceTests: XCTestCase {
    let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
    let profile = RouterSystemProfile(resolver: .quad9)
    private let sampleDigest = String(repeating: "a", count: 64)

    func fixture(allCases: Bool = false) throws -> RouterTrafficReceipt {
        let boot = UUID()
        let binding = RouterTrafficBinding(phase: .active,
            installation: .init(id: UUID(), ownerUID: 501), instance: UUID(), revision: UUID(),
            work: .init(bootID: boot, pid: 999, birthSeconds: 1_000, birthMicroseconds: 0),
            planDigest: try RouterSystemCompiler.digest(plan: plan, profile: profile),
            configurationDigest: sampleDigest, stageReceiptDigest: sampleDigest, baselineID: UUID(),
            baselineDigest: sampleDigest, networkFingerprint: sampleDigest, coreSHA256: RouterCoreRelease.executableSHA256,
            coreVersion: RouterCoreRelease.version, compilerPolicy: RouterSystemCompiler.policyVersion)
        let interval = RouterTrafficInterval(
            start: .init(bootID: boot, uptime: 100, date: Date(timeIntervalSince1970: 2_000)),
            end: .init(bootID: boot, uptime: 120, date: Date(timeIntervalSince1970: 2_020)))
        let session = UUID()
        let records = try (allCases ? RouterTrafficCoveragePolicy.requirements(plan) : []).map { id in
            RouterTrafficCaseRecord(id: id, attempt: UUID(), session: session, bindingDigest: try binding.digest(),
                interval: interval, transcript: .init(outcome: .incomplete, requestNonce: UUID(),
                    endpointDigest: nil, expectedEgress: nil, reply: nil,
                    rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
        }
        return .init(version: 1, coveragePolicy: 1, session: session, before: binding, after: binding,
                     interval: interval, records: records)
    }

    /// Changes typed fixture values, then restores canonical storage encoding.
    func changed(_ value: RouterTrafficReceipt, _ edit: (inout [String: Any]) -> Void) throws -> RouterTrafficReceipt {
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: RouterTrafficCodec.encode(value)) as? [String: Any])
        edit(&object)
        return try JSONDecoder().decode(RouterTrafficReceipt.self, from: JSONSerialization.data(withJSONObject: object))
    }
    func echo(_ nonce: UUID = UUID(), endpoint: String? = nil) -> RouterTrafficEcho {
        .init(requestNonce: nonce, responseNonce: nonce, endpointDigest: endpoint ?? sampleDigest, observedAddress: "192.0.2.1")
    }
    func transcript(_ receipt: RouterTrafficReceipt, _ value: RouterTrafficTranscript, at index: Int = 0) throws -> RouterTrafficReceipt {
        let encoded = try JSONSerialization.jsonObject(with: RouterTrafficCodec.encode(value))
        return try changed(receipt) {
            var records = $0["records"] as! [[String: Any]]
            records[index]["transcript"] = encoded
            $0["records"] = records
        }
    }

    func testCoverageComesFromPlanAndKeepsBothFamiliesUDPAndNegativeSelectors() throws {
        let id = UUID(), proxy = UUID()
        let plan = RouterPlan(proxies: [.init(id: proxy, name: "HTTP", kind: .http, host: "127.0.0.1", port: 1082)],
            rules: [.init(id: id, selector: .init(processPath: "/Applications/Test.app/Contents/MacOS/Test",
                domain: .init(kind: .suffix, value: "example.com")), destination: .proxy(proxy))],
            defaultDestination: .direct)
        let cases = try RouterTrafficCoveragePolicy.requirements(plan)
        XCTAssertEqual(cases.count, 32)
        for variation in [RouterTrafficVariation.selected, .processOutside, .domainOutside, .suffixDescendant, .suffixBoundaryOutside] {
            for transport in [RouterTrafficTransport.tcp, .udp] {
                for family in [RouterTrafficFamily.ipv4, .ipv6] {
                    XCTAssertTrue(cases.contains(.init(rule: id, variation: variation, transport: transport, family: family)))
                }
            }
        }
        for variation in [RouterTrafficVariation.fallback, .dnsA, .dnsAAAA] {
            XCTAssertEqual(cases.filter { $0.rule == nil && $0.variation == variation }.count, 4)
        }
        var shadowed = plan
        shadowed.rules.insert(.init(id: UUID(), selector: .init(domain: .init(kind: .suffix, value: "example.com")),
                                   destination: .direct), at: 0)
        XCTAssertEqual(try RouterTrafficCoveragePolicy.requirements(shadowed).filter { $0.rule == id }.count, 20)
        var invalid = plan; invalid.rules.append(plan.rules[0])
        XCTAssertThrowsError(try RouterTrafficCoveragePolicy.requirements(invalid))
        invalid.rules = Array(repeating: plan.rules[0], count: 513)
        XCTAssertThrowsError(try RouterTrafficCoveragePolicy.requirements(invalid))
    }

    func testEmptyOrFullyPopulatedFixtureCannotBecomeAcceptedAndExportsItsLimits() throws {
        for full in [false, true] {
            let receipt = try fixture(allCases: full), bytes = try RouterTrafficCodec.encode(receipt)
            let decoded = try RouterTrafficCodec.decode(bytes, plan: plan, profile: profile)
            let assessment = try decoded.assess(plan: plan, profile: profile)
            XCTAssertEqual(assessment.cases.count, 12)
            XCTAssertFalse(assessment.canPromoteAccepted)
            XCTAssertEqual(assessment.status, "incomplete")
            XCTAssertTrue(assessment.cases.allSatisfy { !$0.gaps.isEmpty })
            let output = try XCTUnwrap(JSONSerialization.jsonObject(with: RouterTrafficCodec.encode(assessment)) as? [String: Any])
            XCTAssertEqual(output["canPromoteAccepted"] as? Bool, false)
            XCTAssertEqual(output["status"] as? String, "incomplete")
            XCTAssertEqual(Set(output["blockers"] as! [String]), ["controlPlaneRecipeMissing", "liveCollectorUnavailable"])
        }
    }

    func testBindingChangesCannotMixInstancesProcessesNetworkOrConfiguration() throws {
        let original = try fixture()
        let changes: [(String, Any)] = [("instance", UUID().uuidString), ("revision", UUID().uuidString),
            ("configurationDigest", String(repeating: "b", count: 64)), ("baselineID", UUID().uuidString),
            ("networkFingerprint", String(repeating: "b", count: 64)), ("compilerPolicy", 3)]
        for (key, value) in changes {
            let invalid = try changed(original) { var after = $0["after"] as! [String: Any]; after[key] = value; $0["after"] = after }
            XCTAssertThrowsError(try invalid.validate(plan: plan, profile: profile), key)
        }
        let process = try changed(original) {
            var after = $0["after"] as! [String: Any], work = after["work"] as! [String: Any]
            work["birthMicroseconds"] = 1; after["work"] = work; $0["after"] = after
        }
        XCTAssertThrowsError(try process.validate(plan: plan, profile: profile))
        XCTAssertThrowsError(try original.validate(plan: plan, profile: .init(resolver: .cloudflare)))
    }

    func testDuplicateExtraSessionAndAttemptRecordsReject() throws {
        let original = try fixture(allCases: true)
        for kind in ["duplicate_case", "attempt", "session", "binding", "unknown_rule"] {
            let invalid = try changed(original) {
                var records = $0["records"] as! [[String: Any]]
                switch kind {
                case "duplicate_case": records[1]["id"] = records[0]["id"]
                case "attempt": records[1]["attempt"] = records[0]["attempt"]
                case "session": records[0]["session"] = UUID().uuidString
                case "binding": records[0]["bindingDigest"] = String(repeating: "b", count: 64)
                default: var id = records[0]["id"] as! [String: Any]; id["rule"] = UUID().uuidString; records[0]["id"] = id
                }
                $0["records"] = records
            }
            XCTAssertThrowsError(try invalid.validate(plan: plan, profile: profile), kind)
        }
    }

    func testReceiptAndCaseClockWindowsRejectDriftBootChangeAndOutOfWindow() throws {
        let original = try fixture(allCases: true)
        for kind in ["boot", "drift", "too_long", "before_capture", "before_process", "case_after_capture"] {
            let invalid = try changed(original) {
                var interval = $0["interval"] as! [String: Any]
                var start = interval["start"] as! [String: Any], end = interval["end"] as! [String: Any]
                switch kind {
                case "boot": start["bootID"] = UUID().uuidString
                case "drift": end["uptime"] = 125
                case "too_long": end["uptime"] = 1101
                case "before_process": start["date"] = Date(timeIntervalSince1970: 999).timeIntervalSinceReferenceDate
                default:
                    var records = $0["records"] as! [[String: Any]]
                    var child = records[0]["interval"] as! [String: Any]
                    var clock = child[kind == "before_capture" ? "start" : "end"] as! [String: Any]
                    clock["uptime"] = kind == "before_capture" ? 99 : 121
                    child[kind == "before_capture" ? "start" : "end"] = clock
                    records[0]["interval"] = child; $0["records"] = records
                }
                interval["start"] = start; interval["end"] = end; $0["interval"] = interval
            }
            XCTAssertThrowsError(try invalid.validate(plan: plan, profile: profile), kind)
        }
    }

    func testEchoNonceAndEndpointMismatchRejectWhileMissingEgressRemainsGap() throws {
        let original = try fixture(allCases: true), nonce = UUID()
        let validEcho = echo(nonce)
        for value in [echo(), echo(nonce, endpoint: String(repeating: "b", count: 64))] {
            let invalid = try transcript(original, .init(outcome: .forwarded, requestNonce: nonce,
                endpointDigest: sampleDigest, expectedEgress: "192.0.2.1", reply: value,
                rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
            XCTAssertThrowsError(try invalid.validate(plan: plan, profile: profile))
        }
        let claimed = try transcript(original, .init(outcome: .forwarded, requestNonce: nonce,
            endpointDigest: sampleDigest, expectedEgress: "192.0.2.2", reply: validEcho,
            rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
        let result = try claimed.assess(plan: plan, profile: profile)
        XCTAssertTrue(result.cases[0].gaps.contains(.egressMismatch))
        XCTAssertEqual(result.status, "reported_failure")
        XCTAssertTrue(result.cases[0].gaps.contains(.ruleUncorrelated))
        XCTAssertFalse(result.canPromoteAccepted)
    }

    func testIPv6SpellingsDoNotProduceFalseMismatchAndMissingEgressIsNotFailure() throws {
        let original = try fixture(allCases: true), nonce = UUID()
        let reply = RouterTrafficEcho(requestNonce: nonce, responseNonce: nonce,
                                     endpointDigest: sampleDigest, observedAddress: "2001:db8::1")
        for expected in [nil, "2001:0db8:0:0:0:0:0:1"] as [String?] {
            let record = try transcript(original, .init(outcome: .forwarded, requestNonce: nonce,
                endpointDigest: sampleDigest, expectedEgress: expected, reply: reply,
                rejectControlBefore: nil, rejectControlAfter: nil, gaps: []))
            let result = try record.assess(plan: plan, profile: profile)
            XCTAssertEqual(result.status, "incomplete")
            XCTAssertEqual(result.cases[0].gaps.contains(.egressUnknown), expected == nil)
            XCTAssertFalse(result.cases[0].gaps.contains(.egressMismatch))
        }
    }

    func testCurrentPolicyAndCoreMetadataCannotContradictCurrentPlanDigest() throws {
        let original = try fixture()
        for (field, value) in [("coreVersion", "9.99"), ("coreSHA256", String(repeating: "b", count: 64)),
                               ("compilerPolicy", 999)] as [(String, Any)] {
            let invalid = try changed(original) {
                for side in ["before", "after"] {
                    var binding = $0[side] as! [String: Any]; binding[field] = value; $0[side] = binding
                }
            }
            XCTAssertThrowsError(try invalid.validate(plan: plan, profile: profile))
        }
    }

    func testDurationAndProcessBirthLimitsIndependently() throws {
        let original = try fixture()
        let beforeBirth = try changed(original) {
            var interval = $0["interval"] as! [String: Any]
            for (side, seconds) in [("start", 999.0), ("end", 1019.0)] {
                var clock = interval[side] as! [String: Any]
                clock["date"] = Date(timeIntervalSince1970: seconds).timeIntervalSinceReferenceDate
                interval[side] = clock
            }
            $0["interval"] = interval
        }
        XCTAssertThrowsError(try beforeBirth.validate(plan: plan, profile: profile))
        let start = original.interval.start
        for (limit, duration) in [(900.0, 901.0), (60.0, 61.0)] {
            let interval = RouterTrafficInterval(start: start, end: .init(bootID: start.bootID,
                uptime: start.uptime + duration, date: start.date.addingTimeInterval(duration)))
            XCTAssertThrowsError(try interval.validate(boot: start.bootID, maximumDuration: limit))
        }
    }

    func testRejectControlsNeverProveRejectionAndAllNoncesAreUniqueAcrossSession() throws {
        let original = try fixture(allCases: true), first = echo(), last = echo(), nonce = UUID()
        let claimed = try transcript(original, .init(outcome: .rejected, requestNonce: nonce,
            endpointDigest: sampleDigest, expectedEgress: nil, reply: nil,
            rejectControlBefore: first, rejectControlAfter: last, gaps: []))
        XCTAssertTrue(try claimed.assess(plan: plan, profile: profile).cases[0].gaps.contains(.rejectionUnproven))
        let reused = try transcript(claimed, .init(outcome: .incomplete, requestNonce: first.requestNonce,
            endpointDigest: nil, expectedEgress: nil, reply: nil,
            rejectControlBefore: nil, rejectControlAfter: nil, gaps: []), at: 1)
        XCTAssertThrowsError(try reused.validate(plan: plan, profile: profile))
        let repeatedControl = try transcript(original, .init(outcome: .rejected, requestNonce: nonce,
            endpointDigest: sampleDigest, expectedEgress: nil, reply: nil,
            rejectControlBefore: first, rejectControlAfter: first, gaps: []))
        XCTAssertThrowsError(try repeatedControl.validate(plan: plan, profile: profile))
    }

    func testFailedRecordsAreReportedSeparatelyAndCanonicalCodecRejectsUnknownNullAndDuplicates() throws {
        let original = try fixture(allCases: true)
        let failed = try transcript(original, .init(outcome: .failed, requestNonce: UUID(), endpointDigest: nil,
            expectedEgress: nil, reply: nil, rejectControlBefore: nil, rejectControlAfter: nil, gaps: [.endpointUnavailable]))
        XCTAssertEqual(try failed.assess(plan: plan, profile: profile).status, "reported_failure")
        let bytes = try RouterTrafficCodec.encode(original)
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        func canonical(_ object: [String: Any]) throws -> Data {
            try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys, .withoutEscapingSlashes])
        }
        XCTAssertNoThrow(try RouterTrafficCodec.decode(canonical(object), plan: plan, profile: profile))
        object["authenticated"] = true
        XCTAssertThrowsError(try RouterTrafficCodec.decode(canonical(object), plan: plan, profile: profile))
        object.removeValue(forKey: "authenticated")
        var records = object["records"] as! [[String: Any]], transcript = records[0]["transcript"] as! [String: Any]
        transcript["reply"] = NSNull(); records[0]["transcript"] = transcript; object["records"] = records
        XCTAssertThrowsError(try RouterTrafficCodec.decode(canonical(object), plan: plan, profile: profile))
        let duplicate = Data("{\"version\":1,".utf8) + bytes.dropFirst()
        XCTAssertThrowsError(try RouterTrafficCodec.decode(duplicate, plan: plan, profile: profile))
        XCTAssertThrowsError(try RouterTrafficCodec.decode(Data(repeating: 32, count: RouterTrafficCodec.maximumBytes + 1),
                                                         plan: plan, profile: profile))
    }
}
