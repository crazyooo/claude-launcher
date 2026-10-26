import Foundation
import Darwin

/// Offline record validation only. No decoded record is a live measurement authority.
enum RouterTrafficEvidenceError: String, Error {
    case invalidPlan, invalidReceipt, limitExceeded, sourceChanged
}

enum RouterTrafficFamily: String, Codable, Hashable { case ipv4, ipv6 }
enum RouterTrafficTransport: String, Codable, Hashable { case tcp, udp }
enum RouterTrafficVariation: String, Codable, Hashable {
    case selected, suffixDescendant, suffixBoundaryOutside, processOutside, domainOutside
    case fallback, dnsA, dnsAAAA
}

struct RouterTrafficCase: Codable, Hashable {
    let rule: UUID?
    let variation: RouterTrafficVariation
    let transport: RouterTrafficTransport
    let family: RouterTrafficFamily
}

enum RouterTrafficCoveragePolicy {
    static let version = 1
    static let maximumCases = 16_384

    /// Preserve impossible/shadowed cases as requirements; the collector must report
    /// their gaps. A caller cannot choose a smaller required list to obtain success.
    static func requirements(_ plan: RouterPlan) throws -> [RouterTrafficCase] {
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else {
            throw RouterTrafficEvidenceError.invalidPlan
        }
        var cases: [RouterTrafficCase] = []
        func add(_ rule: UUID?, _ variation: RouterTrafficVariation) {
            for transport in [RouterTrafficTransport.tcp, .udp] {
                for family in [RouterTrafficFamily.ipv4, .ipv6] {
                    cases.append(.init(rule: rule, variation: variation, transport: transport, family: family))
                }
            }
        }
        for rule in plan.rules {
            add(rule.id, .selected)
            if rule.selector.processPath != nil { add(rule.id, .processOutside) }
            if let domain = rule.selector.domain {
                add(rule.id, .domainOutside)
                if domain.kind == .suffix {
                    add(rule.id, .suffixDescendant)
                    add(rule.id, .suffixBoundaryOutside)
                }
            }
        }
        add(nil, .fallback)
        add(nil, .dnsA)
        add(nil, .dnsAAAA)
        guard cases.count <= maximumCases, Set(cases).count == cases.count else {
            throw RouterTrafficEvidenceError.limitExceeded
        }
        return cases
    }
}

enum RouterTrafficGap: String, Codable, Hashable {
    case notRun, endpointUnavailable, identityUnknown, shadowedRule, unsupportedFamily
    case dnsMappingUnknown, ruleUncorrelated, egressUnknown, egressMismatch, rejectionUnproven
    case liveCollectorUnavailable, controlPlaneRecipeMissing
}

struct RouterTrafficBinding: Codable {
    enum CapturePhase: String, Codable { case active }
    let phase: CapturePhase
    let installation: RouterSystemInstallationIdentity
    let instance: UUID
    let revision: UUID
    let work: RouterSystemWork
    let planDigest: String
    let configurationDigest: String
    let stageReceiptDigest: String
    let baselineID: UUID
    let baselineDigest: String
    let networkFingerprint: String
    let coreSHA256: String
    let coreVersion: String
    let compilerPolicy: Int

    func validate() throws {
        guard installation.isValid, work.pid > 1, work.birthSeconds > 0,
              work.birthMicroseconds < 1_000_000,
              compilerPolicy == RouterSystemCompiler.policyVersion,
              coreVersion == RouterCoreRelease.version, coreSHA256 == RouterCoreRelease.executableSHA256,
              [planDigest, configurationDigest, stageReceiptDigest, baselineDigest,
               networkFingerprint, coreSHA256].allSatisfy(RouterSystemProvider.validDigest) else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
    }

    func digest() throws -> String { RouterSystemObservation.hash(try RouterTrafficCodec.encode(self)) }
}

struct RouterTrafficInterval: Codable {
    let start: RouterSystemClock
    let end: RouterSystemClock

    func validate(boot: UUID, maximumDuration: TimeInterval) throws {
        let elapsed = end.uptime - start.uptime
        let wallElapsed = end.date.timeIntervalSince(start.date)
        guard start.bootID == boot, end.bootID == boot,
              start.uptime.isFinite, end.uptime.isFinite, start.uptime >= 0,
              elapsed >= 0, elapsed <= maximumDuration,
              start.date.timeIntervalSince1970.isFinite, end.date.timeIntervalSince1970.isFinite,
              wallElapsed >= 0, wallElapsed <= maximumDuration,
              abs(elapsed - wallElapsed) <= 2 else { throw RouterTrafficEvidenceError.invalidReceipt }
    }

    func contains(_ other: Self) -> Bool {
        other.start.uptime >= start.uptime && other.end.uptime <= end.uptime &&
        other.start.date >= start.date && other.end.date <= end.date
    }
}

/// This transcript is a bounded claim about an echo, not an authenticated witness.
struct RouterTrafficEcho: Codable {
    let requestNonce: UUID
    let responseNonce: UUID
    let endpointDigest: String
    let observedAddress: String

    func validate() throws {
        guard requestNonce == responseNonce, RouterSystemProvider.validDigest(endpointDigest),
              RouterValidation.isIP(observedAddress) else { throw RouterTrafficEvidenceError.invalidReceipt }
    }
}

struct RouterTrafficTranscript: Codable {
    enum Outcome: String, Codable { case forwarded, rejected, failed, incomplete }
    let outcome: Outcome
    let requestNonce: UUID
    let endpointDigest: String?
    let expectedEgress: String?
    let reply: RouterTrafficEcho?
    let rejectControlBefore: RouterTrafficEcho?
    let rejectControlAfter: RouterTrafficEcho?
    let gaps: [RouterTrafficGap]

    func validateShape() throws {
        guard gaps.count <= 16, Set(gaps).count == gaps.count,
              endpointDigest.map(RouterSystemProvider.validDigest) ?? true,
              expectedEgress.map(RouterValidation.isIP) ?? true else { throw RouterTrafficEvidenceError.invalidReceipt }
        for echo in [reply, rejectControlBefore, rejectControlAfter].compactMap({ $0 }) { try echo.validate() }
        if let reply {
            guard reply.requestNonce == requestNonce, reply.endpointDigest == endpointDigest else {
                throw RouterTrafficEvidenceError.invalidReceipt
            }
        }
        if outcome != .rejected {
            guard rejectControlBefore == nil, rejectControlAfter == nil else { throw RouterTrafficEvidenceError.invalidReceipt }
        } else {
            guard reply == nil else { throw RouterTrafficEvidenceError.invalidReceipt }
            for control in [rejectControlBefore, rejectControlAfter].compactMap({ $0 }) {
                guard control.endpointDigest == endpointDigest, control.requestNonce != requestNonce else {
                    throw RouterTrafficEvidenceError.invalidReceipt
                }
            }
        }
    }

    var nonces: [UUID] {
        [requestNonce] + [rejectControlBefore?.requestNonce, rejectControlAfter?.requestNonce].compactMap { $0 }
    }

    private static func addressBytes(_ text: String) -> Data? {
        var ipv4 = in_addr(), ipv6 = in6_addr()
        if text.withCString({ inet_pton(AF_INET, $0, &ipv4) }) == 1 {
            return withUnsafeBytes(of: ipv4) { Data($0) }
        }
        if text.withCString({ inet_pton(AF_INET6, $0, &ipv6) }) == 1 {
            return withUnsafeBytes(of: ipv6) { Data($0) }
        }
        return nil
    }
    var reportsEgressMismatch: Bool {
        guard outcome == .forwarded, let expectedEgress, let reply,
              let expected = Self.addressBytes(expectedEgress),
              let actual = Self.addressBytes(reply.observedAddress) else { return false }
        return expected != actual
    }
    var reportsFailure: Bool { outcome == .failed || reportsEgressMismatch }

    var missingFacts: Set<RouterTrafficGap> {
        var result = Set(gaps)
        // This schema does not yet represent matched-rule/process/DNS correlation
        // or timed, core-correlated rejection controls. Never infer these from an echo.
        result.insert(.ruleUncorrelated)
        switch outcome {
        case .forwarded:
            if reply == nil { result.insert(.endpointUnavailable) }
            if expectedEgress == nil || reply == nil { result.insert(.egressUnknown) }
            if reportsEgressMismatch { result.insert(.egressMismatch) }
        case .rejected: result.insert(.rejectionUnproven)
        case .failed, .incomplete: result.insert(.notRun)
        }
        return result
    }
}

struct RouterTrafficCaseRecord: Codable {
    let id: RouterTrafficCase
    let attempt: UUID
    let session: UUID
    let bindingDigest: String
    let interval: RouterTrafficInterval
    let transcript: RouterTrafficTranscript
}

struct RouterTrafficReceipt: Codable {
    let version: Int
    let coveragePolicy: Int
    let session: UUID
    let before: RouterTrafficBinding
    let after: RouterTrafficBinding
    let interval: RouterTrafficInterval
    let records: [RouterTrafficCaseRecord]

    func validate(plan: RouterPlan, profile: RouterSystemProfile) throws {
        try before.validate(); try after.validate()
        try interval.validate(boot: before.work.bootID, maximumDuration: 900)
        guard try RouterTrafficCodec.encode(before) == RouterTrafficCodec.encode(after),
              version == 1, coveragePolicy == RouterTrafficCoveragePolicy.version,
              before.planDigest == (try RouterSystemCompiler.digest(plan: plan, profile: profile)),
              interval.start.date.timeIntervalSince1970 >= Double(before.work.birthSeconds) +
                  Double(before.work.birthMicroseconds) / 1_000_000,
              records.count <= RouterTrafficCoveragePolicy.maximumCases,
              Set(records.map(\.id)).count == records.count,
              Set(records.map(\.attempt)).count == records.count else { throw RouterTrafficEvidenceError.invalidReceipt }
        let nonces = records.flatMap { $0.transcript.nonces }
        guard Set(nonces).count == nonces.count else { throw RouterTrafficEvidenceError.invalidReceipt }
        let required = Set(try RouterTrafficCoveragePolicy.requirements(plan)), digest = try before.digest()
        for record in records {
            guard required.contains(record.id), record.session == session,
                  record.bindingDigest == digest, interval.contains(record.interval) else {
                throw RouterTrafficEvidenceError.invalidReceipt
            }
            try record.interval.validate(boot: before.work.bootID, maximumDuration: 60)
            try record.transcript.validateShape()
        }
    }

    func assess(plan: RouterPlan, profile: RouterSystemProfile) throws -> RouterTrafficAssessment {
        try validate(plan: plan, profile: profile)
        let required = try RouterTrafficCoveragePolicy.requirements(plan)
        let observed = Dictionary(uniqueKeysWithValues: records.map { ($0.id, $0) })
        let cases = required.map { id -> RouterTrafficAssessment.Case in
            let record = observed[id]
            return .init(id: id, reportedFailure: record?.transcript.reportsFailure == true,
                         gaps: (record?.transcript.missingFacts ?? [.notRun]).sorted { $0.rawValue < $1.rawValue })
        }
        return .init(cases: cases,
                     controlPlane: try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile))
    }
}

/// No complete/success branch until the remaining semantic and authenticity
/// requirements exist. A fully populated fixture is still unverified.
struct RouterTrafficAssessment: Encodable {
    struct Case: Encodable {
        let id: RouterTrafficCase
        let reportedFailure: Bool
        let gaps: [RouterTrafficGap]
    }
    let cases: [Case]
    let controlPlaneCoveragePolicy = RouterControlPlaneCoverage.version
    let controlPlane: [RouterControlPlaneRequirement]
    let status: String
    let blockers: [RouterTrafficGap] = [.controlPlaneRecipeMissing, .liveCollectorUnavailable]
    let canPromoteAccepted = false

    init(cases: [Case], controlPlane: [RouterControlPlaneRequirement]) {
        self.cases = cases
        self.controlPlane = controlPlane
        status = cases.contains(where: \.reportedFailure) ? "reported_failure" : "incomplete"
    }
}

enum RouterTrafficCodec {
    static let maximumBytes = 8 * 1024 * 1024
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard data.count <= maximumBytes else { throw RouterTrafficEvidenceError.limitExceeded }
        return data
    }

    static func decode(_ bytes: Data, plan: RouterPlan, profile: RouterSystemProfile) throws -> RouterTrafficReceipt {
        do {
            _ = try RouterStrictJSON.object(bytes, maximumBytes: maximumBytes, maximumValues: 1_000_000)
            let receipt = try JSONDecoder().decode(RouterTrafficReceipt.self, from: bytes)
            // Private immutable storage is canonical: this also rejects ignored
            // fields, explicit nulls, and alternate representations of scalar values.
            guard try encode(receipt) == bytes else { throw RouterTrafficEvidenceError.invalidReceipt }
            try receipt.validate(plan: plan, profile: profile)
            return receipt
        } catch { throw RouterTrafficEvidenceError.invalidReceipt }
    }
}
