import Foundation

/// A historical, bounded projection. Raw interfaces, routes and DNS stay in the root component.
public struct RouterSystemEnvironmentReview: Codable, Equatable {
    public let id: UUID
    public let instance: UUID
    public let digest: String
    public let fingerprint: String
    public let createdAt: Date
    public let expiresAt: Date
    public let changes: [String]

    func validate() throws {
        let allowed: Set<String> = ["boot", "interfaces", "routes", "dns", "network_settings"]
        guard RouterSystemProvider.validDigest(digest), RouterSystemProvider.validDigest(fingerprint),
              createdAt.timeIntervalSince1970.isFinite, expiresAt == createdAt.addingTimeInterval(60),
              !changes.isEmpty, changes == Array(Set(changes)).sorted(), Set(changes).isSubset(of: allowed) else {
            throw RouterSystemError.journalUnknown
        }
    }
}

struct RouterSystemEnvironmentCandidate {
    let sampled: RouterSystemClock
    let fingerprint: String
    let changes: [String]
    let proof: RouterSystemCleanupProof
}

/// Permission and confirmation share the journal's existing atomic CAS; no second commit record.
struct RouterSystemEnvironmentTransition: Codable, Equatable {
    let review: RouterSystemEnvironmentReview
    let issued: RouterSystemClock
    let sourceDigest: String
    var confirmed: RouterSystemClock?

    private struct Source: Encodable {
        let installation: RouterSystemInstallationIdentity
        let intent: RouterSystemIntent
        let dispatch: RouterSystemDispatchFence
        let work: RouterSystemWork
        let footprint: RouterSystemFootprint
        let configurationDigest: String
    }
    private struct Permission: Encodable {
        let id: UUID
        let instance: UUID
        let sourceDigest: String
        let fingerprint: String
        let issued: RouterSystemClock
        let changes: [String]
    }
    static func source(_ state: RouterSystemJournal) throws -> String {
        guard let installation = state.installation, installation.isValid, let intent = state.intent,
              let dispatch = state.dispatch, let work = state.work, let footprint = state.footprint,
              let configurationDigest = state.configurationDigest else { throw RouterSystemError.ownershipUnknown }
        return try hash(Source(installation: installation, intent: intent, dispatch: dispatch,
                               work: work, footprint: footprint, configurationDigest: configurationDigest))
    }
    static func make(_ state: RouterSystemJournal, id: UUID, candidate: RouterSystemEnvironmentCandidate) throws -> Self {
        try requireOwned(candidate, state: state)
        let source = try source(state)
        let permission = Permission(id: id, instance: candidate.proof.instance, sourceDigest: source,
            fingerprint: candidate.fingerprint, issued: candidate.sampled, changes: candidate.changes)
        let review = RouterSystemEnvironmentReview(id: id, instance: permission.instance,
            digest: try hash(permission), fingerprint: candidate.fingerprint, createdAt: candidate.sampled.date,
            expiresAt: candidate.sampled.date.addingTimeInterval(60), changes: candidate.changes)
        try review.validate()
        return .init(review: review, issued: candidate.sampled, sourceDigest: source)
    }
    func validate(in state: RouterSystemJournal) throws {
        try review.validate()
        guard issued.uptime.isFinite, issued.uptime >= 0, issued.date == review.createdAt,
              state.intent?.id == review.instance, state.usedEnvironmentReviewIDs?.last == review.id,
              try sourceDigest == Self.source(state),
              try review.digest == Self.hash(Permission(id: review.id, instance: review.instance,
                sourceDigest: sourceDigest, fingerprint: review.fingerprint, issued: issued, changes: review.changes)) else {
            throw RouterSystemError.journalUnknown
        }
        if let confirmed {
            guard state.phase == .stopped, state.reason == "external_environment_acknowledged" else {
                throw RouterSystemError.journalUnknown
            }
            try requireFresh(confirmed)
        } else {
            guard state.phase == .stopping, state.reason == "external_environment_changed" else {
                throw RouterSystemError.journalUnknown
            }
        }
    }
    func requireFresh(_ now: RouterSystemClock) throws {
        guard now.bootID == issued.bootID, now.uptime.isFinite, now.date.timeIntervalSince1970.isFinite,
              now.uptime >= issued.uptime, now.uptime < issued.uptime + 60,
              now.date >= issued.date, now.date < review.expiresAt else { throw RouterSystemError.stalePreview }
    }
    func requireMatch(_ candidate: RouterSystemEnvironmentCandidate, state: RouterSystemJournal) throws {
        try Self.requireOwned(candidate, state: state)
        guard try Self.source(state) == sourceDigest,
              candidate.fingerprint == review.fingerprint, candidate.changes == review.changes else {
            throw RouterSystemError.networkConflict
        }
        try requireFresh(candidate.sampled)
    }
    static func requireOwned(_ candidate: RouterSystemEnvironmentCandidate, state: RouterSystemJournal) throws {
        guard state.footprint != nil, state.work != nil, candidate.proof.instance == state.intent?.id,
              let dispatch = state.dispatch, candidate.proof.dispatch == dispatch,
              candidate.proof.ownedResourcesAbsent, !candidate.proof.externalStatePreserved else {
            throw RouterSystemError.cleanupUnproven
        }
    }
    private static func hash<T: Encodable>(_ value: T) throws -> String {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return RouterSystemObservation.hash(try encoder.encode(value))
    }
}

extension RouterSystemBaselineSnapshot {
    /// Same normalization as existing start checks, plus full interface and effective DNS state.
    /// A hash match is never evidence that owned work has exited.
    func environmentDigest() throws -> String {
        try validate()
        struct Environment: Encodable {
            let boot: UUID
            let network: String
            let interfaces: [RouterSystemInterfaceSnapshot.Interface]
            let ipv4: String
            let ipv6: String
            let dns: String
        }
        let value = try Environment(boot: captured.bootID, network: networkFingerprint,
            interfaces: interfaces.sorted { $0.name < $1.name },
            ipv4: RouterSystemObservation.RouteTable.parse(routesIPv4, family: "inet").canonical,
            ipv6: RouterSystemObservation.RouteTable.parse(routesIPv6, family: "inet6").canonical,
            dns: RouterSystemDNS.parse(dns).canonical)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return RouterSystemObservation.hash(try encoder.encode(value))
    }
    func changes(from old: Self) throws -> [String] {
        try validate(); try old.validate()
        var changes: [String] = []
        if captured.bootID != old.captured.bootID { changes.append("boot") }
        if interfaces.sorted(by: { $0.name < $1.name }) != old.interfaces.sorted(by: { $0.name < $1.name }) { changes.append("interfaces") }
        if try RouterSystemObservation.RouteTable.parse(routesIPv4, family: "inet") !=
            RouterSystemObservation.RouteTable.parse(old.routesIPv4, family: "inet") ||
            RouterSystemObservation.RouteTable.parse(routesIPv6, family: "inet6") !=
            RouterSystemObservation.RouteTable.parse(old.routesIPv6, family: "inet6") { changes.append("routes") }
        if try RouterSystemDNS.parse(dns).canonical != RouterSystemDNS.parse(old.dns).canonical { changes.append("dns") }
        if networkFingerprint != old.networkFingerprint { changes.append("network_settings") }
        return changes.sorted()
    }
}
