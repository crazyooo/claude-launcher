import Foundation
import CoreFoundation

/// Stable across upgrades; changing the approved user requires an explicit installation migration.
struct RouterSystemInstallationIdentity: Codable, Equatable {
    let id: UUID
    let ownerUID: UInt32
    var isValid: Bool { ownerUID >= 501 && ownerUID < UInt32.max }
}

struct RouterSystemClock: Codable, Equatable {
    let bootID: UUID
    let uptime: TimeInterval
    let date: Date
}
struct RouterSystemIntent: Codable, Equatable {
    let id: UUID
    let plan: RouterPlan
    let profile: RouterSystemProfile
    let digest: String
    let networkFingerprint: String
    let issued: RouterSystemClock
    let expiresAt: Date
    let deadlineUptime: TimeInterval
}
struct RouterSystemWork: Codable, Equatable {
    let bootID: UUID
    let pid: Int32
    let birthSeconds: UInt64
    let birthMicroseconds: UInt64
}
/// Persisted before spawn, including the case where the child identity is not yet available.
struct RouterSystemDispatchFence: Codable, Equatable {
    let instance: UUID
    let host: RouterSystemWork
    let processGroup: Int32
    let gateDeadlineUptime: TimeInterval
    let gateExpiresAt: Date
    let baselineID: UUID
    let baselineDigest: String
    let networkFingerprint: String
    let configurationDigest: String
}
struct RouterSystemFootprint: Codable, Equatable {
    let instance: UUID
    let work: RouterSystemWork
    let configurationDigest: String
    let interfaceName: String
    let interfaceIndex: UInt32
    let addresses: [String]
    let routeSignatures: [String]
}
struct RouterAcceptedConfiguration: Codable, Equatable {
    let plan: RouterPlan
    let profile: RouterSystemProfile
    let configurationDigest: String
    let acceptanceEvidenceDigest: String
}
struct RouterSystemJournal: Codable {
    enum Phase: String, Codable { case idle, prepared, applying, active, stopping, fault, stopped }
    let version: Int
    var installation: RouterSystemInstallationIdentity?
    var revision: UUID
    var phase: Phase
    var intent: RouterSystemIntent?
    var configurationDigest: String?
    var dispatch: RouterSystemDispatchFence?
    var work: RouterSystemWork?
    var footprint: RouterSystemFootprint?
    var reason: String
    var accepted: RouterAcceptedConfiguration?
    var previousAccepted: RouterAcceptedConfiguration?
    var environmentReview: RouterSystemEnvironmentTransition?
    var usedEnvironmentReviewIDs: [UUID]?
    static let reasons: [Phase: Set<String>] = [
        .idle: ["no_system_instance"], .prepared: ["prepared_not_applied"], .applying: ["execution_pending"],
        .fault: ["execution_outcome_unconfirmed", "runtime_evidence_incomplete"],
        .stopped: ["unused_preview_cancelled", "owned_cleanup_confirmed", "external_environment_acknowledged"],
        .stopping: ["owned_stop_pending", "external_environment_changed"],
        .active: ["capture_observed_traffic_acceptance_pending"]]
    static func empty() -> Self {
        .init(version: 1, revision: UUID(), phase: .idle, reason: "no_system_instance")
    }
}
struct RouterSystemRuntimeObservation {
    let instance: UUID
    let ownershipConfirmed: Bool
    let processAlive: Bool
    let controllerHealthy: Bool
    let capturePresent: Bool
    let footprint: RouterSystemFootprint?
    let startWorkSettled: Bool
    var ipv6CaptureObserved: Bool? = nil
}
struct RouterSystemCleanupProof {
    let instance: UUID
    let dispatch: RouterSystemDispatchFence?
    let startWorkSettled: Bool
    let processExited: Bool
    let interfaceAbsent: Bool
    let routesAbsent: Bool
    let externalStatePreserved: Bool
    var complete: Bool { startWorkSettled && processExited && interfaceAbsent && routesAbsent && externalStatePreserved }
    var ownedResourcesAbsent: Bool { startWorkSettled && processExited && interfaceAbsent && routesAbsent }
}

/// Only this fixed projection may cross IPC. No plaintext config, credentials or raw system output.
public struct RouterSystemStatus: Encodable {
    public let instance: UUID?
    public let phase: String
    public let reason: String
    public let planDigest: String?
    public let previewExpiresAt: Date?
    public let processObserved: Bool
    public let controllerHealthy: Bool
    public let captureObserved: Bool
    public let ipv6CaptureObserved: Bool?
    public let cleanupConfirmed: Bool
    public let environmentReview: RouterSystemEnvironmentReview?
    public var ownedResourcesReleased: Bool {
        cleanupConfirmed || (phase == "stopped" && reason == "external_environment_acknowledged")
    }
    public let routingVerified = false
    public let protectionVerified = false
    public let launchAuthorized = false
    init(_ state: RouterSystemJournal, observation: RouterSystemRuntimeObservation? = nil) {
        instance = state.intent?.id; phase = state.phase.rawValue; reason = state.reason
        planDigest = state.intent?.digest; previewExpiresAt = state.phase == .prepared ? state.intent?.expiresAt : nil
        let bound = observation?.instance == state.intent?.id && observation?.ownershipConfirmed == true
        processObserved = bound && observation?.processAlive == true
        controllerHealthy = bound && observation?.controllerHealthy == true
        captureObserved = bound && observation?.capturePresent == true
        ipv6CaptureObserved = bound ? observation?.ipv6CaptureObserved : nil
        cleanupConfirmed = state.phase == .stopped && state.reason != "external_environment_acknowledged"
        environmentReview = state.environmentReview?.review
    }
}

extension RouterSystemStatus {
    // Public diagnosis only; this reason is deliberately invalid in a persisted journal.
    static let observationUnavailableReason = "runtime_observation_unavailable"
    static func managementOnly(_ state: RouterSystemJournal) throws -> Self {
        var projection = state
        switch state.phase {
        case .applying, .active, .fault:
            projection.phase = .fault; projection.reason = observationUnavailableReason
        case .stopping: break
        default: throw RouterSystemError.ownershipUnknown
        }
        return .init(projection)
    }

    /// No Decodable conformance: callers cannot bypass validation through synthesized constant fields.
    static func decodeWire(_ object: [String: Any]) throws -> Self {
        let flags: Set<String> = ["processObserved", "controllerHealthy", "captureObserved", "cleanupConfirmed",
                                  "routingVerified", "protectionVerified", "launchAuthorized"]
        let required = flags.union(["phase", "reason"])
        let optional: Set<String> = ["instance", "planDigest", "previewExpiresAt", "ipv6CaptureObserved", "environmentReview"]
        let keys = Set(object.keys)
        guard required.isSubset(of: keys), keys.isSubset(of: required.union(optional)),
              !object.values.contains(where: { $0 is NSNull }) else { throw RouterSystemError.invalidRequest }
        for key in flags.union(keys.intersection(["ipv6CaptureObserved"])) {
            guard let value = object[key] as? NSNumber,
                  CFGetTypeID(value) == CFBooleanGetTypeID() else { throw RouterSystemError.invalidRequest }
        }
        struct Wire: Decodable {
            let instance: UUID?
            let phase: String
            let reason: String
            let planDigest: String?
            let previewExpiresAt: Date?
            let processObserved: Bool
            let controllerHealthy: Bool
            let captureObserved: Bool
            let ipv6CaptureObserved: Bool?
            let cleanupConfirmed: Bool
            let routingVerified: Bool
            let protectionVerified: Bool
            let launchAuthorized: Bool
            let environmentReview: RouterSystemEnvironmentReview?
        }
        let wire: Wire
        do { wire = try JSONDecoder().decode(Wire.self, from: JSONSerialization.data(withJSONObject: object)) }
        catch { throw RouterSystemError.invalidRequest }
        guard let phase = RouterSystemJournal.Phase(rawValue: wire.phase),
              RouterSystemJournal.reasons[phase]?.contains(wire.reason) == true ||
                  (phase == .fault && wire.reason == observationUnavailableReason),
              !wire.reason.isEmpty, wire.reason.utf8.count <= 128,
              wire.reason.utf8.allSatisfy({ (97...122).contains($0) || (48...57).contains($0) || $0 == 95 }),
              !wire.routingVerified, !wire.protectionVerified, !wire.launchAuthorized,
              wire.planDigest.map(RouterSystemProvider.validDigest) ?? true,
              wire.previewExpiresAt.map({ $0.timeIntervalSince1970.isFinite }) ?? true,
              (wire.phase == "idle") == (wire.instance == nil),
              (wire.instance == nil) == (wire.planDigest == nil),
              (wire.phase == "prepared") == (wire.previewExpiresAt != nil),
              !wire.captureObserved || (wire.processObserved && wire.controllerHealthy),
              wire.ipv6CaptureObserved != true || wire.captureObserved,
              wire.cleanupConfirmed == (wire.phase == "stopped" && wire.reason != "external_environment_acknowledged") else { throw RouterSystemError.invalidRequest }
        if let review = wire.environmentReview {
            guard let object = object["environmentReview"] as? [String: Any],
                  Set(object.keys) == ["id", "instance", "digest", "fingerprint", "createdAt", "expiresAt", "changes"],
                  review.instance == wire.instance,
                  (phase == .stopping && wire.reason == "external_environment_changed") ||
                    (phase == .stopped && wire.reason == "external_environment_acknowledged") else { throw RouterSystemError.invalidRequest }
            do { try review.validate() } catch { throw RouterSystemError.invalidRequest }
        } else if wire.reason == "external_environment_acknowledged" { throw RouterSystemError.invalidRequest }
        let hasObservation = wire.processObserved || wire.controllerHealthy || wire.captureObserved || wire.ipv6CaptureObserved != nil
        guard wire.reason != observationUnavailableReason || !hasObservation,
              !wire.controllerHealthy || wire.processObserved,
              !hasObservation || [.applying, .active, .fault].contains(phase),
              phase != .active || (wire.processObserved && wire.controllerHealthy && wire.captureObserved) else {
            throw RouterSystemError.invalidRequest
        }
        return Self(instance: wire.instance, phase: wire.phase, reason: wire.reason, planDigest: wire.planDigest,
                    previewExpiresAt: wire.previewExpiresAt, processObserved: wire.processObserved,
                    controllerHealthy: wire.controllerHealthy, captureObserved: wire.captureObserved,
                    ipv6CaptureObserved: wire.ipv6CaptureObserved, cleanupConfirmed: wire.cleanupConfirmed,
                    environmentReview: wire.environmentReview)
    }
    private init(instance: UUID?, phase: String, reason: String, planDigest: String?, previewExpiresAt: Date?,
                 processObserved: Bool, controllerHealthy: Bool, captureObserved: Bool,
                 ipv6CaptureObserved: Bool?, cleanupConfirmed: Bool, environmentReview: RouterSystemEnvironmentReview?) {
        self.instance = instance; self.phase = phase; self.reason = reason; self.planDigest = planDigest
        self.previewExpiresAt = previewExpiresAt; self.processObserved = processObserved
        self.controllerHealthy = controllerHealthy; self.captureObserved = captureObserved
        self.ipv6CaptureObserved = ipv6CaptureObserved; self.cleanupConfirmed = cleanupConfirmed
        self.environmentReview = environmentReview
    }
}
