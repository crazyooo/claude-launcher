import Foundation
import Darwin

/// Private observations. Raw DNS and route records never cross the public IPC boundary.
struct RouterSystemBaselineSnapshot: Codable {
    let captured: RouterSystemClock
    let networkFingerprint: String
    let interfaces: [RouterSystemInterfaceSnapshot.Interface]
    let routesIPv4: String
    let routesIPv6: String
    let dns: String

    func validate() throws {
        guard captured.uptime.isFinite, captured.uptime >= 0, captured.date.timeIntervalSince1970.isFinite,
              RouterSystemProvider.validDigest(networkFingerprint), !interfaces.isEmpty, interfaces.count <= 256,
              Set(interfaces.map(\.name)).count == interfaces.count, Set(interfaces.map(\.index)).count == interfaces.count else {
            throw RouterSystemError.ownershipUnknown
        }
        for value in interfaces { try value.validate() }
        for text in [routesIPv4, routesIPv6, dns] {
            guard !text.isEmpty, text.utf8.count <= 65_536, !text.utf8.contains(0) else { throw RouterSystemError.ownershipUnknown }
        }
        _ = try RouterSystemObservation.RouteTable.parse(routesIPv4, family: "inet")
        _ = try RouterSystemObservation.RouteTable.parse(routesIPv6, family: "inet6")
        _ = try RouterSystemDNS.parse(dns)
    }

    /// Stable configuration comparison for repeated snapshots, never a complete cleanup proof.
    func sameStartEnvironment(as other: Self) throws -> Bool {
        try validate(); try other.validate()
        let v4 = try RouterSystemObservation.RouteTable.parse(routesIPv4, family: "inet")
        let other4 = try RouterSystemObservation.RouteTable.parse(other.routesIPv4, family: "inet")
        let v6 = try RouterSystemObservation.RouteTable.parse(routesIPv6, family: "inet6")
        let other6 = try RouterSystemObservation.RouteTable.parse(other.routesIPv6, family: "inet6")
        let resolver = try RouterSystemDNS.parse(dns).canonical, otherResolver = try RouterSystemDNS.parse(other.dns).canonical
        return captured.bootID == other.captured.bootID && networkFingerprint == other.networkFingerprint &&
            interfaces == other.interfaces && v4 == other4 && v6 == other6 && resolver == otherResolver
    }

    static func collect(command: RouterSystemCommand, network: () throws -> RouterSystemObservation) throws -> Self {
        try collect(read: command.run, interfaces: RouterSystemInterfaceSnapshot.collect,
                    network: network, clock: RouterSystemKernelObservation.clock)
    }
    static func collect(read: (RouterSystemCommand.Command) throws -> (RouterProcessResult, Data),
                        interfaces: () throws -> [RouterSystemInterfaceSnapshot.Interface],
                        network: () throws -> RouterSystemObservation,
                        clock: () throws -> RouterSystemClock) throws -> Self {
        func query(_ command: RouterSystemCommand.Command) throws -> String {
            let (result, data) = try read(command)
            guard result.settled, !result.timedOut, result.exitCode == 0, data.count <= 65_536,
                  let text = String(data: data, encoding: .utf8) else { throw RouterSystemError.operationUnsettled }
            return text
        }
        func round() throws -> Self {
            let began = try clock(), observation = try network()
            guard observation.complete else { throw RouterSystemError.networkConflict }
            let devices = try interfaces(), v4 = try query(.routesIPv4), v6 = try query(.routesIPv6), dns = try query(.dnsState)
            let ended = try clock()
            guard ended.bootID == began.bootID, ended.uptime >= began.uptime, ended.date >= began.date else {
                throw RouterSystemError.networkConflict
            }
            let snapshot = Self(captured: ended, networkFingerprint: observation.fingerprint, interfaces: devices,
                                routesIPv4: v4, routesIPv6: v6, dns: dns)
            try snapshot.validate()
            return snapshot
        }
        let first = try round(), second = try round()
        guard second.captured.uptime >= first.captured.uptime, second.captured.date >= first.captured.date,
              try first.sameStartEnvironment(as: second) else { throw RouterSystemError.networkConflict }
        return second
    }
}

struct RouterSystemBaselineReceipt: Codable {
    let version: Int
    let installation: RouterSystemInstallationIdentity
    let instance: UUID
    let planDigest: String
    let configurationDigest: String
    let host: RouterSystemWork
    let processGroup: Int32
    let gateDeadlineUptime: TimeInterval
    let gateExpiresAt: Date
    let baselineID: UUID
    let snapshot: RouterSystemBaselineSnapshot

    func fence(digest: String) -> RouterSystemDispatchFence {
        .init(instance: instance, host: host, processGroup: processGroup,
              gateDeadlineUptime: gateDeadlineUptime, gateExpiresAt: gateExpiresAt,
              baselineID: baselineID, baselineDigest: digest, networkFingerprint: snapshot.networkFingerprint,
              configurationDigest: configurationDigest)
    }
}

/// Immutable files under a validated stage. An interrupted write is preserved, never overwritten.
final class RouterSystemBaselineStore {
    private struct Claim: Encodable {
        let version = 1
        let installation: RouterSystemInstallationIdentity
        let dispatch: RouterSystemDispatchFence
    }
    private static let claimName = "dispatch-claim.json"
    private let state: RouterSystemDirectory
    private let identity: RouterSystemInstallationIdentity
    private let clock: () throws -> RouterSystemClock
    private let synchronize: (Int32) -> Int32
    private let lock = NSLock()
    private static let maximumBytes = 1024 * 1024

    convenience init(installation: RouterSystemInstallation) throws {
        try installation.verifyCode()
        self.init(state: installation.state, identity: installation.manifest.identity, clock: RouterSystemKernelObservation.clock)
    }
    private init(state: RouterSystemDirectory, identity: RouterSystemInstallationIdentity,
                 clock: @escaping () throws -> RouterSystemClock, synchronize: @escaping (Int32) -> Int32 = fsync) {
        self.state = state; self.identity = identity; self.clock = clock; self.synchronize = synchronize
    }
    static func fixture(state: RouterSystemDirectory, identity: RouterSystemInstallationIdentity,
                        clock: @escaping () throws -> RouterSystemClock,
                        synchronize: @escaping (Int32) -> Int32 = fsync) throws -> RouterSystemBaselineStore {
        guard getuid() != 0, geteuid() != 0, identity.isValid else { throw RouterSystemError.ownershipUnknown }
        return .init(state: state, identity: identity, clock: clock, synchronize: synchronize)
    }

    func create(intent: RouterSystemIntent, configurationDigest: String, host: RouterSystemWork,
                snapshot: RouterSystemBaselineSnapshot) throws -> RouterSystemDispatchFence {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try requireUnclaimedUnlocked(intent.id)
        let before = try fresh(intent)
        guard snapshot.captured.bootID == before.bootID, snapshot.captured.uptime <= before.uptime,
              snapshot.captured.date <= before.date else { throw RouterSystemError.stalePreview }
        let receipt = RouterSystemBaselineReceipt(version: 1, installation: identity, instance: intent.id,
            planDigest: intent.digest, configurationDigest: configurationDigest, host: host, processGroup: host.pid,
            gateDeadlineUptime: intent.deadlineUptime, gateExpiresAt: intent.expiresAt, baselineID: UUID(), snapshot: snapshot)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(receipt)
        guard bytes.count <= Self.maximumBytes else { throw RouterSystemError.journalUnknown }
        let fence = receipt.fence(digest: RouterSystemObservation.hash(bytes))
        try validate(receipt, intent: intent, fence: fence)
        let directory = try stage(intent.id)
        try directory.boundedEntryCount(maximum: 64)
        let name = filename(receipt.baselineID)
        try directory.create(name, data: bytes)
        try directory.synchronizeFile(name, expected: bytes, synchronize: synchronize)
        try directory.validate(); try state.validate()
        guard synchronize(directory.fd) == 0, synchronize(state.fd) == 0 else { throw RouterSystemError.journalUnknown }
        _ = try readUnlocked(intent: intent, fence: fence)
        let after = try fresh(intent)
        guard snapshot.captured.uptime <= after.uptime, snapshot.captured.date <= after.date else {
            throw RouterSystemError.stalePreview
        }
        return fence
    }

    func requireUnclaimed(_ instance: UUID) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try requireUnclaimedUnlocked(instance)
    }
    private func requireUnclaimedUnlocked(_ instance: UUID) throws {
        guard let directory = try state.childIfPresent("stage-" + instance.uuidString.lowercased()) else { return }
        // Empty, partial, corrupt or valid records all consume the original execution identity.
        guard try directory.read(Self.claimName, maximum: 4096) == nil else { throw RouterSystemError.operationUnsettled }
    }
    /// One-shot durable consumption, not an idempotent permission. A failed call never permits spawn.
    /// Archive/retirement must preserve this tombstone or migrate it without allowing UUID reuse.
    func claim(intent: RouterSystemIntent, fence: RouterSystemDispatchFence, verifyApplying: () throws -> Void) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        _ = try fresh(intent)
        _ = try readUnlocked(intent: intent, fence: fence)
        try requireUnclaimedUnlocked(intent.id)
        try verifyApplying()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let bytes = try encoder.encode(Claim(installation: identity, dispatch: fence))
        guard bytes.count <= 4096 else { throw RouterSystemError.journalUnknown }
        let directory = try stage(intent.id)
        try directory.create(Self.claimName, data: bytes) // O_EXCL, including across host restarts.
        try directory.synchronizeFile(Self.claimName, expected: bytes, synchronize: synchronize)
        try directory.validate(); try state.validate()
        guard synchronize(directory.fd) == 0, synchronize(state.fd) == 0,
              try directory.read(Self.claimName, maximum: 4096) == bytes else { throw RouterSystemError.journalUnknown }
        try verifyApplying()
        _ = try fresh(intent)
    }

    /// Verification consumes no new permission; even a readable partial claim never authorizes execution.
    func verifyClaim(intent: RouterSystemIntent, fence: RouterSystemDispatchFence) throws {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        _ = try readUnlocked(intent: intent, fence: fence)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let expected = try encoder.encode(Claim(installation: identity, dispatch: fence))
        guard expected.count <= 4096, try stage(intent.id).read(Self.claimName, maximum: 4096) == expected else {
            throw RouterSystemError.ownershipUnknown
        }
    }

    func read(intent: RouterSystemIntent, fence: RouterSystemDispatchFence) throws -> RouterSystemBaselineReceipt {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        return try readUnlocked(intent: intent, fence: fence)
    }
    private func readUnlocked(intent: RouterSystemIntent, fence: RouterSystemDispatchFence) throws -> RouterSystemBaselineReceipt {
        let directory = try stage(intent.id)
        guard let bytes = try directory.read(filename(fence.baselineID), maximum: Self.maximumBytes),
              RouterSystemObservation.hash(bytes) == fence.baselineDigest else { throw RouterSystemError.ownershipUnknown }
        do {
            let input = try RouterStrictJSON.object(bytes, maximumBytes: Self.maximumBytes, maximumValues: 50_000)
            let receipt = try JSONDecoder().decode(RouterSystemBaselineReceipt.self, from: bytes)
            let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(receipt))
            guard Self.sameFields(input, encoded) else { throw RouterSystemError.journalUnknown }
            try validate(receipt, intent: intent, fence: fence)
            return receipt
        } catch { throw RouterSystemError.journalUnknown }
    }
    private func validate(_ receipt: RouterSystemBaselineReceipt, intent: RouterSystemIntent, fence: RouterSystemDispatchFence) throws {
        try RouterSystemProvider.validateDispatch(fence, intent: intent, configurationDigest: fence.configurationDigest)
        try receipt.snapshot.validate()
        let captured = receipt.snapshot.captured
        guard receipt.version == 1, receipt.installation == identity, receipt.planDigest == intent.digest,
              intent.digest == (try RouterSystemCompiler.digest(plan: intent.plan, profile: intent.profile)),
              receipt.fence(digest: fence.baselineDigest) == fence,
              captured.bootID == intent.issued.bootID, captured.uptime >= intent.issued.uptime,
              captured.uptime < intent.deadlineUptime, captured.date >= intent.issued.date, captured.date < intent.expiresAt else {
            throw RouterSystemError.ownershipUnknown
        }
    }
    private func fresh(_ intent: RouterSystemIntent) throws -> RouterSystemClock {
        let now = try clock()
        guard now.bootID == intent.issued.bootID, now.uptime >= intent.issued.uptime, now.uptime < intent.deadlineUptime,
              now.date >= intent.issued.date, now.date < intent.expiresAt else { throw RouterSystemError.stalePreview }
        return now
    }
    private func stage(_ instance: UUID) throws -> RouterSystemDirectory {
        try state.child("stage-" + instance.uuidString.lowercased())
    }
    private func filename(_ id: UUID) -> String { "baseline-" + id.uuidString.lowercased() + ".json" }
    private static func sameFields(_ a: Any, _ b: Any) -> Bool {
        if let x = a as? [String: Any], let y = b as? [String: Any] {
            return Set(x.keys) == Set(y.keys) && x.allSatisfy { sameFields($0.value, y[$0.key]!) }
        }
        if let x = a as? [Any], let y = b as? [Any] { return x.count == y.count && zip(x, y).allSatisfy { sameFields($0, $1) } }
        return !(a is NSNull) && !(a is [Any]) && !(a is [String: Any]) && !(b is [Any]) && !(b is [String: Any])
    }
}
