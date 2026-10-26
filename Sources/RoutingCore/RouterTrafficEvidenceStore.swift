import Foundation
import Darwin

/// Eight immutable, private records per verified source stage. Reads never create
/// files. Production has no writer until a separately reviewed live collector exists.
final class RouterTrafficEvidenceStore {
    static let capacity = 8
    private let source: RouterSystemStage.EvidenceSource
    private let synchronize: (Int32) -> Int32
    private let lock = NSLock()

    init(source: RouterSystemStage.EvidenceSource, synchronize: @escaping (Int32) -> Int32 = fsync) {
        self.source = source; self.synchronize = synchronize
    }
    private struct Entry: Equatable {
        let image: RouterSystemInstallImage
        let bytes: Data
    }
    private func name(_ index: Int) -> String { "traffic-evidence-\(index).json" }
    private func entry(_ index: Int, in directory: RouterSystemDirectory) throws -> Entry? {
        let leaf = name(index)
        guard let image = try RouterSystemInstallEncoding.image(leaf, in: directory,
                maximum: RouterTrafficCodec.maximumBytes) else { return nil }
        guard let bytes = try directory.read(leaf, maximum: RouterTrafficCodec.maximumBytes),
              image.digest == RouterSystemObservation.hash(bytes), image.count == bytes.count,
              try RouterSystemInstallEncoding.image(leaf, in: directory,
                maximum: RouterTrafficCodec.maximumBytes) == image else { throw RouterTrafficEvidenceError.sourceChanged }
        return .init(image: image, bytes: bytes)
    }
    private func scan(_ directory: RouterSystemDirectory) throws -> [Entry?] {
        try (0..<Self.capacity).map { try entry($0, in: directory) }
    }
    private func decode(_ entry: Entry) throws -> RouterTrafficReceipt {
        let receipt = try RouterTrafficCodec.decode(entry.bytes, plan: source.intent.plan, profile: source.intent.profile)
        guard source.matches(receipt.before), source.matches(receipt.after) else { throw RouterTrafficEvidenceError.sourceChanged }
        return receipt
    }
    private func decodeAll(_ entries: [Entry?]) throws -> [RouterTrafficReceipt] {
        let records = try entries.compactMap { try $0.map(decode) }
        guard Set(records.map(\.session)).count == records.count else { throw RouterTrafficEvidenceError.invalidReceipt }
        return records
    }

    func read() throws -> [RouterTrafficReceipt] {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        return try source.withVerifiedDirectory { directory in
            let first = try scan(directory), records = try decodeAll(first)
            guard try scan(directory) == first else { throw RouterTrafficEvidenceError.sourceChanged }
            return records
        }
    }

    /// Only a nonroot storage fixture can call this successfully. No service/IPC
    /// route supplies these values and no journal acceptance pointer is changed.
    func recordFixture(_ receipt: RouterTrafficReceipt) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterSystemError.ownershipUnknown }
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try receipt.validate(plan: source.intent.plan, profile: source.intent.profile)
        guard source.matches(receipt.before), source.matches(receipt.after) else { throw RouterTrafficEvidenceError.sourceChanged }
        let bytes = try RouterTrafficCodec.encode(receipt)
        try source.withVerifiedDirectory { directory in
            guard directory.owner == getuid() else { throw RouterSystemError.ownershipUnknown }
            let before = try scan(directory)
            _ = try decodeAll(before)
            var slot: Int?
            for index in before.indices {
                if let entry = before[index], try decode(entry).session == receipt.session {
                    guard entry.bytes == bytes else { throw RouterSystemError.conflict }
                    slot = index
                }
            }
            let selected: Int
            if let slot { selected = slot }
            else {
                guard let empty = before.firstIndex(where: { $0 == nil }) else { throw RouterTrafficEvidenceError.limitExceeded }
                selected = empty
            }
            guard try scan(directory) == before else { throw RouterSystemError.conflict }
            var expected = before
            if before[selected] == nil {
                try directory.boundedEntryCount(maximum: 64)
                try directory.create(name(selected), data: bytes)
                guard let created = try entry(selected, in: directory), created.bytes == bytes else {
                    throw RouterSystemError.journalUnknown
                }
                expected[selected] = created
            }
            try directory.synchronizeFile(name(selected), expected: bytes, synchronize: synchronize)
            guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
            guard try scan(directory) == expected else { throw RouterSystemError.conflict }
        }
    }

    /// Selects a retained record, never a caller-supplied path or acceptance flag.
    /// Current network/cleanup/credentials have not been sampled by this method.
    func inspect(session: UUID) throws -> RouterTrafficHistoryInspection {
        guard let receipt = try read().first(where: { $0.session == session }) else {
            throw RouterTrafficEvidenceError.invalidReceipt
        }
        return .init(session: session, instance: receipt.before.instance, planDigest: receipt.before.planDigest,
                     configurationDigest: receipt.before.configurationDigest, interval: receipt.interval,
                     assessment: try receipt.assess(plan: source.intent.plan, profile: source.intent.profile))
    }
}

struct RouterTrafficHistoryInspection: Encodable {
    let session: UUID
    let instance: UUID
    let planDigest: String
    let configurationDigest: String
    let interval: RouterTrafficInterval
    let assessment: RouterTrafficAssessment
    let status = "historical_record_only"
    let currentNetworkChecked = false
    let currentCleanupChecked = false
    let currentCredentialsChecked = false
    let canExecuteRollback = false
    let canPromoteAccepted = false
}
