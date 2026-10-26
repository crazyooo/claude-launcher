import Foundation
import Darwin

/// Retiring removes five owned installation files, never the state tree. This ledger is the proof
/// needed to reuse that tree on reinstall. Callers retain installer and operation leases for writes.
final class RouterSystemInstallRetirement {
    enum Boundary: CaseIterable { case recordSaved, markerStaged, markerSealed, published, publicationSynced, consumed, consumptionSynced }
    struct Observation {
        let pointer: RouterSystemRetiredPointer
        let marker: RouterSystemInstallImage
        let preserved: RouterSystemInstallPreserved
        let residualSocket: RouterSystemInstallNode?
    }
    private struct Record: Codable, Equatable {
        let version: Int
        let planDigest: String
        let preserved: RouterSystemInstallPreserved
        let files: [RouterSystemInstallFileReceipt]
    }
    private struct Marker: Codable, Equatable {
        let version: Int
        let pointer: RouterSystemRetiredPointer
        let registry: RouterSystemInstallNode
        let image: RouterSystemInstallImage
    }
    // Read-only view of Registry's immutable receipt. Do not use inspect() during preview: it fsyncs.
    private struct ClosedMarker: Codable {
        let version: Int
        let active: RouterSystemInstallActive
        let registry: RouterSystemInstallNode
        let image: RouterSystemInstallImage
    }
    private let registry: RouterSystemDirectory
    private let transaction: RouterSystemDirectory
    private let launchDaemons: RouterSystemDirectory
    private let synchronize: (Int32) -> Int32
    private let boundary: (Boundary) throws -> Void
    init(registry: RouterSystemDirectory, transaction: RouterSystemDirectory, launchDaemons: RouterSystemDirectory,
         synchronize: @escaping (Int32) -> Int32 = fsync, boundary: @escaping (Boundary) throws -> Void = { _ in }) {
        self.registry = registry; self.transaction = transaction; self.launchDaemons = launchDaemons
        self.synchronize = synchronize; self.boundary = boundary
    }
    static func transactionLeaf(_ id: UUID) -> String { "transaction-" + id.uuidString.lowercased() }

    func prepare(plan: RouterSystemInstallPlan) throws {
        try bound(plan)
        guard try registry.read("active.json", maximum: 8192) == nil,
              try image("retired.json", registry) == nil,
              try transaction.read("active.receipt", maximum: 16384) == nil else { throw RouterSystemError.conflict }
        let record = try record(plan), bytes = try RouterSystemInstallEncoding.encode(record)
        // All three private records are prepared before active ownership. Partial records are retained.
        try transaction.create("retirement.json", data: bytes)
        try syncFile("retirement.json", transaction); try sync(transaction)
        try boundary(.recordSaved)
        let pointer = RouterSystemRetiredPointer(version: 1, transaction: plan.candidate.transaction,
            transactionDirectory: try .directory(transaction), recordDigest: RouterSystemObservation.hash(bytes))
        let created = try createMarker(RouterSystemInstallEncoding.encode(pointer))
        try boundary(.markerStaged)
        guard try image("retired.publish", transaction) == created else { throw RouterSystemError.conflict }
        let receipt = Marker(version: 1, pointer: pointer, registry: try .directory(registry), image: created)
        try transaction.create("retired.marker.receipt", data: RouterSystemInstallEncoding.encode(receipt))
        try syncFile("retired.marker.receipt", transaction); try sync(transaction)
        try boundary(.markerSealed)
        guard try marker(plan, directory: transaction) == receipt else { throw RouterSystemError.conflict }
    }

    func publish(plan: RouterSystemInstallPlan, tree: RouterSystemInstallTree) throws -> String {
        try bound(plan); try active(plan)
        let receipt = try marker(plan, directory: transaction), record = try record(plan)
        try published(plan, expected: true)
        try tree.verify(record.preserved, exactJournal: true)
        try archives(plan, directory: transaction)
        for file in plan.files {
            guard try RouterSystemInstallEncoding.image(file.file.leaf, in: tree.target(file.file, launchDaemons: launchDaemons),
                maximum: file.file.maximum, mode: file.file.mode) == nil else { throw RouterSystemError.conflict }
        }
        guard try image("retired.closed", transaction) == nil else { throw RouterSystemError.conflict }
        try transfer("retired.publish", from: transaction, to: registry, as: "retired.json", expected: receipt.image,
                     moved: .published, synced: .publicationSynced)
        return receipt.pointer.recordDigest
    }

    /// Preview only reads. It verifies the original closed transaction, not merely pointer contents.
    func observe() throws -> Observation? {
        guard let current = try image("retired.json", registry) else { return nil }
        let pointer: RouterSystemRetiredPointer = try read("retired.json", registry)
        let history = try closed(pointer)
        guard history.marker.image == current, try image("retired.json", registry) == current else { throw RouterSystemError.conflict }
        return .init(pointer: pointer, marker: current, preserved: history.record.preserved, residualSocket: history.residual)
    }

    func validateReinstall(plan: RouterSystemInstallPlan, tree: RouterSystemInstallTree, published isPublished: Bool) throws {
        try bound(plan); try published(plan, expected: isPublished)
        let candidate = plan.candidate
        guard candidate.action == .reinstall, let pointer = candidate.retired, let expected = candidate.retiredMarker else {
            throw RouterSystemError.invalidRequest
        }
        let claimed: Bool
        if try transaction.read("active.receipt", maximum: 16384) == nil {
            claimed = false
            guard !isPublished, try registry.read("active.json", maximum: 8192) == nil else { throw RouterSystemError.conflict }
        } else {
            let position = try RouterSystemInstallRegistry(registry: registry, transaction: transaction).inspect(plan.active(in: transaction))
            guard position == .active || (!isPublished && position == .prepared) else { throw RouterSystemError.conflict }
            claimed = position == .active
        }
        let history = try closed(pointer)
        guard expected == history.marker.image, candidate.preserved == history.record.preserved,
              candidate.installation == history.record.preserved.installation,
              candidate.priorSocket == nil || candidate.priorSocket == history.residual else { throw RouterSystemError.conflict }
        try tree.verify(history.record.preserved, exactJournal: !isPublished)
        let current = try image("retired.json", registry), consumed = try image("retired.closed", transaction)
        guard (current == expected && consumed == nil) || (isPublished && current == nil && consumed == expected) else {
            throw RouterSystemError.conflict
        }
        let files = RouterSystemInstallTransaction(directory: transaction, id: candidate.transaction)
        for entry in plan.files {
            let target = tree.target(entry.file, launchDaemons: launchDaemons)
            guard entry.before == nil, let after = entry.after, try files.load(entry.file, target: target) == entry,
                  try RouterSystemInstallEncoding.image(entry.file.receiptLeaf("retired"), in: transaction,
                    maximum: entry.file.maximum, mode: entry.file.mode) == nil else { throw RouterSystemError.conflict }
            let now = try RouterSystemInstallEncoding.image(entry.file.leaf, in: target, maximum: entry.file.maximum, mode: entry.file.mode)
            let staged = try RouterSystemInstallEncoding.image(entry.file.receiptLeaf("publish"), in: transaction,
                maximum: entry.file.maximum, mode: entry.file.mode)
            guard (claimed && now == after && staged == nil) || (!isPublished && now == nil && staged == after) else { throw RouterSystemError.conflict }
        }
        // Synchronization is confined to apply/preparation; observe() above performs none.
        for leaf in ["plan.json", "retirement.json", "retired.marker.receipt", "active.receipt", "active.closed", "complete.json", "final-proof.json"] {
            try syncFile(leaf, history.directory)
        }
        try sync(history.directory)
    }

    func consume(plan: RouterSystemInstallPlan, tree: RouterSystemInstallTree) throws {
        try active(plan)
        try validateReinstall(plan: plan, tree: tree, published: true)
        guard let expected = plan.candidate.retiredMarker else { throw RouterSystemError.conflict }
        try transfer("retired.json", from: registry, to: transaction, as: "retired.closed", expected: expected,
                     moved: .consumed, synced: .consumptionSynced)
    }

    private func bound(_ plan: RouterSystemInstallPlan) throws {
        try plan.validate()
        let node = try RouterSystemInstallNode.directory(transaction)
        guard registry.owner == transaction.owner, registry.owner == launchDaemons.owner,
              plan.files.allSatisfy({ $0.transactionDirectory == node }),
              try .directory(launchDaemons) == plan.candidate.launchDaemonsParent,
              try RouterSystemInstallPlan.decode(required("plan.json", transaction)) == plan else { throw RouterSystemError.conflict }
    }
    private func active(_ plan: RouterSystemInstallPlan) throws {
        guard try RouterSystemInstallRegistry(registry: registry, transaction: transaction).inspect(plan.active(in: transaction)) == .active else {
            throw RouterSystemError.conflict
        }
    }
    private func published(_ plan: RouterSystemInstallPlan, expected: Bool) throws {
        let bytes = try transaction.read("files-published.json", maximum: 16384)
        if expected {
            guard let bytes, bytes == (try RouterSystemInstallEncoding.encode(RouterSystemInstallPublished(version: 1, planDigest: plan.digest))) else {
                throw RouterSystemError.conflict
            }
        } else { guard bytes == nil else { throw RouterSystemError.conflict } }
    }
    private func record(_ plan: RouterSystemInstallPlan) throws -> Record {
        guard plan.candidate.action == .retire, let preserved = plan.candidate.preserved else { throw RouterSystemError.invalidRequest }
        return .init(version: 1, planDigest: try plan.digest, preserved: preserved, files: plan.files)
    }
    private func marker(_ plan: RouterSystemInstallPlan, directory: RouterSystemDirectory) throws -> Marker {
        let recordBytes = try RouterSystemInstallEncoding.encode(record(plan))
        guard try required("retirement.json", directory) == recordBytes else { throw RouterSystemError.conflict }
        let receipt: Marker = try read("retired.marker.receipt", directory)
        let pointer = RouterSystemRetiredPointer(version: 1, transaction: plan.candidate.transaction,
            transactionDirectory: try .directory(directory), recordDigest: RouterSystemObservation.hash(recordBytes))
        let bytes = try RouterSystemInstallEncoding.encode(pointer)
        guard receipt.version == 1, receipt.pointer == pointer, try receipt.registry == .directory(registry),
              receipt.image.digest == RouterSystemObservation.hash(bytes), receipt.image.count == bytes.count else { throw RouterSystemError.conflict }
        return receipt
    }
    private func closed(_ pointer: RouterSystemRetiredPointer) throws -> (directory: RouterSystemDirectory, record: Record, marker: Marker, residual: RouterSystemInstallNode?) {
        try pointer.validate()
        let old = try registry.child(Self.transactionLeaf(pointer.transaction))
        guard try .directory(old) == pointer.transactionDirectory else { throw RouterSystemError.conflict }
        let plan = try RouterSystemInstallPlan.decode(required("plan.json", old)), expected = try record(plan)
        let receipt = try marker(plan, directory: old)
        guard plan.candidate.transaction == pointer.transaction, receipt.pointer == pointer,
              try image("retired.publish", old) == nil else { throw RouterSystemError.conflict }
        let active = try plan.active(in: old), closed: ClosedMarker = try read("active.receipt", old)
        let bytes = try active.encoded()
        guard closed.version == 1, closed.active == active, try closed.registry == .directory(registry),
              closed.image.digest == RouterSystemObservation.hash(bytes), closed.image.count == bytes.count,
              try image("active.closed", old) == closed.image, try image("active.publish", old) == nil else { throw RouterSystemError.conflict }
        let completion = try RouterSystemInstallCompletion.decode(required("complete.json", old))
        let proofBytes = try required("final-proof.json", old)
        let proof = try RouterSystemInstallEncoding.decode(RouterSystemInstallFinalProof.self, proofBytes)
        guard completion.active == active, completion.proofDigest == RouterSystemObservation.hash(proofBytes),
              proof.version == 1, proof.planDigest == expected.planDigest,
              proof.service.installation == expected.preserved.installation, !proof.service.registered,
              proof.service.socketNode == nil,
              (proof.service.residualSocketNode == nil || proof.service.residualSocketNode == plan.candidate.priorSocket),
              proof.retiredDigest == pointer.recordDigest else { throw RouterSystemError.conflict }
        try archives(plan, directory: old)
        return (old, expected, receipt, proof.service.residualSocketNode)
    }
    private func archives(_ plan: RouterSystemInstallPlan, directory: RouterSystemDirectory) throws {
        for entry in plan.files {
            let file = entry.file
            guard entry.before != nil, entry.after == nil, try entry.transactionDirectory == .directory(directory),
                  try RouterSystemInstallFileReceipt.decode(required(file.receiptLeaf("receipt"), directory)) == entry,
                  let backup = try directory.read(file.receiptLeaf("before"), maximum: file.maximum),
                  RouterSystemObservation.hash(backup) == entry.before?.digest, backup.count == entry.before?.count,
                  try directory.read(file.receiptLeaf("after"), maximum: file.maximum) == nil,
                  try RouterSystemInstallEncoding.image(file.receiptLeaf("retired"), in: directory, maximum: file.maximum, mode: file.mode) == entry.before,
                  try RouterSystemInstallEncoding.image(file.receiptLeaf("publish"), in: directory, maximum: file.maximum, mode: file.mode) == nil else {
                throw RouterSystemError.conflict
            }
        }
    }
    private func required(_ leaf: String, _ directory: RouterSystemDirectory) throws -> Data {
        guard let bytes = try directory.read(leaf, maximum: 1024 * 1024) else { throw RouterSystemError.journalUnknown }
        return bytes
    }
    private func read<T: Codable>(_ leaf: String, _ directory: RouterSystemDirectory) throws -> T {
        try RouterSystemInstallEncoding.decode(T.self, required(leaf, directory))
    }
    private func image(_ leaf: String, _ directory: RouterSystemDirectory) throws -> RouterSystemInstallImage? {
        try RouterSystemInstallEncoding.image(leaf, in: directory, maximum: 8192)
    }
    private func sync(_ directory: RouterSystemDirectory) throws {
        try directory.validate()
        guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
    }
    private func syncFile(_ leaf: String, _ directory: RouterSystemDirectory) throws {
        try directory.synchronizeFile(leaf, expected: required(leaf, directory), synchronize: synchronize)
    }
    private func transfer(_ leaf: String, from source: RouterSystemDirectory, to target: RouterSystemDirectory,
                          as name: String, expected: RouterSystemInstallImage, moved: Boundary, synced: Boundary) throws {
        let from = try image(leaf, source), to = try image(name, target)
        if from == expected && to == nil {
            guard renameatx_np(source.fd, leaf, target.fd, name, UInt32(RENAME_EXCL)) == 0 else { throw RouterSystemError.conflict }
            try boundary(moved)
        } else { guard from == nil && to == expected else { throw RouterSystemError.conflict } }
        guard try image(name, target) == expected else { throw RouterSystemError.conflict }
        try syncFile(name, target); try sync(source); try sync(target)
        try boundary(synced)
        guard try image(leaf, source) == nil, try image(name, target) == expected else { throw RouterSystemError.conflict }
    }
    private func createMarker(_ bytes: Data) throws -> RouterSystemInstallImage {
        try transaction.validate()
        let fd = openat(transaction.fd, "retired.publish", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RouterSystemError.journalUnknown }; defer { close(fd) }
        _ = try transaction.regular(fd, mode: 0o600)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterSystemError.journalUnknown }; offset += count
        }
        let expected = RouterSystemInstallImage(node: .init(try transaction.regular(fd, mode: 0o600)),
            digest: RouterSystemObservation.hash(bytes), count: bytes.count)
        guard synchronize(fd) == 0, try image("retired.publish", transaction) == expected else { throw RouterSystemError.journalUnknown }
        try sync(transaction)
        return expected
    }
}
