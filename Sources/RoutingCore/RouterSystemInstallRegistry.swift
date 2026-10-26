import Foundation
import Darwin

enum RouterSystemInstallAction: String, Codable { case install, upgrade, retire, reinstall }

struct RouterSystemInstallActive: Codable, Equatable {
    let version: Int
    let transaction: UUID
    let action: RouterSystemInstallAction
    let planDigest: String
    let packageID: UUID
    let helperDigest: String
    let installationID: UUID
    let ownerUID: UInt32
    let transactionDirectory: RouterSystemInstallNode

    func encoded() throws -> Data { try RouterSystemInstallRegistry.encode(self) }
    static func decode(_ data: Data) throws -> Self {
        _ = try RouterStrictJSON.object(data, maximumBytes: 8192)
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 1, value.ownerUID >= 501, value.ownerUID < UInt32.max,
              RouterSystemProvider.validDigest(value.planDigest), RouterSystemProvider.validDigest(value.helperDigest),
              try value.encoded() == data else { throw RouterSystemError.journalUnknown }
        return value
    }
}

/// The coordinator supplies this only after verifying actual final files/job/socket. The registry
/// records that proof's digest; it does not inspect or assert live service/network state itself.
struct RouterSystemInstallCompletion: Codable, Equatable {
    let version: Int
    let active: RouterSystemInstallActive
    let proofDigest: String
    func encoded() throws -> Data { try RouterSystemInstallRegistry.encode(self) }
    static func decode(_ data: Data) throws -> Self {
        _ = try RouterStrictJSON.object(data, maximumBytes: 16384)
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 1, RouterSystemProvider.validDigest(value.proofDigest),
              try RouterSystemInstallActive.decode(value.active.encoded()) == value.active,
              try value.encoded() == data else { throw RouterSystemError.journalUnknown }
        return value
    }
}

/// Complements installer.lock: releasing a process lock after a crash does not release ownership of
/// an unfinished transaction. All methods require the caller to hold that lock. No service effects.
final class RouterSystemInstallRegistry {
    enum Position: Equatable { case prepared, active, closed(RouterSystemInstallCompletion) }
    enum Boundary: CaseIterable { case staged, sealed, claimed, completed, closed }
    private struct Receipt: Codable, Equatable {
        let version: Int
        let active: RouterSystemInstallActive
        let registry: RouterSystemInstallNode
        let image: RouterSystemInstallImage
    }
    private let registry: RouterSystemDirectory
    private let transaction: RouterSystemDirectory
    private let synchronize: (Int32) -> Int32
    private let boundary: (Boundary) throws -> Void

    init(registry: RouterSystemDirectory, transaction: RouterSystemDirectory,
         synchronize: @escaping (Int32) -> Int32 = fsync, boundary: @escaping (Boundary) throws -> Void = { _ in }) {
        self.registry = registry; self.transaction = transaction
        self.synchronize = synchronize; self.boundary = boundary
    }
    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(value)
    }

    /// Seals private marker evidence without changing the shared active marker. Incomplete private
    /// files block this UUID; they are not re-created using whatever inode happens to be present.
    func prepare(_ active: RouterSystemInstallActive) throws {
        try verifyPlan(active)
        guard try image("active.json", in: registry) == nil,
              try transaction.read("active.receipt", maximum: 16384) == nil else { throw RouterSystemError.conflict }
        let node = try RouterSystemInstallNode.directory(registry)
        let expected = try createMarker(active.encoded())
        try boundary(.staged)
        guard try image("active.publish", in: transaction) == expected else { throw RouterSystemError.conflict }
        let receipt = Receipt(version: 1, active: active, registry: node, image: expected)
        try transaction.create("active.receipt", data: Self.encode(receipt))
        try sync(transaction)
        try boundary(.sealed)
        _ = try load(active)
    }

    /// Closed transactions can only return their historical completion; they never claim again.
    func claim(_ active: RouterSystemInstallActive) throws -> Position {
        let receipt = try load(active)
        switch try position(receipt) {
        case .closed(let completion):
            try sync(transaction); try sync(registry)
            return .closed(completion)
        case .active:
            try syncMarker("active.json", in: registry, expected: receipt.image)
        case .prepared:
            try move("active.publish", from: transaction, to: registry, name: "active.json")
            try boundary(.claimed)
            try syncMarker("active.json", in: registry, expected: receipt.image)
        }
        try sync(transaction); try sync(registry)
        guard try position(receipt) == .active else { throw RouterSystemError.conflict }
        return .active
    }

    func inspect(_ active: RouterSystemInstallActive) throws -> Position { try position(load(active)) }

    /// Recovery after terminal proof was saved but before the marker was closed must reuse the
    /// original proof. The coordinator revalidates actual final state without replaying bootout.
    func pendingCompletion(_ active: RouterSystemInstallActive) throws -> RouterSystemInstallCompletion? {
        let receipt = try load(active)
        let current = try position(receipt)
        if case .closed(let completion) = current { return completion }
        guard let bytes = try transaction.read("complete.json", maximum: 16384) else { return nil }
        let completion = try RouterSystemInstallCompletion.decode(bytes)
        guard current == .active, completion.active == active else { throw RouterSystemError.conflict }
        try transaction.synchronizeFile("complete.json", expected: bytes, synchronize: synchronize)
        try sync(transaction)
        return completion
    }

    /// Terminal proof is immutable. The active inode is archived only after the proof is durable.
    func finish(_ completion: RouterSystemInstallCompletion) throws {
        let bytes = try completion.encoded()
        guard try RouterSystemInstallCompletion.decode(bytes) == completion else { throw RouterSystemError.journalUnknown }
        let receipt = try load(completion.active)
        switch try position(receipt) {
        case .prepared: throw RouterSystemError.operationUnsettled
        case .closed(let prior):
            guard prior == completion else { throw RouterSystemError.conflict }
            try sync(transaction); try sync(registry)
            return
        case .active: break
        }
        if let prior = try transaction.read("complete.json", maximum: 16384) {
            guard prior == bytes else { throw RouterSystemError.conflict }
        } else { try transaction.create("complete.json", data: bytes) }
        try transaction.synchronizeFile("complete.json", expected: bytes, synchronize: synchronize)
        try sync(transaction)
        try boundary(.completed)
        guard try position(receipt) == .active else { throw RouterSystemError.conflict }
        try move("active.json", from: registry, to: transaction, name: "active.closed")
        try boundary(.closed)
        try syncMarker("active.closed", in: transaction, expected: receipt.image)
        try sync(registry); try sync(transaction)
        guard try position(receipt) == .closed(completion) else { throw RouterSystemError.conflict }
    }

    private func verifyPlan(_ active: RouterSystemInstallActive) throws {
        _ = try RouterSystemInstallActive.decode(active.encoded())
        guard registry.owner == transaction.owner,
              active.transactionDirectory == (try RouterSystemInstallNode.directory(transaction)),
              active.transactionDirectory != (try RouterSystemInstallNode.directory(registry)),
              let bytes = try transaction.read("plan.json", maximum: 1024 * 1024),
              RouterSystemObservation.hash(bytes) == active.planDigest else { throw RouterSystemError.conflict }
        try transaction.synchronizeFile("plan.json", expected: bytes, synchronize: synchronize)
    }
    private func load(_ active: RouterSystemInstallActive) throws -> Receipt {
        try verifyPlan(active)
        guard let bytes = try transaction.read("active.receipt", maximum: 16384) else { throw RouterSystemError.journalUnknown }
        _ = try RouterStrictJSON.object(bytes, maximumBytes: 16384)
        let value = try JSONDecoder().decode(Receipt.self, from: bytes)
        let marker = try active.encoded()
        guard value.version == 1, value.active == active,
              value.registry == (try RouterSystemInstallNode.directory(registry)),
              value.image.digest == RouterSystemObservation.hash(marker), value.image.count == marker.count,
              try Self.encode(value) == bytes else { throw RouterSystemError.conflict }
        try transaction.synchronizeFile("active.receipt", expected: bytes, synchronize: synchronize)
        try sync(transaction)
        return value
    }
    private func position(_ receipt: Receipt) throws -> Position {
        let staged = try image("active.publish", in: transaction)
        let closed = try image("active.closed", in: transaction)
        if closed == receipt.image, staged == nil {
            // A newer transaction may already own active.json. Never open or modify that marker.
            guard let bytes = try transaction.read("complete.json", maximum: 16384) else { throw RouterSystemError.journalUnknown }
            let completion = try RouterSystemInstallCompletion.decode(bytes)
            guard completion.active == receipt.active else { throw RouterSystemError.conflict }
            try transaction.synchronizeFile("complete.json", expected: bytes, synchronize: synchronize)
            try syncMarker("active.closed", in: transaction, expected: receipt.image)
            return .closed(completion)
        }
        let current = try image("active.json", in: registry)
        if staged == receipt.image, current == nil, closed == nil { return .prepared }
        if staged == nil, current == receipt.image, closed == nil { return .active }
        throw RouterSystemError.conflict
    }
    private func image(_ name: String, in parent: RouterSystemDirectory) throws -> RouterSystemInstallImage? {
        try parent.validate()
        var before = stat(), after = stat()
        if fstatat(parent.fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return nil
        }
        guard let bytes = try parent.read(name, maximum: 8192),
              fstatat(parent.fd, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(before, after) else { throw RouterSystemError.conflict }
        try parent.validate()
        return .init(node: .init(after), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
    }
    private func createMarker(_ bytes: Data) throws -> RouterSystemInstallImage {
        try transaction.validate()
        let fd = openat(transaction.fd, "active.publish", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RouterSystemError.journalUnknown }; defer { close(fd) }
        _ = try transaction.regular(fd, mode: 0o600)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterSystemError.journalUnknown }; offset += count
        }
        let held = try transaction.regular(fd, mode: 0o600)
        let expected = RouterSystemInstallImage(node: .init(held), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
        guard synchronize(fd) == 0, try image("active.publish", in: transaction) == expected else { throw RouterSystemError.journalUnknown }
        try sync(transaction)
        return expected
    }
    private func syncMarker(_ name: String, in parent: RouterSystemDirectory, expected: RouterSystemInstallImage) throws {
        guard try image(name, in: parent) == expected,
              let bytes = try parent.read(name, maximum: 8192) else { throw RouterSystemError.conflict }
        try parent.synchronizeFile(name, expected: bytes, synchronize: synchronize)
        guard try image(name, in: parent) == expected else { throw RouterSystemError.conflict }
    }
    private func sync(_ parent: RouterSystemDirectory) throws {
        try parent.validate()
        guard synchronize(parent.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try parent.validate()
    }
    private func move(_ name: String, from source: RouterSystemDirectory, to target: RouterSystemDirectory, name destination: String) throws {
        try source.validate(); try target.validate()
        guard renameatx_np(source.fd, name, target.fd, destination, UInt32(RENAME_EXCL)) == 0 else { throw RouterSystemError.conflict }
    }
}
