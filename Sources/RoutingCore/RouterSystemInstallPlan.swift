import Foundation
import Darwin

enum RouterSystemInstallEncoding {
    static func encode<T: Encodable>(_ value: T) throws -> Data { try RouterSystemInstallRegistry.encode(value) }
    static func decode<T: Codable>(_ type: T.Type, _ bytes: Data, maximum: Int = 1024 * 1024) throws -> T {
        _ = try RouterStrictJSON.object(bytes, maximumBytes: maximum)
        let result = try JSONDecoder().decode(type, from: bytes)
        guard try encode(result) == bytes else { throw RouterSystemError.journalUnknown }
        return result
    }
    static func save(_ bytes: Data, as leaf: String, in directory: RouterSystemDirectory) throws {
        if let existing = try directory.read(leaf, maximum: 1024 * 1024) {
            guard existing == bytes else { throw RouterSystemError.conflict }
        } else { try directory.create(leaf, data: bytes) }
        try directory.synchronizeFile(leaf, expected: bytes)
        guard fsync(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
    }
    static func image(_ leaf: String, in directory: RouterSystemDirectory, maximum: Int,
                      mode: mode_t = 0o600) throws -> RouterSystemInstallImage? {
        try directory.validate(); try RouterSystemDirectory.leaf(leaf)
        let fd = openat(directory.fd, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return nil }
        defer { close(fd) }
        let before = try directory.regular(fd, mode: mode)
        guard let bytes = try directory.read(leaf, maximum: maximum, mode: mode) else { throw RouterSystemError.conflict }
        let after = try directory.regular(fd, mode: mode)
        var linked = stat()
        guard RouterSystemDirectory.unchanged(before, after),
              fstatat(directory.fd, leaf, &linked, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(after, linked), bytes.count == after.st_size else { throw RouterSystemError.conflict }
        try directory.validate()
        return .init(node: .init(after), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
    }
}

struct RouterSystemInstallJob: Codable, Equatable {
    let registered: Bool
    let work: RouterSystemWork?
    static let absent = Self(registered: false, work: nil)
    func validate() throws {
        guard registered || work == nil else { throw RouterSystemError.ownershipUnknown }
        if let work {
            guard work.pid > 1, work.birthSeconds > 0, work.birthMicroseconds < 1_000_000 else {
                throw RouterSystemError.ownershipUnknown
            }
        }
    }
}
struct RouterSystemInstallParents: Codable, Equatable {
    let root: RouterSystemInstallNode
    let bin: RouterSystemInstallNode
    let core: RouterSystemInstallNode
    let run: RouterSystemInstallNode
    let state: RouterSystemInstallNode
}
struct RouterSystemInstallPreserved: Codable, Equatable {
    let installation: RouterSystemInstallationIdentity
    let parents: RouterSystemInstallParents
    let operationLock: RouterSystemInstallImage
    let journal: RouterSystemInstallImage
    func validate() throws {
        guard installation.isValid, operationLock.count == 0,
              operationLock.digest == RouterSystemObservation.hash(Data()), journal.count > 0,
              journal.count <= RouterSystemJournalDecoder.maximumBytes,
              RouterSystemProvider.validDigest(journal.digest) else { throw RouterSystemError.journalUnknown }
    }
}
struct RouterSystemRetiredPointer: Codable, Equatable {
    let version: Int
    let transaction: UUID
    let transactionDirectory: RouterSystemInstallNode
    let recordDigest: String
    func validate() throws {
        guard version == 1, RouterSystemProvider.validDigest(recordDigest) else { throw RouterSystemError.journalUnknown }
    }
}
struct RouterSystemInstallCandidateFile: Codable, Equatable {
    let file: RouterSystemInstallFile
    let before: RouterSystemInstallImage?
    let afterDigest: String?
    let afterCount: Int?
}

/// The user confirms this read-only semantic observation, before staged inodes exist.
struct RouterSystemInstallCandidate: Codable, Equatable {
    let version: Int
    let transaction: UUID
    let packageID: UUID
    let action: RouterSystemInstallAction
    let installation: RouterSystemInstallationIdentity
    let helperDigest: String
    let destinationParent: RouterSystemInstallNode
    let launchDaemonsParent: RouterSystemInstallNode
    let files: [RouterSystemInstallCandidateFile]
    let preserved: RouterSystemInstallPreserved?
    let originalJob: RouterSystemInstallJob
    // Omitted for historical plans, preserving their original encoded bytes and digest.
    var priorSocket: RouterSystemInstallNode? = nil
    let retired: RouterSystemRetiredPointer?
    let retiredMarker: RouterSystemInstallImage?
    var digest: String { get throws { RouterSystemObservation.hash(try RouterSystemInstallEncoding.encode(self)) } }

    func initialJournalBytes() throws -> Data {
        try validate()
        guard action == .install else { throw RouterSystemError.invalidRequest }
        let value = RouterSystemJournal(version: 1, installation: installation, revision: transaction,
            phase: .idle, reason: "no_system_instance")
        return try RouterSystemInstallEncoding.encode(value)
    }
    func validate() throws {
        guard version == 1, installation.isValid, RouterSystemProvider.validDigest(helperDigest),
              files.map(\.file) == RouterSystemInstallFile.allCases,
              (retired == nil) == (retiredMarker == nil) else { throw RouterSystemError.journalUnknown }
        try originalJob.validate(); try preserved?.validate(); try retired?.validate()
        if let retired, let retiredMarker {
            let bytes = try RouterSystemInstallEncoding.encode(retired)
            guard retired.transaction != transaction, retiredMarker.digest == RouterSystemObservation.hash(bytes),
                  retiredMarker.count == bytes.count else { throw RouterSystemError.conflict }
        }
        for file in files {
            if let old = file.before {
                guard RouterSystemProvider.validDigest(old.digest), old.count >= 0, old.count <= file.file.maximum else { throw RouterSystemError.journalUnknown }
            }
            guard (file.afterDigest == nil) == (file.afterCount == nil) else { throw RouterSystemError.journalUnknown }
            if let digest = file.afterDigest, let count = file.afterCount {
                guard RouterSystemProvider.validDigest(digest), count >= 0, count <= file.file.maximum else { throw RouterSystemError.journalUnknown }
            }
        }
        switch action {
        case .install:
            guard installation.id == transaction, preserved == nil, retired == nil, originalJob == .absent, priorSocket == nil,
                  files.allSatisfy({ $0.before == nil && $0.afterDigest != nil }) else { throw RouterSystemError.conflict }
        case .upgrade, .retire:
            guard preserved?.installation == installation, retired == nil,
                  files.allSatisfy({ $0.before != nil && ($0.afterDigest == nil) == (action == .retire) }) else { throw RouterSystemError.conflict }
        case .reinstall:
            guard preserved?.installation == installation, retired != nil, originalJob == .absent,
                  files.allSatisfy({ $0.before == nil && $0.afterDigest != nil }) else { throw RouterSystemError.conflict }
        }
        if action != .retire {
            guard files.first(where: { $0.file == .helper })?.afterDigest == helperDigest,
                  files.first(where: { $0.file == .core })?.afterDigest == RouterCoreRelease.executableSHA256 else { throw RouterSystemError.conflict }
        }
    }
}

/// Internal receipts bind the confirmed candidate to actual staged files. This is never the preview.
struct RouterSystemInstallPlan: Codable, Equatable {
    let version: Int
    let candidate: RouterSystemInstallCandidate
    let files: [RouterSystemInstallFileReceipt]
    let rootReceipt: RouterSystemInstallRoot.Receipt?
    var digest: String { get throws { RouterSystemObservation.hash(try RouterSystemInstallEncoding.encode(self)) } }
    static func decode(_ bytes: Data) throws -> Self {
        let value = try RouterSystemInstallEncoding.decode(Self.self, bytes)
        try value.validate(); return value
    }
    func validate() throws {
        try candidate.validate()
        guard version == 1, files.map(\.file) == RouterSystemInstallFile.allCases,
              (rootReceipt != nil) == (candidate.action == .install),
              let transactionNode = files.first?.transactionDirectory,
              files.allSatisfy({ $0.transactionDirectory == transactionNode }) else { throw RouterSystemError.journalUnknown }
        let parents: RouterSystemInstallParents
        if let rootReceipt {
            let tree = rootReceipt.tree
            guard rootReceipt.transactionDirectory == transactionNode,
                  tree.files.map(\.kind) == RouterSystemInstallRoot.File.allCases else { throw RouterSystemError.conflict }
            let journal = try candidate.initialJournalBytes()
            guard let original = tree.files.first(where: { $0.kind == .journal })?.image,
                  original.digest == RouterSystemObservation.hash(journal), original.count == journal.count else {
                throw RouterSystemError.conflict
            }
            parents = .init(root: tree.root, bin: tree.bin, core: tree.core, run: tree.run, state: tree.state)
            for entry in tree.files {
                if let kind = entry.kind.installFile {
                    guard files.first(where: { $0.file == kind })?.after == entry.image else { throw RouterSystemError.conflict }
                }
            }
        } else {
            guard let preserved = candidate.preserved else { throw RouterSystemError.conflict }
            parents = preserved.parents
        }
        for (file, expected) in zip(files, candidate.files) {
            _ = try RouterSystemInstallFileReceipt.decode(file.encoded())
            guard file.transaction == candidate.transaction, file.file == expected.file, file.before == expected.before,
                  file.after?.digest == expected.afterDigest, file.after?.count == expected.afterCount else { throw RouterSystemError.conflict }
            let parent: RouterSystemInstallNode
            switch file.file { case .helper: parent = parents.bin; case .core: parent = parents.core
            case .manifest, .packageReceipt: parent = parents.root; case .launchd: parent = candidate.launchDaemonsParent }
            guard file.targetDirectory == parent else { throw RouterSystemError.conflict }
        }
        if let rootReceipt {
            guard rootReceipt.version == 1, rootReceipt.transaction == candidate.transaction,
                  rootReceipt.destinationParent == candidate.destinationParent else { throw RouterSystemError.conflict }
        }
    }
    func active(in transaction: RouterSystemDirectory) throws -> RouterSystemInstallActive {
        .init(version: 1, transaction: candidate.transaction, action: candidate.action, planDigest: try digest,
              packageID: candidate.packageID, helperDigest: candidate.helperDigest, installationID: candidate.installation.id,
              ownerUID: candidate.installation.ownerUID, transactionDirectory: try .directory(transaction))
    }
}

struct RouterSystemInstallTree {
    let root: RouterSystemDirectory
    let bin: RouterSystemDirectory
    let core: RouterSystemDirectory
    let run: RouterSystemDirectory
    let state: RouterSystemDirectory
    init(parent: RouterSystemDirectory) throws {
        root = try parent.installChild(.installedRoot)
        bin = try root.installChild(.bin); core = try root.installChild(.core)
        run = try root.installChild(.run); state = try root.installChild(.state)
    }
    func parents() throws -> RouterSystemInstallParents {
        .init(root: try .directory(root), bin: try .directory(bin), core: try .directory(core), run: try .directory(run), state: try .directory(state))
    }
    func target(_ file: RouterSystemInstallFile, launchDaemons: RouterSystemDirectory) -> RouterSystemDirectory {
        switch file { case .helper: return bin; case .core: return core
        case .manifest, .packageReceipt: return root; case .launchd: return launchDaemons }
    }
    func operationImage() throws -> RouterSystemInstallImage {
        guard let image = try RouterSystemInstallEncoding.image("operation.lock", in: state, maximum: 1),
              image.count == 0 else { throw RouterSystemError.conflict }
        return image
    }
    func journalImage() throws -> RouterSystemInstallImage {
        guard let image = try RouterSystemInstallEncoding.image("journal.json", in: state, maximum: RouterSystemJournalDecoder.maximumBytes) else { throw RouterSystemError.journalUnknown }
        return image
    }
    func journal(_ identity: RouterSystemInstallationIdentity) throws -> RouterSystemJournal {
        guard let bytes = try state.read("journal.json", maximum: RouterSystemJournalDecoder.maximumBytes) else { throw RouterSystemError.journalUnknown }
        let value = try RouterSystemJournalDecoder.decode(bytes)
        guard value.installation == identity else { throw RouterSystemError.conflict }; return value
    }
    func verify(_ preserved: RouterSystemInstallPreserved, exactJournal: Bool) throws {
        try preserved.validate()
        guard try parents() == preserved.parents, try operationImage() == preserved.operationLock else { throw RouterSystemError.conflict }
        let value = try journal(preserved.installation)
        if exactJournal {
            guard try journalImage() == preserved.journal, [.idle, .stopped].contains(value.phase) else { throw RouterSystemError.operationUnsettled }
        }
    }
}

struct RouterSystemInstallServiceProof: Codable, Equatable {
    let installation: RouterSystemInstallationIdentity
    let registered: Bool
    let socketNode: RouterSystemInstallNode?
    // Retained filesystem node, explicitly not a registered or healthy listener.
    var residualSocketNode: RouterSystemInstallNode? = nil
}
protocol RouterSystemInstallService {
    func job() throws -> RouterSystemInstallJob
    func registrationObserved() throws -> Bool
    func observedSocket() throws -> RouterSystemInstallNode?
    func authorizeResidualReplacement(_ node: RouterSystemInstallNode?) throws
    func quiesce(original: RouterSystemInstallJob) throws
    func register() throws
    func proof(identity: RouterSystemInstallationIdentity, retired: Bool) throws -> RouterSystemInstallServiceProof
}

// Test services without a filesystem listener cannot authorize residual replacement.
extension RouterSystemInstallService {
    func registrationObserved() throws -> Bool { try job().registered }
    func observedSocket() throws -> RouterSystemInstallNode? { nil }
    func authorizeResidualReplacement(_ node: RouterSystemInstallNode?) throws {
        guard node == nil else { throw RouterSystemError.conflict }
    }
}
