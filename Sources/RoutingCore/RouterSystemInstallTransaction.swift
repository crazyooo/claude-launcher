import Foundation
import Darwin

/// Only these five files may be published by the system installer. Paths never come from IPC.
enum RouterSystemInstallFile: String, Codable, CaseIterable {
    case helper, core, manifest, packageReceipt, launchd

    var leaf: String {
        switch self {
        case .helper: return "router-system-helper"
        case .core: return "mihomo"
        case .manifest: return "install-manifest.json"
        case .packageReceipt: return "package-receipt.json"
        case .launchd: return RouterSystemLayout.label + ".plist"
        }
    }
    var mode: mode_t {
        switch self {
        case .helper, .core: return 0o700
        case .launchd: return 0o644
        case .manifest, .packageReceipt: return 0o600
        }
    }
    var maximum: Int { self == .helper || self == .core ? 128 * 1024 * 1024 : 65536 }
    func receiptLeaf(_ suffix: String) -> String { rawValue + "." + suffix }
}

/// Rename changes ctime. Birth time, device and inode remain stable across our archive/publish moves.
struct RouterSystemInstallNode: Codable, Equatable {
    let device: Int32
    let inode: UInt64
    let birthSeconds: Int64
    let birthNanoseconds: Int64

    init(_ info: stat) {
        device = info.st_dev; inode = info.st_ino
        birthSeconds = Int64(info.st_birthtimespec.tv_sec)
        birthNanoseconds = Int64(info.st_birthtimespec.tv_nsec)
    }
    static func directory(_ directory: RouterSystemDirectory) throws -> Self {
        try directory.validate()
        var info = stat()
        guard fstat(directory.fd, &info) == 0 else { throw RouterSystemError.ownershipUnknown }
        return .init(info)
    }
}

struct RouterSystemInstallImage: Codable, Equatable {
    let node: RouterSystemInstallNode
    let digest: String
    let count: Int
}

/// Immutable evidence must exist durably before either rename. Same bytes on a new inode conflict.
struct RouterSystemInstallFileReceipt: Codable, Equatable {
    let version: Int
    let transaction: UUID
    let file: RouterSystemInstallFile
    let transactionDirectory: RouterSystemInstallNode
    let targetDirectory: RouterSystemInstallNode
    let before: RouterSystemInstallImage?
    let after: RouterSystemInstallImage?

    func encoded() throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        return try encoder.encode(self)
    }
    static func decode(_ bytes: Data) throws -> Self {
        _ = try RouterStrictJSON.object(bytes, maximumBytes: 8192)
        let value = try JSONDecoder().decode(Self.self, from: bytes)
        guard value.version == 1, value.before != nil || value.after != nil,
              try value.encoded() == bytes else { throw RouterSystemError.journalUnknown }
        for image in [value.before, value.after].compactMap({ $0 }) {
            guard RouterSystemProvider.validDigest(image.digest), image.count >= 0,
                  image.count <= value.file.maximum else { throw RouterSystemError.journalUnknown }
        }
        return value
    }
}

/// Fixed-file transaction kernel. The coordinator holds installer and operation leases for its entire
/// lifetime. No rollback-by-overwrite: old inodes are archived, new inodes use RENAME_EXCL, and partial
/// evidence is preserved. This type performs no service or network operation.
final class RouterSystemInstallTransaction {
    enum Boundary: CaseIterable {
        case beforeCopySaved, afterCopySaved, stagedFileSaved, receiptSaved
        case beforeArchive, archived, archiveSynced, beforePublish, published, publicationSynced
    }
    private let directory: RouterSystemDirectory
    private let id: UUID
    private let synchronize: (Int32) -> Int32
    private let boundary: (Boundary) throws -> Void

    init(directory: RouterSystemDirectory, id: UUID, synchronize: @escaping (Int32) -> Int32 = fsync,
         boundary: @escaping (Boundary) throws -> Void = { _ in }) {
        self.directory = directory; self.id = id; self.synchronize = synchronize; self.boundary = boundary
    }

    /// Called once before the overall install plan is sealed. If interrupted before receipt creation,
    /// staging again fails O_EXCL; partial evidence cannot be silently adopted or discarded.
    func stage(_ file: RouterSystemInstallFile, new: Data?, target: RouterSystemDirectory) throws -> RouterSystemInstallFileReceipt {
        guard directory.owner == target.owner, new.map({ $0.count <= file.maximum }) ?? true,
              try directory.read(file.receiptLeaf("receipt"), maximum: 8192) == nil else {
            throw RouterSystemError.conflict
        }
        let old = try snapshot(file.leaf, in: target, file: file)
        guard old != nil || new != nil else { throw RouterSystemError.invalidRequest }
        let targetNode = try RouterSystemInstallNode.directory(target)
        let transactionNode = try RouterSystemInstallNode.directory(directory)
        guard targetNode != transactionNode else { throw RouterSystemError.invalidRequest }
        if let old { try directory.create(file.receiptLeaf("before"), data: old.bytes) }
        try boundary(.beforeCopySaved)
        var created: RouterSystemInstallImage?
        if let new {
            try directory.create(file.receiptLeaf("after"), data: new)
            try boundary(.afterCopySaved)
            created = try createPublication(file, bytes: new)
        }
        try boundary(.stagedFileSaved)
        let staged = try snapshot(file.receiptLeaf("publish"), in: directory, file: file)
        guard staged?.image == created, staged?.bytes == new,
              try snapshot(file.leaf, in: target, file: file)?.image == old?.image,
              try RouterSystemInstallNode.directory(target) == targetNode else { throw RouterSystemError.conflict }
        let receipt = RouterSystemInstallFileReceipt(version: 1, transaction: id, file: file,
            transactionDirectory: transactionNode, targetDirectory: targetNode, before: old?.image, after: staged?.image)
        try directory.create(file.receiptLeaf("receipt"), data: receipt.encoded())
        try syncDirectory(directory)
        try boundary(.receiptSaved)
        _ = try load(file, target: target)
        return receipt
    }

    func load(_ file: RouterSystemInstallFile, target: RouterSystemDirectory) throws -> RouterSystemInstallFileReceipt {
        guard let data = try directory.read(file.receiptLeaf("receipt"), maximum: 8192) else {
            throw RouterSystemError.journalUnknown
        }
        let value = try RouterSystemInstallFileReceipt.decode(data)
        guard value.transaction == id, value.file == file, directory.owner == target.owner,
              value.transactionDirectory == (try RouterSystemInstallNode.directory(directory)),
              value.targetDirectory == (try RouterSystemInstallNode.directory(target)) else { throw RouterSystemError.conflict }
        for (suffix, expected) in [("before", value.before), ("after", value.after)] {
            let bytes = try directory.read(file.receiptLeaf(suffix), maximum: file.maximum)
            guard bytes.map(RouterSystemObservation.hash) == expected?.digest, bytes?.count == expected?.count else {
                throw RouterSystemError.journalUnknown
            }
            if let bytes { try directory.synchronizeFile(file.receiptLeaf(suffix), expected: bytes, synchronize: synchronize) }
        }
        try directory.synchronizeFile(file.receiptLeaf("receipt"), expected: data, synchronize: synchronize)
        try syncDirectory(directory)
        return value
    }

    func publish(_ receipt: RouterSystemInstallFileReceipt, target: RouterSystemDirectory) throws {
        guard try load(receipt.file, target: target) == receipt else { throw RouterSystemError.conflict }
        let file = receipt.file
        func positions() throws -> (current: RouterSystemInstallImage?, archived: RouterSystemInstallImage?, staged: RouterSystemInstallImage?) {
            (try snapshot(file.leaf, in: target, file: file)?.image,
             try snapshot(file.receiptLeaf("retired"), in: directory, file: file)?.image,
             try snapshot(file.receiptLeaf("publish"), in: directory, file: file)?.image)
        }
        let initial = try positions()
        let untouched = initial.current == receipt.before && initial.archived == nil && initial.staged == receipt.after
        let gap = initial.current == nil && initial.archived == receipt.before && initial.staged == receipt.after
        let finished = initial.current == receipt.after && initial.archived == receipt.before && initial.staged == nil
        guard untouched || gap || finished else { throw RouterSystemError.conflict }

        if !finished {
            if untouched, let before = receipt.before {
                try boundary(.beforeArchive)
                guard try positions().current == before, try positions().archived == nil else { throw RouterSystemError.conflict }
                try move(file.leaf, from: target, to: directory, name: file.receiptLeaf("retired"))
                try boundary(.archived)
                guard try positions().archived == before, try positions().current == nil else { throw RouterSystemError.conflict }
                try syncDirectory(target); try syncDirectory(directory)
                try boundary(.archiveSynced)
            }
            if let after = receipt.after {
                try boundary(.beforePublish)
                let ready = try positions()
                guard ready.current == nil, ready.archived == receipt.before, ready.staged == after else {
                    throw RouterSystemError.conflict
                }
                try move(file.receiptLeaf("publish"), from: directory, to: target, name: file.leaf)
                try boundary(.published)
            }
        }
        // Re-sync the exact retained/new inodes even if a prior attempt completed its renames.
        if let before = receipt.before { try syncFile(file.receiptLeaf("retired"), in: directory, file: file, expected: before) }
        if let after = receipt.after { try syncFile(file.leaf, in: target, file: file, expected: after) }
        try syncDirectory(target); try syncDirectory(directory)
        try boundary(.publicationSynced)
        let final = try positions()
        guard final.current == receipt.after, final.archived == receipt.before, final.staged == nil else {
            throw RouterSystemError.conflict
        }
    }

    private func snapshot(_ name: String, in parent: RouterSystemDirectory, file: RouterSystemInstallFile) throws -> (image: RouterSystemInstallImage, bytes: Data)? {
        try parent.validate()
        var before = stat(), after = stat()
        if fstatat(parent.fd, name, &before, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return nil
        }
        guard let bytes = try parent.read(name, maximum: file.maximum, mode: file.mode),
              fstatat(parent.fd, name, &after, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(before, after) else { throw RouterSystemError.conflict }
        try parent.validate()
        return (.init(node: .init(after), digest: RouterSystemObservation.hash(bytes), count: bytes.count), bytes)
    }
    private func move(_ leaf: String, from source: RouterSystemDirectory, to target: RouterSystemDirectory, name: String) throws {
        try source.validate(); try target.validate()
        guard renameatx_np(source.fd, leaf, target.fd, name, UInt32(RENAME_EXCL)) == 0 else {
            throw RouterSystemError.conflict
        }
    }
    private func syncDirectory(_ directory: RouterSystemDirectory) throws {
        try directory.validate()
        guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
    }
    private func syncFile(_ name: String, in parent: RouterSystemDirectory, file: RouterSystemInstallFile, expected: RouterSystemInstallImage) throws {
        guard try snapshot(name, in: parent, file: file)?.image == expected else { throw RouterSystemError.conflict }
        let descriptor = openat(parent.fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(descriptor) }
        let held = try parent.regular(descriptor, mode: file.mode)
        guard RouterSystemInstallNode(held) == expected.node, synchronize(descriptor) == 0,
              try snapshot(name, in: parent, file: file)?.image == expected else { throw RouterSystemError.journalUnknown }
    }
    /// The sole 0644 create is for a fixed plist publication, not a relaxation of journal writes.
    private func createPublication(_ file: RouterSystemInstallFile, bytes: Data) throws -> RouterSystemInstallImage {
        try directory.validate()
        let name = file.receiptLeaf("publish")
        let fd = openat(directory.fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, file.mode)
        guard fd >= 0 else { throw RouterSystemError.journalUnknown }
        defer { close(fd) }
        // A restrictive process umask is allowed; the fixed private staging directory remains 0700.
        guard fchmod(fd, file.mode) == 0 else { throw RouterSystemError.journalUnknown }
        _ = try directory.regular(fd, mode: file.mode)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterSystemError.journalUnknown }; offset += count
        }
        let held = try directory.regular(fd, mode: file.mode)
        let expected = RouterSystemInstallImage(node: .init(held), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
        guard synchronize(fd) == 0, try snapshot(name, in: directory, file: file)?.image == expected else {
            throw RouterSystemError.journalUnknown
        }
        try syncDirectory(directory)
        guard try snapshot(name, in: directory, file: file)?.image == expected else { throw RouterSystemError.conflict }
        return expected
    }
}
