import Foundation
import Darwin

/// Only a first installation may publish a whole directory tree. Upgrade and retirement retain
/// the original state directory and operation lock. Payload pin checks belong to the package builder.
final class RouterSystemInstallRoot {
    enum Position: String { case staged, published }
    enum Boundary: CaseIterable { case treeSealed, receiptSealed, beforeRename, renamed, sourceSynced, destinationSynced }
    struct Receipt: Codable, Equatable {
        let version: Int
        let transaction: UUID
        let transactionDirectory: RouterSystemInstallNode
        let destinationParent: RouterSystemInstallNode
        let tree: Tree
        func encoded() throws -> Data { try RouterSystemInstallRegistry.encode(self) }
    }
    struct Tree: Codable, Equatable {
        let root: RouterSystemInstallNode
        let bin: RouterSystemInstallNode
        let core: RouterSystemInstallNode
        let run: RouterSystemInstallNode
        let state: RouterSystemInstallNode
        let files: [Entry]
    }
    struct Entry: Codable, Equatable {
        let kind: File
        let image: RouterSystemInstallImage
    }
    enum File: String, Codable, CaseIterable {
        case helper, core, manifest, packageReceipt, journal, journalLock, operationLock, hostLock
        var installFile: RouterSystemInstallFile? {
            switch self {
            case .helper: return .helper
            case .core: return .core
            case .manifest: return .manifest
            case .packageReceipt: return .packageReceipt
            default: return nil
            }
        }
        var leaf: String {
            if let installFile { return installFile.leaf }
            switch self {
            case .journal: return "journal.json"
            case .journalLock: return "journal.lock"
            case .hostLock: return "host.lock"
            default: return "operation.lock"
            }
        }
        var mode: mode_t { installFile?.mode ?? 0o600 }
        var maximum: Int { installFile?.maximum ?? RouterSystemJournalDecoder.maximumBytes }
    }
    private let transaction: RouterSystemDirectory
    private let destination: RouterSystemDirectory
    private let id: UUID
    private let synchronize: (Int32) -> Int32
    private let boundary: (Boundary) throws -> Void

    init(transaction: RouterSystemDirectory, destination: RouterSystemDirectory, id: UUID,
         synchronize: @escaping (Int32) -> Int32 = fsync, boundary: @escaping (Boundary) throws -> Void = { _ in }) {
        self.transaction = transaction; self.destination = destination; self.id = id
        self.synchronize = synchronize; self.boundary = boundary
    }

    /// Called before a shared active transaction is claimed. An incomplete private tree is preserved;
    /// no second stage call adopts it. A sealed receipt is the only route into publication/retry.
    func stage(files: [RouterSystemInstallFile: Data], initialJournal: Data) throws -> Receipt {
        guard Set(files.keys) == [.helper, .core, .manifest, .packageReceipt],
              transaction.owner == destination.owner, try directoryNode(.installedRoot, parent: destination) == nil else {
            throw RouterSystemError.conflict
        }
        let journal = try RouterSystemJournalDecoder.decode(initialJournal)
        guard journal.installation?.isValid == true, journal.phase == .idle, journal.intent == nil else {
            throw RouterSystemError.journalUnknown
        }
        let root = try transaction.installChild(.stagedRoot, create: true)
        let bin = try root.installChild(.bin, create: true), core = try root.installChild(.core, create: true)
        let run = try root.installChild(.run, create: true), state = try root.installChild(.state, create: true)
        let installer = RouterSystemInstallTransaction(directory: transaction, id: id, synchronize: synchronize)
        var expected: [File: RouterSystemInstallImage] = [:]
        for kind in File.allCases {
            let parent = target(kind, root: root, bin: bin, core: core, state: state)
            if let file = kind.installFile {
                guard let bytes = files[file] else { throw RouterSystemError.invalidRequest }
                let receipt = try installer.stage(file, new: bytes, target: parent)
                try installer.publish(receipt, target: parent)
                expected[kind] = receipt.after
            } else {
                expected[kind] = try createInitial(kind, bytes: kind == .journal ? initialJournal : Data(), state: state)
            }
        }
        let tree = try observe(root)
        guard tree.files.allSatisfy({ expected[$0.kind] == $0.image }) else { throw RouterSystemError.conflict }
        for directory in [bin, core, run, state, root] { try sync(directory) }
        let treeBytes = try RouterSystemInstallRegistry.encode(tree)
        try transaction.create("frozen-tree.json", data: treeBytes)
        try sync(transaction)
        try boundary(.treeSealed)
        let receipt = Receipt(version: 1, transaction: id, transactionDirectory: try .directory(transaction),
            destinationParent: try .directory(destination), tree: tree)
        guard try observe(root) == tree else { throw RouterSystemError.conflict }
        try transaction.create("root.receipt", data: receipt.encoded())
        try sync(transaction)
        try boundary(.receiptSealed)
        return try load()
    }

    func load() throws -> Receipt {
        guard let bytes = try transaction.read("root.receipt", maximum: 16384) else { throw RouterSystemError.journalUnknown }
        _ = try RouterStrictJSON.object(bytes, maximumBytes: 16384)
        let value = try JSONDecoder().decode(Receipt.self, from: bytes)
        guard value.version == 1, value.transaction == id,
              value.transactionDirectory == (try .directory(transaction)), value.destinationParent == (try .directory(destination)),
              value.tree.files.map(\.kind) == File.allCases, try value.encoded() == bytes,
              let treeBytes = try transaction.read("frozen-tree.json", maximum: 16384),
              treeBytes == (try RouterSystemInstallRegistry.encode(value.tree)) else { throw RouterSystemError.conflict }
        for entry in value.tree.files {
            guard RouterSystemProvider.validDigest(entry.image.digest), entry.image.count >= 0,
                  entry.image.count <= entry.kind.maximum else { throw RouterSystemError.journalUnknown }
            if [.journalLock, .operationLock, .hostLock].contains(entry.kind) {
                guard entry.image.count == 0, entry.image.digest == RouterSystemObservation.hash(Data()) else { throw RouterSystemError.journalUnknown }
            }
        }
        try transaction.synchronizeFile("frozen-tree.json", expected: treeBytes, synchronize: synchronize)
        try transaction.synchronizeFile("root.receipt", expected: bytes, synchronize: synchronize)
        try sync(transaction)
        return value
    }

    func position(_ receipt: Receipt) throws -> Position {
        guard receipt == (try load()) else { throw RouterSystemError.conflict }
        let staged = try directoryNode(.stagedRoot, parent: transaction)
        let installed = try directoryNode(.installedRoot, parent: destination)
        if staged == receipt.tree.root, installed == nil { return .staged }
        if staged == nil, installed == receipt.tree.root { return .published }
        throw RouterSystemError.conflict
    }

    /// Must precede launchd registration. Once registration can accept user requests, the coordinator
    /// uses its files-published phase instead; it must not demand an unchanged initial journal.
    func publish(_ receipt: Receipt) throws {
        if try position(receipt) == .staged {
            try verifyTree(receipt, root: transaction.installChild(.stagedRoot))
            try boundary(.beforeRename)
            guard try position(receipt) == .staged else { throw RouterSystemError.conflict }
            try verifyTree(receipt, root: transaction.installChild(.stagedRoot))
            guard renameatx_np(transaction.fd, RouterSystemDirectory.InstallChild.stagedRoot.rawValue,
                               destination.fd, RouterSystemDirectory.InstallChild.installedRoot.rawValue,
                               UInt32(RENAME_EXCL)) == 0 else { throw RouterSystemError.conflict }
            try boundary(.renamed)
        }
        guard try position(receipt) == .published else { throw RouterSystemError.conflict }
        try sync(transaction); try boundary(.sourceSynced)
        try sync(destination); try boundary(.destinationSynced)
        // Acquire new capabilities: old parent-bound staging descriptors are deliberately invalid.
        try verifyTree(receipt, root: destination.installChild(.installedRoot))
        guard try position(receipt) == .published else { throw RouterSystemError.conflict }
    }

    private func verifyTree(_ receipt: Receipt, root: RouterSystemDirectory) throws {
        guard try observe(root) == receipt.tree else { throw RouterSystemError.conflict }
        let bin = try root.installChild(.bin), core = try root.installChild(.core), state = try root.installChild(.state)
        for entry in receipt.tree.files {
            let parent = target(entry.kind, root: root, bin: bin, core: core, state: state)
            let fd = openat(parent.fd, entry.kind.leaf, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
            let held = try parent.regular(fd, mode: entry.kind.mode)
            guard RouterSystemInstallNode(held) == entry.image.node, synchronize(fd) == 0 else { throw RouterSystemError.journalUnknown }
        }
        for directory in [bin, core, state, try root.installChild(.run), root] { try sync(directory) }
        guard try observe(root) == receipt.tree else { throw RouterSystemError.conflict }
    }
    private func observe(_ root: RouterSystemDirectory) throws -> Tree {
        let bin = try root.installChild(.bin), core = try root.installChild(.core)
        let run = try root.installChild(.run), state = try root.installChild(.state)
        try requireEntries(root, ["bin", "core", "run", "state", "install-manifest.json", "package-receipt.json"])
        try requireEntries(bin, ["router-system-helper"]); try requireEntries(core, ["mihomo"])
        try requireEntries(run, []); try requireEntries(state, ["journal.json", "journal.lock", "operation.lock", "host.lock"])
        let entries = try File.allCases.map { kind -> Entry in
            .init(kind: kind, image: try image(kind, parent: target(kind, root: root, bin: bin, core: core, state: state)))
        }
        return .init(root: try .directory(root), bin: try .directory(bin), core: try .directory(core),
                     run: try .directory(run), state: try .directory(state), files: entries)
    }
    private func target(_ kind: File, root: RouterSystemDirectory, bin: RouterSystemDirectory,
                        core: RouterSystemDirectory, state: RouterSystemDirectory) -> RouterSystemDirectory {
        switch kind { case .helper: return bin; case .core: return core
        case .manifest, .packageReceipt: return root; default: return state }
    }
    private func image(_ file: File, parent: RouterSystemDirectory) throws -> RouterSystemInstallImage {
        try parent.validate()
        var before = stat(), after = stat()
        guard fstatat(parent.fd, file.leaf, &before, AT_SYMLINK_NOFOLLOW) == 0,
              let bytes = try parent.read(file.leaf, maximum: file.maximum, mode: file.mode),
              fstatat(parent.fd, file.leaf, &after, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(before, after) else { throw RouterSystemError.conflict }
        try parent.validate()
        return .init(node: .init(after), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
    }
    private func createInitial(_ file: File, bytes: Data, state: RouterSystemDirectory) throws -> RouterSystemInstallImage {
        guard file.installFile == nil else { throw RouterSystemError.invalidRequest }
        try state.validate()
        let fd = openat(state.fd, file.leaf, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RouterSystemError.journalUnknown }; defer { close(fd) }
        _ = try state.regular(fd, mode: 0o600)
        var offset = 0
        while offset < bytes.count {
            let count = bytes.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), bytes.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterSystemError.journalUnknown }; offset += count
        }
        let expected = RouterSystemInstallImage(node: .init(try state.regular(fd, mode: 0o600)), digest: RouterSystemObservation.hash(bytes), count: bytes.count)
        guard synchronize(fd) == 0, try image(file, parent: state) == expected else { throw RouterSystemError.journalUnknown }
        try sync(state)
        return expected
    }
    private func directoryNode(_ kind: RouterSystemDirectory.InstallChild, parent: RouterSystemDirectory) throws -> RouterSystemInstallNode? {
        try parent.validate()
        var info = stat()
        if fstatat(parent.fd, kind.rawValue, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return nil
        }
        return try .directory(parent.installChild(kind))
    }
    private func requireEntries(_ parent: RouterSystemDirectory, _ expected: Set<String>) throws {
        try parent.validate()
        let fd = openat(parent.fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        guard let stream = fdopendir(fd) else { close(fd); throw RouterSystemError.ownershipUnknown }
        defer { closedir(stream) }
        var found = Set<String>()
        while true {
            errno = 0
            guard let entry = readdir(stream) else {
                guard errno == 0 else { throw RouterSystemError.ownershipUnknown }; break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            guard expected.contains(name), found.insert(name).inserted else { throw RouterSystemError.conflict }
        }
        guard found == expected else { throw RouterSystemError.conflict }
        try parent.validate()
    }
    private func sync(_ directory: RouterSystemDirectory) throws {
        try directory.validate()
        guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
    }
}
