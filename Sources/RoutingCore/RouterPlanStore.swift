import Foundation
import CryptoKit
import Darwin

public enum RouterStoreError: Error, Equatable {
    case unsafeLocation, unreadable, damaged, unsupportedVersion, invalidPlan
    case busy, conflict, noPreviousVersion, writeFailed
    case outcomeUnknown(UUID)
}

public struct RouterStoredPlan {
    public let current: RouterPlan?
    public let previous: RouterPlan?
    public let revision: UUID?
    fileprivate let origin: String
    fileprivate let digest: String?
    fileprivate let identity: String?
}

/// Current and previous plans share one atomic record. Neither is a network acceptance result.
public final class RouterPlanStore {
    public let directory: URL
    private let maximum = RouterInput.maximumBytes * 2 + 4096
    private let name = "plans.json"
    enum WriteStage { case beforeReplace, afterReplace }
    private let checkpoint: (WriteStage) throws -> Void

    public convenience init(directory: URL) { self.init(directory: directory, checkpoint: { _ in }) }
    init(directory: URL, checkpoint: @escaping (WriteStage) throws -> Void) {
        self.directory = directory.standardizedFileURL
        self.checkpoint = checkpoint
    }

    private struct Record: Codable {
        let version: Int
        let revision: UUID
        let current: RouterPlan
        let previous: RouterPlan?
    }

    public func load() throws -> RouterStoredPlan {
        let fd = try openDirectory(create: false)
        guard fd >= 0 else { return absent() }
        defer { close(fd) }
        return try snapshot(fd)
    }

    public func save(_ plan: RouterPlan, expecting original: RouterStoredPlan) throws -> RouterStoredPlan {
        try validate(plan)
        return try transaction(expecting: original) { current in
            .init(version: 1, revision: UUID(), current: plan, previous: current.current)
        }
    }

    public func restore(expecting original: RouterStoredPlan) throws -> RouterStoredPlan {
        try transaction(expecting: original) { current in
            guard let previous = current.previous else { throw RouterStoreError.noPreviousVersion }
            return .init(version: 1, revision: UUID(), current: previous, previous: current.current)
        }
    }

    private func validate(_ plan: RouterPlan) throws {
        guard plan.schemaVersion == 1 else { throw RouterStoreError.unsupportedVersion }
        guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }),
              try JSONEncoder().encode(plan).count <= RouterInput.maximumBytes else { throw RouterStoreError.invalidPlan }
    }
    private func absent(directoryIdentity: String? = nil) -> RouterStoredPlan {
        .init(current: nil, previous: nil, revision: nil, origin: directory.path, digest: nil, identity: directoryIdentity)
    }
    private func openDirectory(create: Bool) throws -> Int32 {
        guard directory.path == directory.resolvingSymlinksInPath().path else { throw RouterStoreError.unsafeLocation }
        if create {
            do { try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                                                        attributes: [.posixPermissions: 0o700]) }
            catch { throw RouterStoreError.unsafeLocation }
        }
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        if fd < 0 {
            if !create && errno == ENOENT { return -1 }
            throw RouterStoreError.unsafeLocation
        }
        do { try checkDirectory(fd); return fd } catch { close(fd); throw error }
    }
    private func checkDirectory(_ fd: Int32) throws {
        var info = stat(), linked = stat()
        guard fstat(fd, &info) == 0, lstat(directory.path, &linked) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o077 == 0,
              linked.st_dev == info.st_dev, linked.st_ino == info.st_ino,
              directory.path == directory.resolvingSymlinksInPath().path else { throw RouterStoreError.unsafeLocation }
    }
    private func safeFile(_ info: stat) -> Bool {
        info.st_mode & S_IFMT == S_IFREG && info.st_uid == getuid() && info.st_nlink == 1 && info.st_mode & 0o077 == 0
    }
    private func identity(_ info: stat) -> String { "\(info.st_dev):\(info.st_ino)" }
    private func same(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_nlink == b.st_nlink &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    private func snapshot(_ directoryFD: Int32) throws -> RouterStoredPlan {
        try checkDirectory(directoryFD)
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 {
            if errno == ENOENT {
                var info = stat()
                guard fstat(directoryFD, &info) == 0 else { throw RouterStoreError.unreadable }
                return absent(directoryIdentity: identity(info) + "/absent")
            }
            throw RouterStoreError.unreadable
        }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, safeFile(info), info.st_size >= 0, info.st_size <= maximum else { throw RouterStoreError.unreadable }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 16384)
        while data.count <= maximum {
            let count = Darwin.read(fd, &buffer, min(buffer.count, maximum + 1 - data.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterStoreError.unreadable }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        var after = stat(), linked = stat(), dirInfo = stat()
        guard data.count <= maximum, data.count == info.st_size, fstat(fd, &after) == 0,
              fstatat(directoryFD, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
              same(info, after), same(info, linked), fstat(directoryFD, &dirInfo) == 0 else { throw RouterStoreError.unreadable }
        try checkDirectory(directoryFD)
        let record = try decode(data)
        return .init(current: record.current, previous: record.previous, revision: record.revision,
                     origin: directory.path, digest: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined(),
                     identity: identity(dirInfo) + "/" + identity(info))
    }
    private func decode(_ data: Data) throws -> Record {
        do {
            guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  Set(object.keys).isSubset(of: ["version", "revision", "current", "previous"]) else { throw RouterStoreError.damaged }
            // Decode scalars strictly, then decode each plan with the R1 unknown-field checks.
            let canonical = try JSONSerialization.data(withJSONObject: object)
            struct Header: Decodable { let version: Int }
            guard try JSONDecoder().decode(Header.self, from: canonical).version == 1 else { throw RouterStoreError.unsupportedVersion }
            let record = try JSONDecoder().decode(Record.self, from: canonical)
            guard let raw = object["current"] else { throw RouterStoreError.damaged }
            let current = try RouterInput.plan(JSONSerialization.data(withJSONObject: raw))
            try validate(current)
            var previous: RouterPlan?
            if let rawPrevious = object["previous"], !(rawPrevious is NSNull) {
                previous = try RouterInput.plan(JSONSerialization.data(withJSONObject: rawPrevious))
                if let previous { try validate(previous) }
            }
            return .init(version: 1, revision: record.revision, current: current, previous: previous)
        } catch let error as RouterStoreError { throw error }
        catch { throw RouterStoreError.damaged }
    }
    private func checkExpected(_ current: RouterStoredPlan, _ original: RouterStoredPlan) throws {
        // A previously missing directory may be created by this transaction. An
        // observed existing directory, including an empty one, must retain identity.
        let firstCreation = original.digest == nil && original.identity == nil && current.digest == nil
        guard original.origin == directory.path, current.digest == original.digest,
              firstCreation || current.identity == original.identity else { throw RouterStoreError.conflict }
    }
    private func transaction(expecting original: RouterStoredPlan, make: (RouterStoredPlan) throws -> Record) throws -> RouterStoredPlan {
        guard original.origin == directory.path else { throw RouterStoreError.conflict }
        let directoryFD = try openDirectory(create: true)
        defer { close(directoryFD) }
        let lockFD = openat(directoryFD, "store.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600)
        guard lockFD >= 0 else { throw RouterStoreError.unsafeLocation }
        defer { close(lockFD) }
        var lockInfo = stat()
        guard fstat(lockFD, &lockInfo) == 0, safeFile(lockInfo) else { throw RouterStoreError.unsafeLocation }
        guard flock(lockFD, LOCK_EX | LOCK_NB) == 0 else { throw RouterStoreError.busy }
        defer { flock(lockFD, LOCK_UN) }
        func checkLock() throws {
            var linked = stat()
            guard fstatat(directoryFD, "store.lock", &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  safeFile(linked), identity(linked) == identity(lockInfo) else { throw RouterStoreError.unsafeLocation }
        }
        try checkLock()
        let current = try snapshot(directoryFD); try checkExpected(current, original)
        let record = try make(current)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
        let data = try encoder.encode(record)
        guard data.count <= maximum else { throw RouterStoreError.invalidPlan }
        let temporary = ".pending-" + record.revision.uuidString + ".json"
        let temporaryFD = openat(directoryFD, temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard temporaryFD >= 0 else { throw RouterStoreError.writeFailed }
        defer { close(temporaryFD) }
        var replaced = false
        do {
            try data.withUnsafeBytes { bytes in
                var written = 0
                while written < bytes.count {
                    let count = Darwin.write(temporaryFD, bytes.baseAddress!.advanced(by: written), bytes.count - written)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw RouterStoreError.writeFailed }
                    written += count
                }
            }
            guard fsync(temporaryFD) == 0 else { throw RouterStoreError.writeFailed }
            try checkpoint(.beforeReplace)
            try checkLock(); try checkExpected(snapshot(directoryFD), original)
            try checkTemporary(temporaryFD, name: temporary, directoryFD: directoryFD, expected: data)
            guard renameat(directoryFD, temporary, directoryFD, name) == 0 else { throw RouterStoreError.writeFailed }
            replaced = true
            try checkpoint(.afterReplace)
            guard fsync(directoryFD) == 0 else { throw RouterStoreError.writeFailed }
            let saved = try snapshot(directoryFD)
            guard saved.revision == record.revision, saved.current == record.current,
                  saved.previous == record.previous else { throw RouterStoreError.conflict }
            return saved
        } catch {
            if replaced { throw RouterStoreError.outcomeUnknown(record.revision) }
            if let known = error as? RouterStoreError { throw known }
            throw RouterStoreError.writeFailed
        }
    }

    private func checkTemporary(_ fd: Int32, name: String, directoryFD: Int32, expected: Data) throws {
        var before = stat(), linked = stat()
        guard fstat(fd, &before) == 0, safeFile(before), before.st_size == expected.count,
              fstatat(directoryFD, name, &linked, AT_SYMLINK_NOFOLLOW) == 0, same(before, linked) else { throw RouterStoreError.writeFailed }
        var bytes = Data(), buffer = [UInt8](repeating: 0, count: 16384)
        while bytes.count < expected.count {
            let count = pread(fd, &buffer, min(buffer.count, expected.count - bytes.count), off_t(bytes.count))
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterStoreError.writeFailed }
            bytes.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard bytes == expected, fstat(fd, &after) == 0, same(before, after),
              fstatat(directoryFD, name, &linked, AT_SYMLINK_NOFOLLOW) == 0, same(after, linked) else { throw RouterStoreError.writeFailed }
    }
}
