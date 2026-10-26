import Foundation
import Darwin

/// User-owned runtime state only. Root must use a separate installed helper/provider.
struct RouterRuntimeFiles {
    let root: URL
    init(root: URL) { self.root = root }

    static func physicalPath(_ url: URL) -> String? {
        guard let pointer = realpath(url.path, nil) else { return nil }
        defer { free(pointer) }; return String(cString: pointer)
    }

    func prepare() throws {
        guard getuid() != 0 else { throw RouterRuntimeError.unsafeFile }
        var existing = root
        while Self.physicalPath(existing) == nil && existing.path != "/" { existing = existing.deletingLastPathComponent() }
        guard Self.physicalPath(existing) == existing.path else { throw RouterRuntimeError.unsafeFile }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try validateDirectory(root)
    }
    func validateDirectory(_ url: URL) throws {
        var info = stat()
        guard url.path == Self.physicalPath(url), lstat(url.path, &info) == 0,
              info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
            throw RouterRuntimeError.unsafeFile
        }
        // A private leaf inside a renameable shared parent is not a private namespace.
        var parent = url.deletingLastPathComponent()
        while true {
            var ancestor = stat()
            guard lstat(parent.path, &ancestor) == 0, ancestor.st_mode & S_IFMT == S_IFDIR,
                  ancestor.st_uid == 0 || ancestor.st_uid == getuid(),
                  ancestor.st_mode & 0o022 == 0 || ancestor.st_mode & S_ISVTX != 0 else {
                throw RouterRuntimeError.unsafeFile
            }
            if parent.path == "/" { break }
            parent = parent.deletingLastPathComponent()
        }
    }
    func createGeneration() throws -> URL {
        try prepare()
        guard try FileManager.default.contentsOfDirectory(atPath: root.path).count < 8 else { throw RouterRuntimeError.workspaceFull }
        let directory = root.appendingPathComponent(UUID().uuidString.lowercased())
        guard mkdir(directory.path, 0o700) == 0 else { throw RouterRuntimeError.unsafeFile }
        try validateDirectory(directory)
        return directory
    }
    func writeNew(_ data: Data, to url: URL, executable: Bool = false) throws {
        try validateDirectory(url.deletingLastPathComponent())
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, executable ? 0o700 : 0o600)
        guard fd >= 0 else { throw RouterRuntimeError.unsafeFile }
        defer { close(fd) }
        var offset = 0
        while offset < data.count {
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            if n < 0 && errno == EINTR { continue }
            guard n > 0 else { throw RouterRuntimeError.operationFailed }; offset += n
        }
        guard fsync(fd) == 0 else { throw RouterRuntimeError.operationFailed }
    }
    func readPrivate(_ url: URL, maximum: Int = 2_100_000) throws -> Data {
        try validateDirectory(url.deletingLastPathComponent())
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RouterRuntimeError.unsafeFile }
        defer { close(fd) }
        var before = stat(), after = stat(), linked = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_mode & 0o077 == 0, before.st_uid == getuid(), before.st_nlink == 1,
              before.st_size >= 0, before.st_size <= maximum else { throw RouterRuntimeError.unsafeFile }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= maximum {
            let n = Darwin.read(fd, &buffer, min(buffer.count, maximum + 1 - data.count))
            if n < 0 && errno == EINTR { continue }
            guard n >= 0 else { throw RouterRuntimeError.unsafeFile }
            if n == 0 { break }; data.append(contentsOf: buffer.prefix(n))
        }
        guard data.count == before.st_size, fstat(fd, &after) == 0, lstat(url.path, &linked) == 0,
              before.st_ino == linked.st_ino, before.st_dev == linked.st_dev, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw RouterRuntimeError.unsafeFile
        }
        return data
    }

    func replacePrivate(_ data: Data, at url: URL) throws {
        try validateDirectory(url.deletingLastPathComponent())
        if FileManager.default.fileExists(atPath: url.path) { _ = try readPrivate(url) }
        let temporary = url.deletingLastPathComponent().appendingPathComponent("write-" + UUID().uuidString)
        try writeNew(data, to: temporary)
        guard rename(temporary.path, url.path) == 0 else { throw RouterRuntimeError.operationFailed }
        let fd = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterRuntimeError.ownershipUnknown }
        defer { close(fd) }
        guard fsync(fd) == 0, try readPrivate(url) == data else { throw RouterRuntimeError.ownershipUnknown }
    }

    func locked<T>(_ body: () throws -> T) throws -> T {
        try prepare()
        let fd = open(root.appendingPathComponent("service.lock").path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RouterRuntimeError.unsafeFile }
        defer { close(fd) }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1,
              info.st_mode & 0o077 == 0, info.st_uid == getuid() else { throw RouterRuntimeError.unsafeFile }
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw RouterRuntimeError.alreadyLoaded }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    /// Sampling must not create the runtime directory, lock, or a new journal.
    func observingExisting<T>(_ body: () throws -> T) throws -> T {
        var node = stat()
        guard lstat(root.path, &node) == 0 else {
            if errno == ENOENT { throw RouterConnectionFailure.noActiveInstance }
            throw RouterConnectionFailure.identityChanged
        }
        try validateDirectory(root)
        let path = root.appendingPathComponent("service.lock").path
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw RouterConnectionFailure.identityChanged }
        defer { close(fd) }
        func verify() throws {
            try validateDirectory(root)
            var held = stat(), linked = stat(), parent = stat()
            guard lstat(root.path, &parent) == 0, parent.st_dev == node.st_dev, parent.st_ino == node.st_ino,
                  fstat(fd, &held) == 0, lstat(path, &linked) == 0,
                  held.st_mode & S_IFMT == S_IFREG, held.st_mode & 0o7777 == 0o600,
                  held.st_uid == getuid(), held.st_nlink == 1, held.st_size == 0,
                  RouterSystemDirectory.unchanged(held, linked) else { throw RouterConnectionFailure.identityChanged }
        }
        try verify()
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw RouterConnectionFailure.busy }
        defer { flock(fd, LOCK_UN) }
        try verify()
        let result = try body()
        try verify()
        return result
    }
}
