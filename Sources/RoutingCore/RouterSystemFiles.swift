import Foundation
import Darwin

enum RouterSystemLayout {
    static let root = "/Library/Application Support/Claude Router"
    static let helper = root + "/bin/router-system-helper"
    static let core = root + "/core/mihomo"
    static let state = root + "/state"
    static let socket = root + "/run/control.sock"
    static let label = "local.crazymax.claude-router.system-host"
    static let installerRoot = "/Library/Application Support/Claude Router Installer"
    static let applicationSupport = "/Library/Application Support"
    static let launchDaemons = "/Library/LaunchDaemons"
}

/// Directory capability, not a caller-selected pathname. Production opens only the fixed root tree.
final class RouterSystemDirectory {
    let fd: Int32
    let owner: uid_t
    private let installedPath: String?
    private let privateLeaf: Bool
    private let parent: (RouterSystemDirectory, String)?
    private init(fd: Int32, owner: uid_t, installedPath: String? = nil, privateLeaf: Bool = true,
                 parent: (RouterSystemDirectory, String)? = nil) {
        self.fd = fd; self.owner = owner; self.installedPath = installedPath; self.privateLeaf = privateLeaf; self.parent = parent
    }
    deinit { close(fd) }

    static func installed(_ path: String, privateLeaf: Bool) throws -> RouterSystemDirectory {
        guard getuid() == 0, geteuid() == 0,
              [RouterSystemLayout.root, RouterSystemLayout.state,
               RouterSystemLayout.root + "/bin", RouterSystemLayout.root + "/core",
               RouterSystemLayout.root + "/run", RouterSystemLayout.installerRoot,
               RouterSystemLayout.applicationSupport, RouterSystemLayout.launchDaemons].contains(path) else { throw RouterSystemError.ownershipUnknown }
        var current = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard current >= 0 else { throw RouterSystemError.ownershipUnknown }
        do {
            try validateDirectory(current, owner: 0, privateLeaf: false)
            let pieces = path.split(separator: "/").map(String.init)
            for (index, piece) in pieces.enumerated() {
                let next = openat(current, piece, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard next >= 0 else { throw RouterSystemError.ownershipUnknown }
                close(current); current = next
                try validateDirectory(current, owner: 0, privateLeaf: privateLeaf && index == pieces.count - 1)
            }
            return .init(fd: current, owner: 0, installedPath: path, privateLeaf: privateLeaf)
        } catch { close(current); throw error }
    }

    /// Tests pass an already-open private directory; no production API or IPC uses this initializer.
    static func fixture(directoryFD: Int32, owner: uid_t) throws -> RouterSystemDirectory {
        let copy = fcntl(directoryFD, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else { throw RouterSystemError.ownershipUnknown }
        do {
            try validateDirectory(copy, owner: owner, privateLeaf: true)
            return .init(fd: copy, owner: owner)
        } catch { close(copy); throw error }
    }

    static func validateDirectory(_ fd: Int32, owner: uid_t, privateLeaf: Bool) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == owner,
              info.st_mode & 0o022 == 0, !privateLeaf || info.st_mode & 0o077 == 0 else { throw RouterSystemError.ownershipUnknown }
        try rejectACL(fd)
    }
    func validate() throws {
        try Self.validateDirectory(fd, owner: owner, privateLeaf: privateLeaf)
        var held = stat(), linked = stat()
        guard fstat(fd, &held) == 0 else { throw RouterSystemError.ownershipUnknown }
        if let installedPath {
            let current = try Self.installed(installedPath, privateLeaf: privateLeaf)
            guard fstat(current.fd, &linked) == 0, held.st_dev == linked.st_dev, held.st_ino == linked.st_ino else { throw RouterSystemError.ownershipUnknown }
        }
        if let (parent, name) = parent {
            try parent.validate()
            guard fstatat(parent.fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  held.st_dev == linked.st_dev, held.st_ino == linked.st_ino else { throw RouterSystemError.ownershipUnknown }
        }
    }
    static func rejectACL(_ fd: Int32) throws {
        var before = stat(), after = stat()
        guard fstat(fd, &before) == 0 else { throw RouterSystemError.ownershipUnknown }
        errno = 0
        guard let acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) else {
            // Darwin reports ENOENT for absent extended security on a valid open file.
            // This is an fd operation, not a missing pathname; all other failures are rejected.
            guard errno == ENOENT, fstat(fd, &after) == 0, unchanged(before, after) else { throw RouterSystemError.ownershipUnknown }
            return
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        guard acl_valid(acl) == 0 else { throw RouterSystemError.ownershipUnknown }
        var entry: acl_entry_t?
        errno = 0
        // Darwin returns 0 when an entry EXISTS. In a validated ACL, index zero is
        // invalid (EINVAL) only when there are no entries; other failures remain unknown.
        let result = acl_get_entry(acl, Int32(ACL_FIRST_ENTRY.rawValue), &entry)
        guard result == -1, errno == EINVAL, entry == nil else { throw RouterSystemError.ownershipUnknown }
    }
    static func leaf(_ name: String) throws {
        guard !name.isEmpty, name.count <= 128, name != ".", name != "..",
              name.utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 || $0 == 46 }) else {
            throw RouterSystemError.ownershipUnknown
        }
    }
    func regular(_ file: Int32, mode: mode_t) throws -> stat {
        var info = stat()
        guard fstat(file, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == owner,
              info.st_mode & 0o7777 == mode, info.st_nlink == 1 else { throw RouterSystemError.ownershipUnknown }
        try Self.rejectACL(file)
        return info
    }
    static func unchanged(_ a: stat, _ b: stat) -> Bool {
        a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_size == b.st_size && a.st_mode == b.st_mode &&
        a.st_uid == b.st_uid && a.st_gid == b.st_gid && a.st_nlink == b.st_nlink &&
        a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec
    }
    func read(_ name: String, maximum: Int, mode: mode_t = 0o600) throws -> Data? {
        try validate()
        try Self.leaf(name)
        guard maximum > 0, maximum <= 128 * 1024 * 1024 else { throw RouterSystemError.invalidRequest }
        let file = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if file < 0 {
            if errno == ENOENT { return nil }
            throw RouterSystemError.ownershipUnknown
        }
        defer { close(file) }
        let before = try regular(file, mode: mode)
        guard before.st_size >= 0, before.st_size <= maximum else { throw RouterSystemError.journalUnknown }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while data.count <= maximum {
            let count = Darwin.read(file, &buffer, min(buffer.count, maximum + 1 - data.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterSystemError.journalUnknown }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
        }
        var linked = stat()
        let after = try regular(file, mode: mode)
        guard data.count == before.st_size, Self.unchanged(before, after),
              fstatat(fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0, Self.unchanged(after, linked) else { throw RouterSystemError.journalUnknown }
        return data
    }
    func create(_ name: String, data: Data, mode: mode_t = 0o600) throws {
        try validate()
        try Self.leaf(name)
        guard data.count <= 128 * 1024 * 1024, mode == 0o600 || mode == 0o700 else { throw RouterSystemError.invalidRequest }
        let file = openat(fd, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard file >= 0 else { throw RouterSystemError.journalUnknown }
        defer { close(file) }
        _ = try regular(file, mode: mode)
        var offset = 0
        while offset < data.count {
            let count = data.withUnsafeBytes { Darwin.write(file, $0.baseAddress!.advanced(by: offset), data.count - offset) }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw RouterSystemError.journalUnknown }
            offset += count
        }
        guard fsync(file) == 0 else { throw RouterSystemError.journalUnknown }
        let written = try regular(file, mode: mode)
        var linked = stat()
        guard fstatat(fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0, Self.unchanged(written, linked),
              try read(name, maximum: max(1, data.count), mode: mode) == data else { throw RouterSystemError.journalUnknown }
    }
    /// Readable bytes after an interrupted write are not proof of durable state.
    func synchronizeFile(_ name: String, expected: Data, synchronize: (Int32) -> Int32 = fsync) throws {
        try validate(); try Self.leaf(name)
        guard expected.count <= 128 * 1024 * 1024 else { throw RouterSystemError.invalidRequest }
        let file = openat(fd, name, O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard file >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(file) }
        let before = try regular(file, mode: 0o600)
        guard before.st_size == expected.count else { throw RouterSystemError.journalUnknown }
        var actual = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while actual.count <= expected.count {
            let count = Darwin.read(file, &buffer, min(buffer.count, expected.count + 1 - actual.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterSystemError.journalUnknown }
            if count == 0 { break }
            actual.append(contentsOf: buffer.prefix(count))
        }
        func verifyIdentity() throws {
            let current = try regular(file, mode: 0o600)
            var linked = stat()
            guard Self.unchanged(before, current), fstatat(fd, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  Self.unchanged(current, linked) else { throw RouterSystemError.journalUnknown }
            try validate()
        }
        guard actual == expected else { throw RouterSystemError.journalUnknown }
        try verifyIdentity()
        guard synchronize(file) == 0 else { throw RouterSystemError.journalUnknown }
        try verifyIdentity()
    }
    func child(_ name: String) throws -> RouterSystemDirectory {
        try validate()
        try Self.leaf(name)
        let file = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard file >= 0 else { throw RouterSystemError.ownershipUnknown }
        do {
            try Self.validateDirectory(file, owner: owner, privateLeaf: true)
            return .init(fd: file, owner: owner, parent: (self, name))
        } catch { close(file); throw error }
    }
    func childIfPresent(_ name: String) throws -> RouterSystemDirectory? {
        try validate(); try Self.leaf(name)
        var info = stat()
        if fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }
            return nil
        }
        return try child(name)
    }
    func createDirectory(_ name: String) throws -> RouterSystemDirectory {
        try validate()
        try Self.leaf(name)
        guard mkdirat(fd, name, 0o700) == 0 else { throw RouterSystemError.journalUnknown }
        guard fsync(fd) == 0 else { throw RouterSystemError.journalUnknown }
        return try child(name)
    }
    func boundedEntryCount(maximum: Int) throws {
        // Reopening '.' gives this scan an independent directory offset.
        let duplicate = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
        guard duplicate >= 0 else { throw RouterSystemError.ownershipUnknown }
        guard let directory = fdopendir(duplicate) else { close(duplicate); throw RouterSystemError.ownershipUnknown }
        defer { closedir(directory) }
        var count = 0
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else { throw RouterSystemError.ownershipUnknown }
                break
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) { String(cString: $0) }
            }
            if name == "." || name == ".." { continue }
            count += 1
            guard count < maximum else { throw RouterSystemError.journalUnknown }
        }
    }
}

extension RouterSystemDirectory {
    /// Fixed installer tree only. Ordinary journal child/create APIs remain private-mode-only.
    enum InstallChild: String {
        case stagedRoot = "root.publish", installedRoot = "Claude Router"
        case bin, core, run, state
        var mode: mode_t { self == .state ? 0o700 : 0o755 }
    }
    func installChild(_ kind: InstallChild, create: Bool = false) throws -> RouterSystemDirectory {
        try validate()
        if create {
            guard kind != .installedRoot, mkdirat(fd, kind.rawValue, kind.mode) == 0 else { throw RouterSystemError.conflict }
        }
        let descriptor = openat(fd, kind.rawValue, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw RouterSystemError.ownershipUnknown }
        do {
            // Staging has a private ancestor; normalize only the directory just created exclusively.
            if create, fchmod(descriptor, kind.mode) != 0 { throw RouterSystemError.journalUnknown }
            try Self.validateDirectory(descriptor, owner: owner, privateLeaf: kind == .state)
            var info = stat(), linked = stat()
            guard fstat(descriptor, &info) == 0, info.st_mode & 0o7777 == kind.mode,
                  fstatat(fd, kind.rawValue, &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  Self.unchanged(info, linked) else { throw RouterSystemError.conflict }
            if create {
                guard fsync(descriptor) == 0, fsync(fd) == 0 else { throw RouterSystemError.journalUnknown }
            }
            try validate()
            return RouterSystemDirectory(fd: descriptor, owner: owner, privateLeaf: kind == .state, parent: (self, kind.rawValue))
        } catch { close(descriptor); throw error }
    }
}
