import Foundation
import Darwin

public struct ConnectorLifetimeIdentity: Codable, Equatable, Sendable {
    let device: Int32
    let inode: UInt64
}

/// Fixed inode, never removed or replaced. Gateway retains this object until process exit.
final class ConnectorGatewayLifetime {
    private let fd: Int32
    let identity: ConnectorLifetimeIdentity
    init(directory: URL, expected: ConnectorLifetimeIdentity? = nil) throws {
        let root = try PrivateRecoveryDirectory(directory)
        fd = openat(root.fd, "connector-gateway.lifetime", O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK |
                    (expected == nil ? O_CREAT : 0), 0o600)
        guard fd >= 0 else { throw PrivateRecoveryDirectory.failure }
        do {
            let info = try root.validate(fd)
            identity = .init(device: info.st_dev, inode: info.st_ino)
            guard expected == nil || expected == identity, flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                throw PrivateRecoveryDirectory.failure
            }
            var linked = stat()
            guard fstatat(root.fd, "connector-gateway.lifetime", &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  linked.st_dev == info.st_dev, linked.st_ino == info.st_ino, linked.st_nlink == 1 else {
                throw PrivateRecoveryDirectory.failure
            }
        } catch { close(fd); throw error }
    }
    deinit { close(fd) }
}

/// An unresolved record is always a restart barrier, never a permission or replay instruction.
struct ConnectorHoldIntent: Codable, Equatable {
    let version: Int
    let hold: ConnectorHoldBinding
    let lifetime: ConnectorLifetimeIdentity
    var attachment: ConnectorTransactionBinding?
    var released: Bool
    init(hold: ConnectorHoldBinding, lifetime: ConnectorLifetimeIdentity) {
        version = 1; self.hold = hold; self.lifetime = lifetime; released = false
    }
    private enum Field: String, CodingKey { case version, hold, lifetime, attachment, released }
    init(from decoder: Decoder) throws {
        let root = try decoder.container(keyedBy: ConnectorSchema.Key.self)
        var keys: Set<String> = ["version", "hold", "lifetime", "released"]
        if root.contains(.init("attachment")) { keys.insert("attachment") }
        try ConnectorSchema.keys(decoder, keys)
        try ConnectorSchema.identity(root.superDecoder(forKey: .init("hold")), pf: false)
        try ConnectorSchema.keys(root.superDecoder(forKey: .init("lifetime")), ["device", "inode"])
        let fields = try decoder.container(keyedBy: Field.self)
        version = try fields.decode(Int.self, forKey: .version)
        hold = try fields.decode(ConnectorHoldBinding.self, forKey: .hold)
        lifetime = try fields.decode(ConnectorLifetimeIdentity.self, forKey: .lifetime)
        released = try fields.decode(Bool.self, forKey: .released)
        if fields.contains(.attachment) {
            try ConnectorSchema.identity(root.superDecoder(forKey: .init("attachment")), pf: true)
            attachment = try fields.decode(ConnectorTransactionBinding.self, forKey: .attachment)
        }
        guard version == 1, hold.valid, lifetime.inode > 0,
              attachment.map({ $0.valid && hold.matches($0) }) ?? true else { throw ConnectorSchema.invalid(decoder) }
    }
}

/// Caller owns the Supervisor lifecycle lock. All store work is additionally serialized here.
final class ConnectorHoldStore: @unchecked Sendable {
    private let directory: PrivateRecoveryDirectory
    private let lock = NSLock()
    private let afterReplace: (() throws -> Void)?
    init(directory: URL, afterReplace: (() throws -> Void)? = nil) throws {
        self.directory = try PrivateRecoveryDirectory(directory); self.afterReplace = afterReplace
    }
    func load() throws -> ConnectorHoldIntent? {
        lock.lock(); defer { lock.unlock() }; return try read()
    }
    private func read() throws -> ConnectorHoldIntent? {
        guard let bytes = try directory.read("connector-hold.json") else { return nil }
        return try JSONDecoder().decode(ConnectorHoldIntent.self, from: bytes)
    }
    func save(_ next: ConnectorHoldIntent, replacing expected: ConnectorHoldIntent?) throws {
        lock.lock(); defer { lock.unlock() }
        guard try read() == expected else { throw PrivateRecoveryDirectory.failure }
        // Validate even records constructed in memory, not just external JSON.
        let bytes = try JSONEncoder().encode(next)
        _ = try JSONDecoder().decode(ConnectorHoldIntent.self, from: bytes)
        try directory.write(bytes, to: "connector-hold.json", afterReplace: afterReplace)
    }
}

final class PrivateRecoveryDirectory {
    static let failure = LauncherError.message("恢复记录或生命周期锁不可用；保持阻断。")
    let fd: Int32
    init(_ url: URL) throws {
        guard url.standardizedFileURL.path == url.resolvingSymlinksInPath().path else { throw Self.failure }
        fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        var info = stat()
        guard fd >= 0 else { throw Self.failure }
        guard fstat(fd, &info) == 0, info.st_uid == geteuid(), info.st_mode & 0o777 == 0o700 else {
            close(fd); throw Self.failure
        }
    }
    deinit { close(fd) }
    func validate(_ file: Int32) throws -> stat {
        var info = stat()
        guard fstat(file, &info) == 0, info.st_uid == geteuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o777 == 0o600, info.st_nlink == 1 else { throw Self.failure }
        return info
    }
    func read(_ leaf: String) throws -> Data? {
        let file = openat(fd, leaf, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC)
        if file < 0 { if errno == ENOENT { return nil }; throw Self.failure }
        defer { close(file) }
        let before = try validate(file)
        guard (1...8192).contains(before.st_size) else { throw Self.failure }
        var data = Data(), buffer = [UInt8](repeating: 0, count: 8193)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, data.count + count <= 8192 else { throw Self.failure }
            if count == 0 { break }; data.append(contentsOf: buffer.prefix(count))
        }
        let after = try validate(file)
        guard data.count == before.st_size, before.st_size == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw Self.failure }
        return data
    }
    func write(_ data: Data, to leaf: String, afterReplace: (() throws -> Void)?) throws {
        guard data.count <= 8192 else { throw Self.failure }
        let temporary = ".recovery-\(UUID().uuidString)"
        let file = openat(fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw Self.failure }; defer { close(file) }
        try data.withUnsafeBytes { bytes in
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.write(file, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw Self.failure }; offset += count
            }
        }
        guard fsync(file) == 0, renameat(fd, temporary, fd, leaf) == 0 else { throw Self.failure }
        try afterReplace?()
        guard fsync(fd) == 0 else { throw Self.failure }
    }
}
