import Foundation
import Darwin

public struct EnvironmentSettings: Codable, Equatable {
    public let version = 1
    public var expectedIP = ""
    public var diagnosticProxy = ""
    public var notifications = true
    private var loadedRevision: String?
    private var legacyRevision: String?
    private var origin: URL?
    private enum CodingKeys: String, CodingKey { case version, expectedIP, diagnosticProxy, notifications }
    public init() {}
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.expectedIP == rhs.expectedIP && lhs.diagnosticProxy == rhs.diagnosticProxy && lhs.notifications == rhs.notifications
    }
    public static let url = Paths.root.appendingPathComponent("environment-settings.json")

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        guard (try container.decodeIfPresent(Int.self, forKey: .version) ?? 1) == 1 else {
            throw LauncherError.message("环境检测配置版本尚未支持，已保留原文件。")
        }
        expectedIP = try container.decode(String.self, forKey: .expectedIP)
        diagnosticProxy = try container.decode(String.self, forKey: .diagnosticProxy)
        notifications = try container.decodeIfPresent(Bool.self, forKey: .notifications) ?? true
    }

    public func validate() throws {
        guard expectedIP.isEmpty || normalizedIPv4(expectedIP) != nil else {
            throw LauncherError.message("固定出口需要有效的 IPv4 地址；原设置未修改。")
        }
        guard diagnosticProxy.isEmpty || EnvironmentRoutes.validatedProxy(diagnosticProxy).error == nil else {
            throw LauncherError.message("诊断代理地址无效，或包含认证信息；原设置未修改。")
        }
    }

    public static func readIfPresent() throws -> Self? { try readIfPresent(at: url) }
    static func readIfPresent(at location: URL) throws -> Self? {
        guard let bytes = try EnvironmentStorage.readBytes(location) else { return nil }
        do {
            var value = try JSONDecoder().decode(Self.self, from: bytes)
            try value.validate(); value.loadedRevision = fingerprintData(bytes); value.origin = location
            return value
        } catch { throw LauncherError.message("环境检测配置无法读取，已保留原文件。") }
    }

    public static func read() throws -> Self { try read(at: url, legacy: PreflightSettings.url) }
    static func read(at location: URL, legacy: URL) throws -> Self {
        if let value = try readIfPresent(at: location) { return value }
        var value = Self(); value.origin = location
        value.diagnosticProxy = "http://127.0.0.1:1082"
        if let bytes = try EnvironmentStorage.readBytes(legacy) {
            do {
                let previous = try JSONDecoder().decode(PreflightSettings.self, from: bytes)
                try previous.validate()
                value.expectedIP = previous.expectedIP; value.notifications = previous.notifications
                value.legacyRevision = fingerprintData(bytes)
            } catch { throw LauncherError.message("旧检测配置无法迁移，已保留原文件；请先核对。") }
        } else {
            // Documentation-only example in this source snapshot; configure your own baseline before use.
            value.expectedIP = "203.0.113.43"
            value.legacyRevision = "absent"
        }
        return value
    }

    public func save() throws { try save(at: Self.url, legacy: PreflightSettings.url) }
    func save(at location: URL, legacy: URL) throws {
        try validate()
        guard origin == nil || origin == location else { throw LauncherError.message("配置来源不一致，请重新读取。") }
        try EnvironmentStorage.withLock(at: location.deletingLastPathComponent().appendingPathComponent("environment-settings.lock")) {
            let current = try EnvironmentStorage.readBytes(location)
            guard current.map(fingerprintData) == loadedRevision else {
                throw LauncherError.message("环境检测配置已变化，请重新读取；没有覆盖现有文件。")
            }
            if current == nil, let legacyRevision {
                let latest = try EnvironmentStorage.readBytes(legacy).map(fingerprintData) ?? "absent"
                guard latest == legacyRevision else { throw LauncherError.message("旧配置已变化，请重新读取后再迁移。") }
            }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
            try EnvironmentStorage.writeBytes(encoder.encode(self), to: location)
        }
    }
}

enum EnvironmentStorage {
    static func readBytes(_ url: URL, maximum: Int = 262_144, allowRootOwner: Bool = false) throws -> Data? {
        let parent = url.deletingLastPathComponent()
        guard maximum >= 0, parent.standardizedFileURL.path == parent.resolvingSymlinksInPath().path else { throw storageError() }
        let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard descriptor >= 0 else {
            if errno == ENOENT {
                var info = stat()
                if lstat(url.path, &info) == 0 || errno != ENOENT { throw storageError() }
                return nil
            }
            throw storageError()
        }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, (info.st_uid == getuid() || (allowRootOwner && info.st_uid == 0)),
              info.st_size >= 0, info.st_size <= maximum else { throw storageError() }
        var data = Data(); var buffer = [UInt8](repeating: 0, count: 16384)
        while true {
            let count = Darwin.read(descriptor, &buffer, min(buffer.count, maximum + 1 - data.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw storageError() }
            if count == 0 { break }
            data.append(contentsOf: buffer.prefix(count))
            guard data.count <= maximum else { throw storageError() }
        }
        func same(_ other: stat) -> Bool {
            other.st_dev == info.st_dev && other.st_ino == info.st_ino && other.st_size == info.st_size &&
                other.st_mode == info.st_mode && other.st_uid == info.st_uid && other.st_nlink == info.st_nlink &&
                other.st_mtimespec.tv_sec == info.st_mtimespec.tv_sec && other.st_mtimespec.tv_nsec == info.st_mtimespec.tv_nsec &&
                other.st_ctimespec.tv_sec == info.st_ctimespec.tv_sec && other.st_ctimespec.tv_nsec == info.st_ctimespec.tv_nsec
        }
        var after = stat(), linked = stat()
        guard fstat(descriptor, &after) == 0, lstat(url.path, &linked) == 0,
              same(after), same(linked), data.count == info.st_size else { throw storageError() }
        return data
    }

    static func ensureDirectory(_ directory: URL) throws {
        // URL equality also includes its cached directory/trailing-slash hint.
        // A URL constructed before mkdir must remain valid after another writer creates it.
        guard directory.standardizedFileURL.path == directory.resolvingSymlinksInPath().path else { throw storageError() }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { throw storageError() }
    }

    static func withLock<T>(at url: URL, _ body: () throws -> T) throws -> T {
        try ensureDirectory(url.deletingLastPathComponent())
        let descriptor = open(url.path, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
        guard descriptor >= 0 else { throw storageError() }
        defer { close(descriptor) }
        var info = stat()
        guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_uid == getuid(), info.st_nlink == 1, flock(descriptor, LOCK_EX | LOCK_NB) == 0 else { throw storageError() }
        defer { flock(descriptor, LOCK_UN) }
        return try body()
    }

    static func writeBytes(_ data: Data, to url: URL, maximum: Int = 262_144) throws {
        guard data.count <= maximum else { throw storageError() }
        try ensureDirectory(url.deletingLastPathComponent())
        // Reading first rejects symlinks, devices, unreadable files and unowned destinations.
        _ = try readBytes(url, maximum: maximum)
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".environment-" + UUID().uuidString + ".tmp")
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard descriptor >= 0 else { throw storageError() }
        defer { close(descriptor) }
        try data.withUnsafeBytes { bytes in
            var written = 0
            while written < bytes.count {
                let count = Darwin.write(descriptor, bytes.baseAddress!.advanced(by: written), bytes.count - written)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw storageError() }
                written += count
            }
        }
        guard fsync(descriptor) == 0, rename(temporary.path, url.path) == 0 else { throw storageError() }
        let directory = open(url.deletingLastPathComponent().path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
        guard directory >= 0 else { throw storageError() }
        defer { close(directory) }
        guard fsync(directory) == 0 else { throw storageError() }
    }
    static func storageError() -> LauncherError { .message("检测记录路径不可安全读取或写入，已保留原状态。") }
}
