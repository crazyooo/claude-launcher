import Foundation
import CryptoKit
import Security
import Darwin

public enum AccountVaultError: Error, LocalizedError {
    case unsafe, invalid, conflict, busy, recovery, key, size, existence
    public var errorDescription: String? {
        switch self {
        case .unsafe: return "资料路径、文件类型或权限不符合要求。"
        case .invalid: return "加密档案或身份配置验证失败。"
        case .conflict: return "资料被其他程序修改，已保留恢复记录。"
        case .busy: return "请先退出使用这些资料的客户端。"
        case .recovery: return "上次切换尚未完成，请先恢复。"
        case .key: return "保险库钥匙串密钥不可用；没有替换原密钥。"
        case .size: return "资料超过归档上限，未生成截断档案。"
        case .existence: return "此基础模块不支持跨文件存在状态的切换。"
        }
    }
}

/// JSON identity boundaries. Desktop cookies and native credential Keychain
/// entries require separate adapters before this can be called a full switch.
enum AccountFields {
    static let files = [".claude.json", ".claude/.credentials.json", ".claude/settings.json", ".claude/settings.local.json"]
    static func paths(_ file: String) throws -> [[String]] {
        switch file {
        case ".claude.json": return ["userID", "machineID", "anonymousId", "oauthAccount", "primaryApiKey"].map { [$0] }
        case ".claude/.credentials.json": return [["claudeAiOauth"], ["trustedDeviceToken"]]
        case ".claude/settings.json", ".claude/settings.local.json":
            return [["apiKeyHelper"], ["env", "CLAUDE_CODE_OAUTH_TOKEN"], ["env", "ANTHROPIC_API_KEY"], ["env", "ANTHROPIC_AUTH_TOKEN"]]
        default: throw AccountVaultError.invalid
        }
    }
    static func object(_ data: Data) throws -> [String: Any] {
        guard let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw AccountVaultError.invalid }
        return value
    }
    static func encode(_ value: [String: Any]) throws -> Data { try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) }
    static func selected(_ data: Data, file: String) throws -> Data {
        let source = try object(data); var result: [String: Any] = [:]
        for path in try paths(file) {
            if path.count == 1 { result[path[0]] = source[path[0]] }
            else {
                if let value = source[path[0]], !(value is [String: Any]) { throw AccountVaultError.invalid }
                if let value = (source[path[0]] as? [String: Any])?[path[1]] {
                    var nested = result[path[0]] as? [String: Any] ?? [:]; nested[path[1]] = value; result[path[0]] = nested
                }
            }
        }
        return try encode(result)
    }
    static func merge(_ original: Data, with identity: Data, file: String) throws -> Data {
        var current = try object(original); let incoming = try object(identity)
        guard try encode(incoming) == selected(identity, file: file) else { throw AccountVaultError.invalid }
        for path in try paths(file) {
            if path.count == 1 { current[path[0]] = incoming[path[0]] }
            else {
                if let value = current[path[0]], !(value is [String: Any]) { throw AccountVaultError.invalid }
                var nested = current[path[0]] as? [String: Any] ?? [:]
                nested[path[1]] = (incoming[path[0]] as? [String: Any])?[path[1]]
                if current[path[0]] != nil || !nested.isEmpty { current[path[0]] = nested }
            }
        }
        return try encode(current)
    }
}

public enum AccountMasterKey {
    public static func load(create: Bool) throws -> SymmetricKey {
        let base: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.crazyooo.claude-launcher.account-vault.v1",
            kSecAttrAccount as String: "master", kSecAttrSynchronizable as String: false]
        var query = base; query[kSecReturnData as String] = true; query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            guard let bytes = result as? Data, bytes.count == 32 else { throw AccountVaultError.key }
            return SymmetricKey(data: bytes)
        }
        guard status == errSecItemNotFound, create else { throw AccountVaultError.key }
        let key = SymmetricKey(size: .bits256); var item = base
        item[kSecValueData as String] = key.withUnsafeBytes { Data($0) }
        let added = SecItemAdd(item as CFDictionary, nil)
        if added == errSecDuplicateItem { return try load(create: false) }
        guard added == errSecSuccess else { throw AccountVaultError.key }; return key
    }
}

/// Descriptor-relative I/O; no traversal through a symlink, hardlink or special file.
private final class AccountDirectory {
    static let limit = 8 * 1024 * 1024
    let fd: Int32
    let root: URL
    init(_ url: URL) throws {
        guard url.standardizedFileURL.path == url.resolvingSymlinksInPath().path else { throw AccountVaultError.unsafe }
        root = url
        fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw AccountVaultError.unsafe }
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { close(fd); throw AccountVaultError.unsafe }
    }
    deinit { close(fd) }
    func names() throws -> [String] {
        let descriptor = openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard descriptor >= 0 else { throw AccountVaultError.unsafe }
        guard let directory = fdopendir(descriptor) else { close(descriptor); throw AccountVaultError.unsafe }
        defer { closedir(directory) }
        var names: [String] = []
        while true {
            errno = 0
            guard let entry = readdir(directory) else {
                guard errno == 0 else { throw AccountVaultError.unsafe }; return names
            }
            let name = withUnsafePointer(to: &entry.pointee.d_name) {
                $0.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { names.append(name) }
            guard names.count <= 4096 else { throw AccountVaultError.size }
        }
    }
    func parent(_ name: String) throws -> (Int32, String) {
        let parts = name.split(separator: "/", omittingEmptySubsequences: false)
        guard !parts.isEmpty, parts.allSatisfy({ !$0.isEmpty && $0 != "." && $0 != ".." }) else { throw AccountVaultError.unsafe }
        var current = fcntl(fd, F_DUPFD_CLOEXEC, 0); guard current >= 0 else { throw AccountVaultError.unsafe }
        for part in parts.dropLast() {
            let next = openat(current, String(part), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); close(current)
            guard next >= 0 else { throw AccountVaultError.unsafe }; current = next
            var info = stat()
            guard fstat(current, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else { close(current); throw AccountVaultError.unsafe }
        }
        return (current, String(parts.last!))
    }
    func read(_ name: String) throws -> Data? {
        let (directory, leaf) = try parent(name); defer { close(directory) }
        let file = openat(directory, leaf, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if file < 0 { if errno == ENOENT { return nil }; throw AccountVaultError.unsafe }
        defer { close(file) }; var before = stat()
        guard fstat(file, &before) == 0, before.st_uid == getuid(), before.st_mode & S_IFMT == S_IFREG,
              before.st_nlink == 1, before.st_mode & 0o022 == 0 else { throw AccountVaultError.unsafe }
        guard before.st_size >= 0, before.st_size <= Self.limit else { throw AccountVaultError.size }
        var output = Data(), buffer = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(file, &buffer, buffer.count)
            if count == 0 { break }; if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw AccountVaultError.unsafe }
            guard output.count + count <= Self.limit else { throw AccountVaultError.size }
            output.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard fstat(file, &after) == 0, before.st_size == after.st_size, output.count == before.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec, before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec, before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else { throw AccountVaultError.conflict }
        return output
    }
    func write(_ data: Data, name: String) throws {
        guard data.count <= Self.limit else { throw AccountVaultError.size }
        let (directory, leaf) = try parent(name); defer { close(directory) }
        let temporary = ".account-\(UUID().uuidString)"
        let file = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard file >= 0 else { throw AccountVaultError.unsafe }; defer { close(file) }
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let count = Darwin.write(file, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
                if count < 0 && errno == EINTR { continue }; guard count > 0 else { throw AccountVaultError.unsafe }; offset += count
            }
        }
        guard fsync(file) == 0, renameat(directory, temporary, directory, leaf) == 0, fsync(directory) == 0 else { throw AccountVaultError.unsafe }
    }
}

public struct AccountArchiveSummary: Codable, Identifiable {
    public let id: UUID
    public let name: String
    public let createdAt: Date
}
private struct IdentityDocument: Codable { let name: String; let present: Bool; let identity: Data }
private struct CredentialIdentity: Codable { let binding: CodeCredentialBinding; let fields: Data }
private struct IdentityArchive: Codable { let version: Int; let summary: AccountArchiveSummary; let documents: [IdentityDocument]; let credential: CredentialIdentity? }
private struct IdentityChange: Codable { let name: String; let before: Data; let after: Data }
private struct CredentialChange: Codable { let before: CodeCredentialSnapshot; let after: Data }
private struct IdentityJournal: Codable { let version: Int; let changes: [IdentityChange]; let credential: CredentialChange? }

/// Explicitly scoped foundation: no default home, no credential reads during UI polling.
/// Real Desktop/native Keychain switching is not exposed by this partial adapter.
public actor AccountVault {
    private let source: AccountDirectory
    private let vault: AccountDirectory
    private let binding: String
    private let keyProvider: (Bool) throws -> SymmetricKey
    private let idle: () throws -> Bool
    private let credentials: CodeCredentialStore?
    private let lock: Int32
    public init(sourceRoot: URL, vaultRoot: URL, keyProvider: @escaping (Bool) throws -> SymmetricKey,
                clientsIdle: @escaping () throws -> Bool, credentials: CodeCredentialStore? = nil) throws {
        source = try AccountDirectory(sourceRoot); vault = try AccountDirectory(vaultRoot)
        binding = fingerprintData(Data("\(getuid()):\(sourceRoot.standardizedFileURL.path)".utf8))
        self.keyProvider = keyProvider; idle = clientsIdle; self.credentials = credentials
        try credentials?.binding.validate()
        lock = openat(vault.fd, "operation.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        var info = stat()
        guard lock >= 0, fstat(lock, &info) == 0, info.st_uid == getuid(), info.st_mode & S_IFMT == S_IFREG,
              info.st_nlink == 1, info.st_mode & 0o077 == 0 else { if lock >= 0 { close(lock) }; throw AccountVaultError.unsafe }
    }
    deinit { close(lock) }
    private func exclusive<T>(requireIdle: Bool = true, _ body: () throws -> T) throws -> T {
        guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw AccountVaultError.busy }
        defer { flock(lock, LOCK_UN) }
        if requireIdle { guard try idle() else { throw AccountVaultError.busy } }
        return try body()
    }
    private func aad(_ purpose: String) -> Data { Data("ClaudeLauncherVault.v1:\(binding):\(purpose)".utf8) }
    private func seal<T: Encodable>(_ value: T, purpose: String, key: SymmetricKey) throws -> Data {
        let bytes = try JSONEncoder().encode(value)
        guard bytes.count < AccountDirectory.limit - 28 else { throw AccountVaultError.size }
        guard let result = try AES.GCM.seal(bytes, using: key, authenticating: aad(purpose)).combined else { throw AccountVaultError.invalid }
        return result
    }
    private func unseal<T: Decodable>(_ type: T.Type, data: Data, purpose: String, key: SymmetricKey) throws -> T {
        do { return try JSONDecoder().decode(type, from: AES.GCM.open(.init(combined: data), using: key, authenticating: aad(purpose))) }
        catch { throw AccountVaultError.invalid }
    }
    private func journal(_ key: SymmetricKey) throws -> IdentityJournal? {
        guard let bytes = try vault.read("transaction.sealed"), !bytes.isEmpty else { return nil }
        let record = try unseal(IdentityJournal.self, data: bytes, purpose: "journal", key: key)
        try validateJournal(record)
        return record
    }
    private func validVersion(_ version: Int, hasCredential: Bool) -> Bool { version == (hasCredential ? 2 : 1) }
    private func validateJournal(_ record: IdentityJournal) throws {
        guard validVersion(record.version, hasCredential: record.credential != nil),
              (record.credential != nil) == (credentials != nil),
              Set(record.changes.map(\.name)).count == record.changes.count,
              record.changes.allSatisfy({ AccountFields.files.contains($0.name) }) else { throw AccountVaultError.invalid }
        if let item = record.credential {
            guard item.before.binding == credentials?.binding, !item.before.persistentReference.isEmpty,
                  item.before.value.count <= 1024 * 1024, item.after.count <= 1024 * 1024 else { throw AccountVaultError.invalid }
            let identity = try AccountFields.selected(item.after, file: ".claude/.credentials.json")
            guard try AccountFields.merge(item.before.value, with: identity, file: ".claude/.credentials.json") == item.after else { throw AccountVaultError.invalid }
        }
    }
    public func capture(name: String) throws -> AccountArchiveSummary {
        try exclusive {
            let clean = name.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !clean.isEmpty, clean.count <= 80, !clean.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains) else { throw AccountVaultError.invalid }
            let existing = try vault.names().contains { $0 != "operation.lock" }
            let key = try keyProvider(!existing)
            guard try journal(key) == nil else { throw AccountVaultError.recovery }
            let native = try credentials?.snapshot()
            var docs: [IdentityDocument] = []
            var originals: [(String, Data?)] = []
            for file in AccountFields.files {
                let data = try source.read(file)
                originals.append((file, data))
                docs.append(.init(name: file, present: data != nil, identity: try AccountFields.selected(data ?? Data("{}".utf8), file: file)))
            }
            guard try idle() else { throw AccountVaultError.busy }
            for (file, data) in originals { guard try source.read(file) == data else { throw AccountVaultError.conflict } }
            if let native { guard try credentials?.snapshot() == native else { throw AccountVaultError.conflict } }
            let identity = try native.map { CredentialIdentity(binding: $0.binding, fields: try AccountFields.selected($0.value, file: ".claude/.credentials.json")) }
            let summary = AccountArchiveSummary(id: UUID(), name: clean, createdAt: Date())
            let data = try seal(IdentityArchive(version: identity == nil ? 1 : 2, summary: summary, documents: docs, credential: identity), purpose: summary.id.uuidString, key: key)
            try vault.write(Data([1]), name: "initialized")
            try vault.write(data, name: summary.id.uuidString + ".account")
            return summary
        }
    }
    public func restore(id: UUID) throws {
        try exclusive {
            let key = try keyProvider(false)
            guard try journal(key) == nil else { throw AccountVaultError.recovery }
            guard let bytes = try vault.read(id.uuidString + ".account") else { throw AccountVaultError.invalid }
            let archive = try unseal(IdentityArchive.self, data: bytes, purpose: id.uuidString, key: key)
            guard validVersion(archive.version, hasCredential: archive.credential != nil), archive.summary.id == id,
                  archive.documents.map(\.name).sorted() == AccountFields.files.sorted(),
                  (archive.credential != nil) == (credentials != nil) else { throw AccountVaultError.invalid }
            var nativeChange: CredentialChange?
            if let identity = archive.credential {
                guard let credentials, credentials.binding == identity.binding else { throw AccountVaultError.invalid }
                let before = try credentials.snapshot()
                nativeChange = .init(before: before, after: try AccountFields.merge(before.value, with: identity.fields, file: ".claude/.credentials.json"))
            }
            var changes: [IdentityChange] = []
            for document in archive.documents {
                let before = try source.read(document.name)
                guard (before != nil) == document.present else { throw AccountVaultError.existence }
                if let before { changes.append(.init(name: document.name, before: before, after: try AccountFields.merge(before, with: document.identity, file: document.name))) }
            }
            let record = IdentityJournal(version: nativeChange == nil ? 1 : 2, changes: changes, credential: nativeChange)
            try validateJournal(record)
            let sealed = try seal(record, purpose: "journal", key: key)
            // Keep an encrypted pre-change backup after commit as well as the recovery journal.
            try vault.write(sealed, name: "backup-\(UUID().uuidString).sealed")
            try vault.write(sealed, name: "transaction.sealed")
            do {
                if let item = nativeChange { guard try credentials?.snapshot() == item.before else { throw AccountVaultError.conflict } }
                for change in changes {
                    guard try idle(), try source.read(change.name) == change.before else { throw AccountVaultError.conflict }
                    try source.write(change.after, name: change.name)
                }
                if let item = nativeChange {
                    guard try idle(), let credentials else { throw AccountVaultError.busy }
                    try credentials.update(expected: item.before, value: item.after)
                }
                if let item = nativeChange { guard try credentials?.snapshot() == item.before.replacing(item.after) else { throw AccountVaultError.conflict } }
                for change in changes { guard try source.read(change.name) == change.after else { throw AccountVaultError.conflict } }
                guard try idle() else { throw AccountVaultError.busy }
            } catch {
                do { try rollback(record) } catch { throw AccountVaultError.recovery }
                throw error
            }
            // Commit marker failure must never trigger rollback after the durable journal may be empty.
            try vault.write(Data(), name: "transaction.sealed")
        }
    }
    public func archives() throws -> [AccountArchiveSummary] {
        try exclusive(requireIdle: false) {
            let names = try vault.names().filter { $0.hasSuffix(".account") }
            guard !names.isEmpty else { return [] }
            let key = try keyProvider(false)
            return try names.map { name in
                guard let id = UUID(uuidString: String(name.dropLast(8))), let bytes = try vault.read(name) else { throw AccountVaultError.invalid }
                let archive = try unseal(IdentityArchive.self, data: bytes, purpose: id.uuidString, key: key)
                guard validVersion(archive.version, hasCredential: archive.credential != nil), archive.summary.id == id else { throw AccountVaultError.invalid }
                return archive.summary
            }.sorted { $0.createdAt > $1.createdAt }
        }
    }
    public func backups() throws -> [UUID] {
        try exclusive(requireIdle: false) {
            try vault.names().filter { $0.hasPrefix("backup-") && $0.hasSuffix(".sealed") }.map { name in
                guard let id = UUID(uuidString: String(name.dropFirst(7).dropLast(7))) else { throw AccountVaultError.invalid }; return id
            }
        }
    }
    public func restoreBackup(id: UUID) throws {
        try exclusive {
            let key = try keyProvider(false)
            guard try journal(key) == nil else { throw AccountVaultError.recovery }
            guard let bytes = try vault.read("backup-\(id.uuidString).sealed") else { throw AccountVaultError.invalid }
            let record = try unseal(IdentityJournal.self, data: bytes, purpose: "journal", key: key)
            try validateJournal(record)
            try validateRollback(record)
            // Recovery remains possible if rollback is interrupted.
            try vault.write(bytes, name: "transaction.sealed")
            try rollback(record)
        }
    }
    public func recover() throws {
        try exclusive {
            guard let bytes = try vault.read("transaction.sealed"), !bytes.isEmpty else { return }
            if let record = try journal(keyProvider(false)) { try rollback(record) }
        }
    }
    private func validateRollback(_ record: IdentityJournal) throws {
        try validateJournal(record)
        for change in record.changes {
            let current = try source.read(change.name)
            guard current == change.before || current == change.after else { throw AccountVaultError.conflict }
        }
        if let item = record.credential {
            let current = try credentials?.snapshot()
            guard current == item.before || current == item.before.replacing(item.after) else { throw AccountVaultError.conflict }
        }
    }
    private func rollback(_ record: IdentityJournal) throws {
        try validateRollback(record)
        if let item = record.credential {
            guard try idle(), let credentials else { throw AccountVaultError.busy }
            let current = try credentials.snapshot()
            if current != item.before {
                guard current == item.before.replacing(item.after) else { throw AccountVaultError.conflict }
                try credentials.update(expected: current, value: item.before.value)
            }
        }
        for change in record.changes.reversed() {
            guard try idle() else { throw AccountVaultError.busy }
            let current = try source.read(change.name)
            if current == change.before { continue }; guard current == change.after else { throw AccountVaultError.conflict }
            try source.write(change.before, name: change.name)
        }
        for change in record.changes { guard try source.read(change.name) == change.before else { throw AccountVaultError.conflict } }
        if let item = record.credential { guard try credentials?.snapshot() == item.before else { throw AccountVaultError.conflict } }
        guard try idle() else { throw AccountVaultError.busy }
        try vault.write(Data(), name: "transaction.sealed")
    }
}
