import Foundation
import Security
import Darwin

/// Created only after the user selects Connect. Discovery reads attributes,
/// while credential contents are reserved for explicit archive transactions.
public enum CodeAccountConnection {
    public static func connect() throws -> AccountVault {
        var keychain: SecKeychain?
        guard SecKeychainCopyDefault(&keychain) == errSecSuccess, let keychain else { throw AccountVaultError.key }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "Claude Code-credentials", kSecAttrSynchronizable as String: false,
            kSecMatchSearchList as String: [keychain], kSecMatchLimit as String: kSecMatchLimitAll,
            kSecReturnAttributes as String: true]
        var result: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let rows = result as? [[String: Any]], rows.count == 1, let row = rows.first,
              row[kSecAttrService as String] as? String == "Claude Code-credentials",
              let account = row[kSecAttrAccount as String] as? String, !account.isEmpty else {
            throw LauncherError.message("未找到唯一的默认 Claude Code 钥匙串凭据，未连接账号资料。")
        }
        let store = try NativeCodeCredentialStore(keychain: keychain, account: account)
        try ConnectorIPC.privateDirectory(create: true)
        let directory = Paths.root.appendingPathComponent("code-account-vault")
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            guard errno == ENOENT else { throw AccountVaultError.unsafe }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        guard lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw AccountVaultError.unsafe }
        return try AccountVault(sourceRoot: FileManager.default.homeDirectoryForCurrentUser,
            vaultRoot: directory, keyProvider: { try AccountMasterKey.load(create: $0) },
            clientsIdle: { try clientsAreIdle() }, credentials: store)
    }

    static func clientsAreIdle() throws -> Bool {
        let output = ReadCommand.run("/bin/ps", ["-ww", "-axo", "uid=,comm="], timeout: 5)
        guard output.code == 0 else { throw AccountVaultError.busy }
        return try processListIsIdle(output.text, uid: getuid())
    }

    /// Process names only: never arguments. Ambiguous Node/Bun workloads are
    /// rejected because legacy npm Claude can share their executable name.
    static func processListIsIdle(_ text: String, uid: UInt32) throws -> Bool {
        guard !text.isEmpty, text.utf8.count < 131072, text.hasSuffix("\n") else { throw AccountVaultError.busy }
        var ownProcess = false
        for line in text.split(whereSeparator: \.isNewline) {
            let columns = line.split(maxSplits: 1, whereSeparator: { $0 == " " || $0 == "\t" })
            guard columns.count == 2, let owner = UInt32(columns[0]) else { throw AccountVaultError.busy }
            guard owner == uid else { continue }; ownProcess = true
            let path = String(columns[1]).lowercased()
            let name = URL(fileURLWithPath: path).lastPathComponent
            if ["claude", "code"].contains(name) || name.hasPrefix("claude helper") || name.hasPrefix("code helper") ||
                path.contains("/claude.app/") || path.contains("/visual studio code.app/") ||
                path.contains("/visual studio code - insiders.app/") || path.contains("/.local/share/claude/versions/") ||
                path.contains("/@anthropic-ai/claude-code/") { return false }
            if ["node", "nodejs", "bun"].contains(name) {
                throw LauncherError.message("发现 Node/Bun 进程，无法排除旧版 Claude Code 占用。请先退出相关终端任务。")
            }
        }
        guard ownProcess else { throw AccountVaultError.busy }; return true
    }
}
