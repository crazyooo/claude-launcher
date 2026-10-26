import Foundation
import Security

public struct CodeCredentialBinding: Codable, Equatable {
    public let service: String
    public let account: String
    public let keychainPath: String
    public init(account: String, keychainPath: String) {
        self.service = "Claude Code-credentials"; self.account = account; self.keychainPath = keychainPath
    }
    func validate() throws {
        guard service == "Claude Code-credentials", !account.isEmpty, account.utf8.count <= 1024,
              !account.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains),
              keychainPath.hasPrefix("/") else { throw AccountVaultError.invalid }
    }
}
/// Secret data; only the encrypted archive/journal layer may serialize this.
public struct CodeCredentialSnapshot: Codable, Equatable {
    public let binding: CodeCredentialBinding
    public let persistentReference: Data
    public let value: Data
    public init(binding: CodeCredentialBinding, persistentReference: Data, value: Data) {
        self.binding = binding; self.persistentReference = persistentReference; self.value = value
    }
    func replacing(_ data: Data) -> Self { .init(binding: binding, persistentReference: persistentReference, value: data) }
}
public protocol CodeCredentialStore {
    var binding: CodeCredentialBinding { get }
    func snapshot() throws -> CodeCredentialSnapshot
    func update(expected: CodeCredentialSnapshot, value: Data) throws
}
/// Explicit keychain and account; construction never reads the secret. Existing
/// items are updated in place so their access control is not silently replaced.
public final class NativeCodeCredentialStore: CodeCredentialStore {
    public let binding: CodeCredentialBinding
    private let keychain: SecKeychain
    public init(keychain: SecKeychain, account: String) throws {
        var count: UInt32 = 4096, path = [CChar](repeating: 0, count: 4096)
        guard SecKeychainGetPath(keychain, &count, &path) == errSecSuccess else { throw AccountVaultError.key }
        self.keychain = keychain; binding = .init(account: account, keychainPath: String(cString: path)); try binding.validate()
    }
    public func snapshot() throws -> CodeCredentialSnapshot {
        let attributes: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: binding.service, kSecAttrAccount as String: binding.account,
            kSecAttrSynchronizable as String: false, kSecMatchSearchList as String: [keychain],
            kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnAttributes as String: true,
            kSecReturnPersistentRef as String: true]
        var result: CFTypeRef?
        guard SecItemCopyMatching(attributes as CFDictionary, &result) == errSecSuccess,
              let rows = result as? [[String: Any]], rows.count == 1, let row = rows.first,
              row[kSecAttrService as String] as? String == binding.service,
              row[kSecAttrAccount as String] as? String == binding.account,
              let reference = row[kSecValuePersistentRef as String] as? Data, !reference.isEmpty else { throw AccountVaultError.key }
        let query: [String: Any] = [kSecValuePersistentRef as String: reference, kSecReturnAttributes as String: true, kSecReturnData as String: true]
        result = nil
        guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
              let record = result as? [String: Any], record[kSecAttrService as String] as? String == binding.service,
              record[kSecAttrAccount as String] as? String == binding.account,
              let value = record[kSecValueData as String] as? Data, value.count <= 1024 * 1024 else { throw AccountVaultError.key }
        _ = try AccountFields.object(value)
        return .init(binding: binding, persistentReference: reference, value: value)
    }
    public func update(expected: CodeCredentialSnapshot, value: Data) throws {
        guard expected.binding == binding, value.count <= 1024 * 1024, try snapshot() == expected else { throw AccountVaultError.conflict }
        _ = try AccountFields.object(value)
        let query = [kSecValuePersistentRef as String: expected.persistentReference]
        guard SecItemUpdate(query as CFDictionary, [kSecValueData as String: value] as CFDictionary) == errSecSuccess else { throw AccountVaultError.key }
        guard try snapshot() == expected.replacing(value) else { throw AccountVaultError.conflict }
    }
}
