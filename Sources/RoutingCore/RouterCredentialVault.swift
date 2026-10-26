import Foundation
import Security

public struct RouterCredential: Codable {
    public let username: String
    public let password: String
    public init(username: String, password: String) { self.username = username; self.password = password }
    public func validate() throws {
        guard !username.isEmpty, !password.isEmpty, username.utf8.count <= 1024, password.utf8.count <= 4096,
              !(username + password).unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw RouterCredentialError.invalid
        }
    }
}
public enum RouterCredentialError: Error { case invalid, unavailable }

/// Immutable entries preserve credentials referenced by saved plans and their previous version.
/// No automatic garbage collection: a failed save may already have committed its reference.
public enum RouterCredentialVault {
    public static func read(_ id: UUID) throws -> RouterCredential {
        try read(id, lookup: { query in
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        })
    }
    static func read(_ id: UUID, lookup: ([String: Any]) -> (OSStatus, Data?)) throws -> RouterCredential {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.claude-launcher.router-credential",
            kSecAttrAccount as String: id.uuidString.lowercased(),
            kSecReturnData as String: true, kSecMatchLimit as String: kSecMatchLimitOne
        ]
        let (status, data) = lookup(query)
        guard status == errSecSuccess, let data, data.count <= 32_768,
              let value = try? JSONDecoder().decode(RouterCredential.self, from: data) else {
            throw RouterCredentialError.unavailable
        }
        try value.validate()
        return value
    }
    public static func store(_ credential: RouterCredential) throws -> UUID {
        try store(credential, add: { SecItemAdd($0 as CFDictionary, nil) })
    }
    static func store(_ credential: RouterCredential, add: ([String: Any]) -> OSStatus) throws -> UUID {
        try credential.validate()
        let id = UUID()
        let attributes: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "local.claude-launcher.router-credential",
            kSecAttrAccount as String: id.uuidString.lowercased(),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: try JSONEncoder().encode(credential)
        ]
        guard add(attributes) == errSecSuccess else { throw RouterCredentialError.unavailable }
        return id
    }
}
