import Foundation

/// Ephemeral, internal only. Never Codable or passed to UI, IPC, or diagnostic logging.
struct RouterConnectionMaterial: Equatable {
    let secret: String
    let redactions: [String]

    static func read(_ object: [String: Any]) throws -> Self {
        guard let secret = object["secret"] as? String, RouterSystemProvider.validDigest(secret),
              let proxies = object["proxies"] as? [[String: Any]] else { throw RouterConnectionFailure.identityChanged }
        var values = [secret]
        for proxy in proxies {
            for key in ["username", "password"] {
                if let raw = proxy[key] {
                    guard let text = raw as? String else { throw RouterConnectionFailure.identityChanged }
                    if !text.isEmpty { values.append(text) }
                }
            }
        }
        return .init(secret: secret, redactions: Array(Set(values)).sorted())
    }
}
