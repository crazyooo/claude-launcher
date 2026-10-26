import Foundation
import CoreFoundation

public enum RouterSystemError: String, Error {
    case invalidRequest, invalidPlan, invalidCredentials, conflict, stalePreview, networkConflict
    case operationUnsettled, ownershipUnknown, cleanupUnproven, journalUnknown, configurationRejected
}

public struct RouterSystemProfile: Codable, Equatable {
    public enum Resolver: String, Codable { case cloudflare, quad9, plain }
    public let resolver: Resolver
    public init(resolver: Resolver) { self.resolver = resolver }
}

/// Sensitive request-only value; never included in a reply or journal.
public struct RouterSystemCredential {
    public let reference: UUID
    public let value: RouterCredential
    public init(reference: UUID, value: RouterCredential) { self.reference = reference; self.value = value }
}

public enum RouterSystemRequest {
    case prepare(id: UUID, plan: RouterPlan, profile: RouterSystemProfile)
    case apply(id: UUID, credentials: [RouterSystemCredential])
    case status(id: UUID?)
    case stop(id: UUID)
    case previewEnvironment(id: UUID, review: UUID)
    case confirmEnvironment(id: UUID, review: UUID, digest: String)
}

public enum RouterSystemDecoder {
    public static func decode(_ data: Data) throws -> RouterSystemRequest {
        do {
            let object = try RouterStrictJSON.object(data)
            guard let version = object["version"] as? NSNumber,
                  CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1,
                  let action = object["action"] as? String else { throw RouterSystemError.invalidRequest }
            switch action {
            case "prepare":
                try keys(object, ["version", "action", "id", "plan", "profile"])
                guard let planObject = object["plan"] as? [String: Any],
                      let profile = object["profile"] as? [String: Any] else { throw RouterSystemError.invalidRequest }
                try keys(profile, ["resolver"])
                guard let text = profile["resolver"] as? String, let resolver = RouterSystemProfile.Resolver(rawValue: text) else { throw RouterSystemError.invalidRequest }
                let plan = try RouterInput.plan(JSONSerialization.data(withJSONObject: planObject))
                guard !RouterValidation.issues(in: plan).contains(where: { $0.severity == .error }) else { throw RouterSystemError.invalidPlan }
                return .prepare(id: try uuid(object["id"]), plan: plan, profile: .init(resolver: resolver))
            case "apply":
                try keys(object, ["version", "action", "id", "credentials"])
                guard let values = object["credentials"] as? [[String: Any]], values.count <= 128 else { throw RouterSystemError.invalidCredentials }
                let credentials = try values.map { item -> RouterSystemCredential in
                    try keys(item, ["reference", "username", "password"])
                    guard let username = item["username"] as? String, let password = item["password"] as? String else { throw RouterSystemError.invalidCredentials }
                    let credential = RouterCredential(username: username, password: password)
                    try credential.validate()
                    return .init(reference: try uuid(item["reference"]), value: credential)
                }
                guard Set(credentials.map(\.reference)).count == credentials.count else { throw RouterSystemError.invalidCredentials }
                return .apply(id: try uuid(object["id"]), credentials: credentials)
            case "status":
                guard Set(object.keys) == ["version", "action"] || Set(object.keys) == ["version", "action", "id"] else { throw RouterSystemError.invalidRequest }
                return .status(id: try object["id"].map(uuid))
            case "stop":
                try keys(object, ["version", "action", "id"])
                return .stop(id: try uuid(object["id"]))
            case "previewEnvironment":
                try keys(object, ["version", "action", "id", "review"])
                return .previewEnvironment(id: try uuid(object["id"]), review: try uuid(object["review"]))
            case "confirmEnvironment":
                try keys(object, ["version", "action", "id", "review", "digest"])
                guard let digest = object["digest"] as? String, RouterSystemProvider.validDigest(digest) else {
                    throw RouterSystemError.invalidRequest
                }
                return .confirmEnvironment(id: try uuid(object["id"]), review: try uuid(object["review"]), digest: digest)
            default: throw RouterSystemError.invalidRequest
            }
        } catch let error as RouterSystemError { throw error }
        catch { throw RouterSystemError.invalidRequest }
    }
    private static func keys(_ object: [String: Any], _ expected: Set<String>) throws {
        guard Set(object.keys) == expected else { throw RouterSystemError.invalidRequest }
    }
    private static func uuid(_ value: Any?) throws -> UUID {
        guard let text = value as? String, let id = UUID(uuidString: text) else { throw RouterSystemError.invalidRequest }
        return id
    }
}

/// Foundation parses values; a bounded lexical pass rejects duplicate object keys, including escaped equivalents.
/// The validated normalized object is the only object subsequently interpreted.
enum RouterStrictJSON {
    static func object(_ data: Data, maximumBytes: Int = RouterInput.maximumBytes, maximumValues: Int = 20_000) throws -> [String: Any] {
        guard data.count <= maximumBytes else { throw RouterSystemError.invalidRequest }
        var scanner = KeyScanner(bytes: Array(data), maximumValues: maximumValues)
        try scanner.value(depth: 0); scanner.space()
        guard scanner.offset == scanner.bytes.count,
              let value = try JSONSerialization.jsonObject(with: data) as? [String: Any] else { throw RouterSystemError.invalidRequest }
        return value
    }
    private struct KeyScanner {
        let bytes: [UInt8]
        let maximumValues: Int
        var offset = 0
        var count = 0
        mutating func space() { while offset < bytes.count && [9, 10, 13, 32].contains(bytes[offset]) { offset += 1 } }
        mutating func consume(_ byte: UInt8) throws {
            space(); guard offset < bytes.count, bytes[offset] == byte else { throw RouterSystemError.invalidRequest }; offset += 1
        }
        mutating func string() throws -> String {
            space(); let start = offset; try consume(34)
            while offset < bytes.count {
                let byte = bytes[offset]; offset += 1
                if byte == 92 { guard offset < bytes.count else { throw RouterSystemError.invalidRequest }; offset += 1 }
                else if byte == 34 {
                    guard let result = try JSONSerialization.jsonObject(with: Data(bytes[start..<offset]), options: [.fragmentsAllowed]) as? String else { throw RouterSystemError.invalidRequest }
                    return result
                }
            }
            throw RouterSystemError.invalidRequest
        }
        mutating func value(depth: Int) throws {
            count += 1; space()
            guard depth <= 20, count <= maximumValues, offset < bytes.count else { throw RouterSystemError.invalidRequest }
            switch bytes[offset] {
            case 123:
                offset += 1; space(); var seen = Set<String>()
                if offset < bytes.count, bytes[offset] == 125 { offset += 1; return }
                while true {
                    let key = try string()
                    guard seen.insert(key).inserted else { throw RouterSystemError.invalidRequest }
                    try consume(58); try value(depth: depth + 1); space()
                    guard offset < bytes.count else { throw RouterSystemError.invalidRequest }
                    if bytes[offset] == 125 { offset += 1; return }; try consume(44)
                }
            case 91:
                offset += 1; space()
                if offset < bytes.count, bytes[offset] == 93 { offset += 1; return }
                while true {
                    try value(depth: depth + 1); space()
                    guard offset < bytes.count else { throw RouterSystemError.invalidRequest }
                    if bytes[offset] == 93 { offset += 1; return }; try consume(44)
                }
            case 34: _ = try string()
            default:
                let start = offset
                while offset < bytes.count && ![9, 10, 13, 32, 44, 93, 125].contains(bytes[offset]) { offset += 1 }
                guard offset > start else { throw RouterSystemError.invalidRequest }
            }
        }
    }
}
