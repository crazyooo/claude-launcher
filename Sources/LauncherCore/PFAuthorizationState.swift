import Foundation

/// One atomic file contains both identities. No result or automatic continuation is persisted.
public struct PFAuthorizationState: Codable, Equatable {
    public let authorization: PFAuthorizationIntent?
    public let recovery: RecoveryOperationIntent?
    init(authorization: PFAuthorizationIntent?, recovery: RecoveryOperationIntent?) {
        self.authorization = authorization; self.recovery = recovery
    }
    var valid: Bool {
        guard authorization != nil || recovery != nil, recovery?.valid ?? true else { return false }
        guard let recovery, recovery.active, let request = recovery.request else { return true }
        return authorization?.request == request && authorization?.executionID == recovery.executionID
    }
    private enum Field: String, CodingKey { case version, authorization, recovery }
    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: Field.self)
        let version = try fields.decode(Int.self, forKey: .version)
        if version == 1 {
            authorization = try PFAuthorizationIntent(from: decoder); recovery = nil
        } else {
            guard version == 2 else { throw ConnectorSchema.invalid(decoder) }
            try ConnectorSchema.keys(decoder, ["version", "authorization", "recovery"])
            authorization = try fields.decodeIfPresent(PFAuthorizationIntent.self, forKey: .authorization)
            recovery = try fields.decodeIfPresent(RecoveryOperationIntent.self, forKey: .recovery)
        }
        guard valid else { throw ConnectorSchema.invalid(decoder) }
    }
    public func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: Field.self)
        try fields.encode(2, forKey: .version); try fields.encode(authorization, forKey: .authorization)
        try fields.encode(recovery, forKey: .recovery)
    }
}
