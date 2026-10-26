import Foundation

public enum ConnectorControlAction: String, Codable, Sendable {
    case prepare, status, commit, cancel, leave
}

/// Public requests select an operation. Tokens, samples and PF proofs never come from this interface.
public struct ConnectorControlRequest: Codable, Sendable {
    public let version: Int
    public let commandID: UUID
    public let action: ConnectorControlAction
    public let binding: ConnectorTransactionBinding

    public init(action: ConnectorControlAction, binding: ConnectorTransactionBinding) {
        version = 1; commandID = UUID(); self.action = action; self.binding = binding
    }
    private enum Field: String, CodingKey { case version, commandID, action, binding }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(_ value: String) { stringValue = value }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    public init(from decoder: Decoder) throws {
        let invalid = DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                       debugDescription: "Invalid connector control request"))
        let root = try decoder.container(keyedBy: Key.self)
        guard Set(root.allKeys.map(\.stringValue)) == ["version", "commandID", "action", "binding"] else { throw invalid }
        let transaction = try root.nestedContainer(keyedBy: Key.self, forKey: Key("binding"))
        guard Set(transaction.allKeys.map(\.stringValue)) == ["id", "gatewayInstance", "configurationDigest", "initialEpoch", "pf"] else { throw invalid }
        let pf = try transaction.nestedContainer(keyedBy: Key.self, forKey: Key("pf"))
        guard Set(pf.allKeys.map(\.stringValue)) == ["requestID", "expectedRevision", "planID", "planSHA256",
            "runtimeSHA256", "serviceInstance", "generation", "receivedNotBefore"] else { throw invalid }
        let fields = try decoder.container(keyedBy: Field.self)
        version = try fields.decode(Int.self, forKey: .version)
        commandID = try fields.decode(UUID.self, forKey: .commandID)
        action = try fields.decode(ConnectorControlAction.self, forKey: .action)
        binding = try fields.decode(ConnectorTransactionBinding.self, forKey: .binding)
        guard version == 1, binding.valid else { throw invalid }
    }
}

public struct ConnectorControlReply: Codable, Sendable {
    public let version: Int
    public let commandID: UUID
    public let transactionID: UUID
    public let accepted: Bool
    public let reason: String
    /// Local worker state; never substitutes for the observed Gateway snapshot below.
    public let operation: String
    public let localWorkPending: Bool
    public let snapshot: ConnectorSnapshot
}
