import Foundation

/// Pre-authorization identity. It carries no PF evidence or permission to forward.
public struct ConnectorHoldBinding: Codable, Equatable, Sendable {
    public let id: UUID
    let gatewayInstance: UUID
    let configurationDigest: String
    let initialEpoch: UInt64

    public init?(snapshot: ConnectorSnapshot) {
        guard snapshot.holdProtocol == 1, snapshot.transactionProtocol == 2,
              snapshot.gatewayLifetime != nil, snapshot.isCurrent(),
              PFControlContext.hex(snapshot.configDigest, length: 64), snapshot.epoch < UInt64.max else { return nil }
        id = UUID(); gatewayInstance = snapshot.instanceID
        configurationDigest = snapshot.configDigest; initialEpoch = snapshot.epoch
    }
    var valid: Bool { PFControlContext.hex(configurationDigest, length: 64) && initialEpoch < UInt64.max }
    func matches(_ transaction: ConnectorTransactionBinding) -> Bool {
        transaction.id == id && transaction.gatewayInstance == gatewayInstance &&
            transaction.configurationDigest == configurationDigest && transaction.initialEpoch == initialEpoch
    }
}

public struct ConnectorHoldStatus: Codable, Equatable, Sendable {
    public let id: UUID
    public let phase: String
    public var drainPending = false
}

/// Has no expiry that could remove the fence. Only an explicit terminal leave releases it.
struct ConnectorHold {
    let binding: ConnectorHoldBinding
    let effectiveEpoch: UInt64
    private(set) var phase = "holding"
    private(set) var attachment: ConnectorTransactionBinding?
    var fenced: Bool { phase != "released" }
    var terminal: Bool { ["interrupted", "cancelled"].contains(phase) }
    var status: ConnectorHoldStatus { .init(id: binding.id, phase: phase) }
    mutating func drained() { if phase == "holding" { phase = "held" } }
    mutating func attach(_ transaction: ConnectorTransactionBinding) -> Bool {
        if let attachment { return phase == "attached" && attachment == transaction }
        guard phase == "held", transaction.valid, binding.matches(transaction) else { return false }
        attachment = transaction; phase = "attached"; return true
    }
    mutating func interrupt() { if fenced && !terminal { phase = "interrupted" } }
    mutating func cancel() { if fenced { phase = "cancelling" } }
    mutating func cancelled() { if phase == "cancelling" { phase = "cancelled" } }
    mutating func leave() -> Bool {
        guard terminal else { return false }; phase = "leaving"; return true
    }
    mutating func released() { if phase == "leaving" { phase = "released" } }
}

public enum ConnectorHoldAction: String, Codable, Sendable { case hold, status, prepare, commit, cancel, leave }

/// v2 is a separate action-dependent envelope; v1 retains its mandatory PF binding.
public struct ConnectorHoldRequest: Codable, Equatable, Sendable {
    public let version: Int
    public let commandID: UUID
    public let action: ConnectorHoldAction
    public let hold: ConnectorHoldBinding
    public let binding: ConnectorTransactionBinding?
    public init(action: ConnectorHoldAction, hold: ConnectorHoldBinding, binding: ConnectorTransactionBinding? = nil) {
        version = 2; commandID = UUID(); self.action = action; self.hold = hold; self.binding = binding
    }
    var valid: Bool {
        guard version == 2, hold.valid else { return false }
        if action == .prepare || action == .commit {
            return binding.map { $0.valid && hold.matches($0) } == true
        }
        return binding == nil
    }
    private enum Field: String, CodingKey { case version, commandID, action, hold, binding }
    public init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: Field.self)
        version = try fields.decode(Int.self, forKey: .version)
        commandID = try fields.decode(UUID.self, forKey: .commandID)
        action = try fields.decode(ConnectorHoldAction.self, forKey: .action)
        let hasBinding = action == .prepare || action == .commit
        try ConnectorSchema.keys(decoder, hasBinding ? ["version", "commandID", "action", "hold", "binding"] :
                                 ["version", "commandID", "action", "hold"])
        let root = try decoder.container(keyedBy: ConnectorSchema.Key.self)
        try ConnectorSchema.identity(root.superDecoder(forKey: .init("hold")), pf: false)
        hold = try fields.decode(ConnectorHoldBinding.self, forKey: .hold)
        if hasBinding {
            try ConnectorSchema.identity(root.superDecoder(forKey: .init("binding")), pf: true)
            binding = try fields.decode(ConnectorTransactionBinding.self, forKey: .binding)
        } else { binding = nil }
        guard valid else { throw ConnectorSchema.invalid(decoder) }
    }
}

enum ConnectorSchema {
    struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init(_ value: String) { stringValue = value }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }
    static func invalid(_ decoder: Decoder) -> DecodingError {
        .dataCorrupted(.init(codingPath: decoder.codingPath, debugDescription: "Invalid recovery record"))
    }
    static func keys(_ decoder: Decoder, _ expected: Set<String>) throws {
        guard Set(try decoder.container(keyedBy: Key.self).allKeys.map(\.stringValue)) == expected else { throw invalid(decoder) }
    }
    static func identity(_ decoder: Decoder, pf: Bool) throws {
        var fields: Set<String> = ["id", "gatewayInstance", "configurationDigest", "initialEpoch"]
        if pf { fields.insert("pf") }; try keys(decoder, fields)
        if pf {
            let nested = try decoder.container(keyedBy: Key.self).superDecoder(forKey: .init("pf"))
            try keys(nested, ["requestID", "expectedRevision", "planID", "planSHA256", "runtimeSHA256", "serviceInstance", "generation", "receivedNotBefore"])
        }
    }
}

public struct ConnectorHoldReply: Codable, Sendable {
    public let version: Int
    public let commandID: UUID
    public let holdID: UUID
    public let accepted: Bool
    public let reason: String
    public let operation: String
    public let localWorkPending: Bool
    public let snapshot: ConnectorSnapshot
}
