import Foundation

/// Expected installation identity captured before requesting administrator access.
/// It confers no network or launch permission.
public struct PFControlContext: Codable, Equatable {
    let plan_id, plan_sha256, runtime_sha256, service_instance: String
    let receipt_revision: Int64
    static let maximumRevision: Int64 = 9_007_199_254_740_991

    private enum Field: String, CodingKey, CaseIterable {
        case version, plan_id, plan_sha256, runtime_sha256, service_instance, receipt_revision
    }
    private struct Key: CodingKey {
        let stringValue: String
        var intValue: Int? { nil }
        init?(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { return nil }
    }

    public init(from decoder: Decoder) throws {
        let invalid = DecodingError.dataCorrupted(.init(codingPath: decoder.codingPath,
                                                       debugDescription: "Invalid PF control context"))
        let all = try decoder.container(keyedBy: Key.self)
        guard Set(all.allKeys.map(\.stringValue)) == Set(Field.allCases.map(\.rawValue)) else { throw invalid }
        let fields = try decoder.container(keyedBy: Field.self)
        guard try fields.decode(Int.self, forKey: .version) == 1 else { throw invalid }
        plan_id = try fields.decode(String.self, forKey: .plan_id)
        plan_sha256 = try fields.decode(String.self, forKey: .plan_sha256)
        runtime_sha256 = try fields.decode(String.self, forKey: .runtime_sha256)
        service_instance = try fields.decode(String.self, forKey: .service_instance)
        receipt_revision = try fields.decode(Int64.self, forKey: .receipt_revision)
        guard Self.hex(plan_id, length: 32), Self.hex(service_instance, length: 32),
              Self.hex(plan_sha256, length: 64), Self.hex(runtime_sha256, length: 64),
              (0...Self.maximumRevision).contains(receipt_revision) else { throw invalid }
    }

    public func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: Field.self)
        try fields.encode(1, forKey: .version)
        try fields.encode(plan_id, forKey: .plan_id)
        try fields.encode(plan_sha256, forKey: .plan_sha256)
        try fields.encode(runtime_sha256, forKey: .runtime_sha256)
        try fields.encode(service_instance, forKey: .service_instance)
        try fields.encode(receipt_revision, forKey: .receipt_revision)
    }

    static func hex(_ value: String, length: Int) -> Bool {
        value.utf8.count == length && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }

    func sameInstallation(as other: Self) -> Bool {
        plan_id == other.plan_id && plan_sha256 == other.plan_sha256 &&
            runtime_sha256 == other.runtime_sha256 && service_instance == other.service_instance
    }
}

/// Immutable identity reused after an unknown submission outcome.
public struct PFRecoveryRequest: Codable, Equatable {
    let id: String
    let context: PFControlContext
    let epoch: Int
    let createdAt: Date

    init(context: PFControlContext, epoch: Int, now: Date) {
        id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        self.context = context; self.epoch = epoch; createdAt = now
    }

    private enum CodingKeys: String, CodingKey { case id, context, epoch, createdAt }
    public init(from decoder: Decoder) throws {
        try ConnectorSchema.keys(decoder, ["id", "context", "epoch", "createdAt"])
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        id = try fields.decode(String.self, forKey: .id)
        context = try fields.decode(PFControlContext.self, forKey: .context)
        epoch = try fields.decode(Int.self, forKey: .epoch)
        createdAt = try fields.decode(Date.self, forKey: .createdAt)
        guard PFControlContext.hex(id, length: 32), epoch >= 0,
              context.receipt_revision < PFControlContext.maximumRevision,
              createdAt.timeIntervalSince1970.isFinite,
              (0...253_402_300_799).contains(createdAt.timeIntervalSince1970), createdAt.timeIntervalSince1970 > 0 else {
            throw ConnectorSchema.invalid(decoder)
        }
    }
}
