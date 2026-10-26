import Foundation

/// Cancellation linearizes with the single nonblocking START write, never with filesystem I/O.
public final class PFAuthorizationStartPermit: @unchecked Sendable {
    private let lock = NSLock()
    private var cancelled = false
    public init() {}
    public func cancel() { lock.lock(); cancelled = true; lock.unlock() }
    func send(_ body: () throws -> Void) throws {
        lock.lock(); defer { lock.unlock() }
        guard !cancelled else { throw PFAuthorizationGate.failure }
        // Single use even when writing fails or is only partial.
        cancelled = true
        try body()
    }
}

/// Persist before spawning; replace with `armed` and fsync before sending START.
/// No result or permission is persisted here. An armed record remains uncertain after a crash.
public struct PFAuthorizationIntent: Codable, Equatable {
    public let request: PFRecoveryRequest
    public let executionID: UUID
    public let identity: PFAuthorizationExecutionIdentity?
    public let startMayHaveBeenSent: Bool

    public init(request: PFRecoveryRequest, executionID: UUID) {
        self.request = request; self.executionID = executionID
        identity = nil; startMayHaveBeenSent = false
    }
    private init(request: PFRecoveryRequest, executionID: UUID, identity: PFAuthorizationExecutionIdentity) {
        self.request = request; self.executionID = executionID; self.identity = identity
        startMayHaveBeenSent = true
    }
    func armed(with identity: PFAuthorizationExecutionIdentity) throws -> Self {
        guard !startMayHaveBeenSent, self.identity == nil, identity.executionID == executionID, identity.valid else {
            throw PFAuthorizationGate.failure
        }
        return .init(request: request, executionID: executionID, identity: identity)
    }
    private enum CodingKeys: String, CodingKey { case version, request, executionID, identity, startMayHaveBeenSent }
    public init(from decoder: Decoder) throws {
        try ConnectorSchema.keys(decoder, ["version", "request", "executionID", "identity", "startMayHaveBeenSent"])
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        guard try fields.decode(Int.self, forKey: .version) == 1 else { throw ConnectorSchema.invalid(decoder) }
        request = try fields.decode(PFRecoveryRequest.self, forKey: .request)
        executionID = try fields.decode(UUID.self, forKey: .executionID)
        identity = try fields.decodeIfPresent(PFAuthorizationExecutionIdentity.self, forKey: .identity)
        startMayHaveBeenSent = try fields.decode(Bool.self, forKey: .startMayHaveBeenSent)
        guard startMayHaveBeenSent == (identity != nil), identity.map({ $0.executionID == executionID }) ?? true else {
            throw ConnectorSchema.invalid(decoder)
        }
    }
    public func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        try fields.encode(1, forKey: .version); try fields.encode(request, forKey: .request)
        try fields.encode(executionID, forKey: .executionID)
        try fields.encode(identity, forKey: .identity)
        try fields.encode(startMayHaveBeenSent, forKey: .startMayHaveBeenSent)
    }
}
