import Foundation

/// Redacted, durable router operation events. Never stores secrets, credentials,
/// raw proxy passwords, or full configuration bodies.
public enum RouterEventKind: String, Codable, CaseIterable, Sendable {
    case prepareRequested
    case prepareRefused
    case prepareReady
    case applyRequested
    case applyOutcome
    case stopRequested
    case stopOutcome
    case coexistenceInspected
    case hitCorrelationArmed
    case hitCorrelationDisarmed
    case hitCorrelationRunRequested
    case hitCorrelationRunOutcome
    case hitCorrelationRefused
    case matrixLiveRun
    case matrixLiveRefused
    case matrixLoopbackFillRequested
    case pfArmingPreviewNoted
    case pfArmingRefused
    case pfArmingExecuteArmed
    case pfArmingExecuteConfirmed
    case pfArmingExecuteOutcome
    case pfArmingExecuteRefused
    case failClosedProofEnumerated
    case rollbackPreviewNoted
    case rollbackExecuteArmed
    case rollbackExecuteConfirmed
    case rollbackExecuteOutcome
    case rollbackExecuteRefused
    case rollbackRestoreReported
    case faultAcceptanceEnumerated
    case tunApplyPreviewNoted
    case tunApplyExecuteArmed
    case tunApplyExecuteConfirmed
    case tunApplyExecuteOutcome
    case tunApplyExecuteRefused
    case appTrafficAttestationRun
    case appTrafficAttestationRefused
    case storageFailed
}

public struct RouterEventEntry: Codable, Identifiable, Equatable, Sendable {
    public let id: UUID
    public let at: Date
    public let kind: RouterEventKind
    public let summary: String
    public let detail: String
    public let instancePrefix: String?
    public let digestPrefix: String?
    public let routingVerified: Bool
    public let accepted: Bool

    public init(kind: RouterEventKind, summary: String, detail: String = "",
                instance: UUID? = nil, digest: String? = nil, at: Date = Date()) {
        id = UUID()
        self.at = at
        self.kind = kind
        self.summary = Self.redact(summary)
        self.detail = Self.redact(detail)
        instancePrefix = instance.map { String($0.uuidString.prefix(8)) }
        digestPrefix = digest.flatMap { value in
            guard value.count >= 12 else { return nil }
            return String(value.prefix(12))
        }
        routingVerified = false
        accepted = false
    }

    /// Strip credential-like tokens and over-long blobs before persistence.
    public static func redact(_ text: String) -> String {
        var value = text
        let patterns = [
            #"password\s*[:=]\s*\S+"#,
            #"passwd\s*[:=]\s*\S+"#,
            #"secret\s*[:=]\s*\S+"#,
            #"token\s*[:=]\s*\S+"#,
            #"Authorization:\s*\S+"#,
            #"[A-Za-z0-9+/]{80,}={0,2}"#
        ]
        for pattern in patterns {
            if let regex = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) {
                let range = NSRange(value.startIndex..<value.endIndex, in: value)
                value = regex.stringByReplacingMatches(in: value, options: [], range: range, withTemplate: "[redacted]")
            }
        }
        if value.count > 480 { value = String(value.prefix(477)) + "..." }
        return value
    }
}

/// Bounded JSON event log under the user app support root. Atomic replace; corrupt files preserved by failing closed.
public final class RouterEventLog: @unchecked Sendable {
    public static let capacity = 2 * 1024 * 1024
    public static let fileName = "router-events.json"
    public let root: URL
    private let limit: Int
    private let lock = NSLock()

    public init(root: URL = Paths.root, capacity: Int = RouterEventLog.capacity) {
        self.root = root
        limit = max(1024, min(capacity, Self.capacity))
    }

    public func entries() throws -> [RouterEventEntry] {
        lock.lock(); defer { lock.unlock() }
        return try read() ?? []
    }

    public func append(_ entry: RouterEventEntry) throws {
        try append([entry])
    }

    public func append(_ additions: [RouterEventEntry]) throws {
        lock.lock(); defer { lock.unlock() }
        try EnvironmentStorage.withLock(at: root.appendingPathComponent("router-events.lock")) {
            var entries = try read() ?? []
            entries.append(contentsOf: additions)
            let encoder = JSONEncoder()
            encoder.dateEncodingStrategy = .iso8601
            var data = try encoder.encode(entries)
            while data.count > limit && entries.count > 1 {
                entries.removeFirst(max(1, entries.count / 8))
                data = try encoder.encode(entries)
            }
            guard data.count <= limit else {
                throw LauncherError.message("路由事件日志超过容量限制。")
            }
            try EnvironmentStorage.writeBytes(data, to: root.appendingPathComponent(Self.fileName),
                                              maximum: Self.capacity)
        }
    }

    public func record(kind: RouterEventKind, summary: String, detail: String = "",
                       instance: UUID? = nil, digest: String? = nil) {
        do {
            try append(.init(kind: kind, summary: summary, detail: detail, instance: instance, digest: digest))
        } catch {
            // Best-effort secondary note; never throw into UI action paths.
            try? append(.init(kind: .storageFailed, summary: "路由事件写入失败", detail: "storage_failed"))
        }
    }

    private func read() throws -> [RouterEventEntry]? {
        guard let data = try EnvironmentStorage.readBytes(root.appendingPathComponent(Self.fileName),
                                                          maximum: Self.capacity) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try decoder.decode([RouterEventEntry].self, from: data)
    }
}
