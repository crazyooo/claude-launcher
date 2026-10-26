import Foundation

/// A separate observation protocol: no credentials, endpoint, or executable supplied by the caller.
struct RouterConnectionQuery: Codable {
    let version: Int
    let action: String
    let request: UUID
    let instance: UUID?

    init(request: UUID, instance: UUID?) {
        version = 1; action = "connections"; self.request = request; self.instance = instance
    }
    static func decode(_ bytes: Data) throws -> Self {
        do {
            let object = try RouterStrictJSON.object(bytes, maximumBytes: 1024)
            let required: Set<String> = ["version", "action", "request"]
            guard Set(object.keys) == required || Set(object.keys) == required.union(["instance"]),
                  !(object["instance"] is NSNull) else { throw RouterConnectionFailure.invalidResponse }
            let query = try JSONDecoder().decode(Self.self, from: bytes)
            guard query.version == 1, query.action == "connections" else { throw RouterConnectionFailure.invalidResponse }
            return query
        } catch { throw RouterConnectionFailure.invalidResponse }
    }
}

enum RouterConnectionWire {
    private struct Failure: Codable {
        let version: Int
        let request: UUID
        let connectionError: RouterConnectionFailure
    }
    static func classify(_ error: Error) -> RouterConnectionFailure {
        if let failure = error as? RouterConnectionFailure { return failure }
        switch error {
        case RouterSystemClientError.unavailable: return .notInstalled
        case RouterSystemError.ownershipUnknown, RouterSystemError.conflict,
             RouterRuntimeError.ownershipUnknown, RouterRuntimeError.unsafeFile: return .identityChanged
        default: return .controllerUnavailable
        }
    }
    static func response(to query: RouterConnectionQuery,
                         read: () throws -> RouterConnectionSnapshot) throws -> Data {
        do {
            let sample = try read()
            try sample.validate(request: query.request, instance: query.instance, mode: .system,
                                now: Date(), uptime: ProcessInfo.processInfo.systemUptime)
            let bytes = try JSONEncoder().encode(sample)
            guard bytes.count <= RouterConnectionSnapshot.wireLimit else { throw RouterConnectionFailure.responseTooLarge }
            return bytes
        } catch {
            return try JSONEncoder().encode(Failure(version: 1, request: query.request, connectionError: classify(error)))
        }
    }
    static func decode(_ bytes: Data, query: RouterConnectionQuery,
                       now: Date = Date(), uptime: TimeInterval = ProcessInfo.processInfo.systemUptime) throws -> RouterConnectionSnapshot {
        do {
            let object = try RouterStrictJSON.object(bytes, maximumBytes: RouterSystemFrame.replyLimit)
            if Set(object.keys) == ["version", "error"], object["error"] as? String == "invalidRequest" {
                struct Legacy: Decodable { let version: Int; let error: String }
                guard try JSONDecoder().decode(Legacy.self, from: bytes).version == 1 else {
                    throw RouterConnectionFailure.invalidResponse
                }
                throw RouterConnectionFailure.unsupportedComponent
            }
            if object["connectionError"] != nil {
                guard Set(object.keys) == ["version", "request", "connectionError"] else {
                    throw RouterConnectionFailure.invalidResponse
                }
                let failure = try JSONDecoder().decode(Failure.self, from: bytes)
                guard failure.version == 1, failure.request == query.request else { throw RouterConnectionFailure.invalidResponse }
                throw failure.connectionError
            }
            // Preserve Int64 precision by decoding the original bytes, never an NSNumber round-trip.
            let sample = try RouterConnectionSnapshot.decode(bytes)
            try sample.validate(request: query.request, instance: query.instance, mode: .system, now: now, uptime: uptime)
            return sample
        } catch let error as RouterConnectionFailure { throw error }
        catch { throw RouterConnectionFailure.invalidResponse }
    }
}
