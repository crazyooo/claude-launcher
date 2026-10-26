import Foundation
import CoreFoundation

extension RouterSystemReply {
    static func decode(_ data: Data) throws -> RouterSystemStatus {
        let object = try RouterStrictJSON.object(data, maximumBytes: RouterSystemFrame.replyLimit)
        let keys = Set(object.keys)
        guard keys == ["version", "status"] || keys == ["version", "error"],
              let version = object["version"] as? NSNumber,
              CFGetTypeID(version) != CFBooleanGetTypeID(), version == 1 else { throw RouterSystemError.invalidRequest }
        if keys.contains("error") {
            guard let text = object["error"] as? String, let error = RouterSystemError(rawValue: text) else {
                throw RouterSystemError.invalidRequest
            }
            throw error
        }
        guard let status = object["status"] as? [String: Any] else { throw RouterSystemError.invalidRequest }
        return try RouterSystemStatus.decodeWire(status)
    }
}
