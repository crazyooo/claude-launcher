import Foundation
import Darwin

public struct RouterInputError: Error, LocalizedError {
    public let code: String
    init(_ code: String) { self.code = code }
    public var errorDescription: String? { "路由规划输入被拒绝：" + code }
}

/// Bounded, local-only input. Errors deliberately omit paths and decoder payloads.
public enum RouterInput {
    public static let maximumBytes = 1_048_576

    public static func read(_ path: String) throws -> Data {
        guard !path.utf8.contains(0) else { throw RouterInputError("invalid_file") }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RouterInputError("file_unreadable") }
        defer { close(fd) }
        var before = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              before.st_size >= 0, before.st_size <= maximumBytes else {
            throw RouterInputError("regular_file_within_limit_required")
        }
        var result = Data(), buffer = [UInt8](repeating: 0, count: 8192)
        while result.count <= maximumBytes {
            let count = Darwin.read(fd, &buffer, min(buffer.count, maximumBytes + 1 - result.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterInputError("file_read_failed") }
            if count == 0 { break }
            result.append(contentsOf: buffer.prefix(count))
        }
        var after = stat()
        guard result.count <= maximumBytes, fstat(fd, &after) == 0,
              before.st_size == after.st_size, result.count == after.st_size,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec else {
            throw RouterInputError("file_changed_or_too_large")
        }
        return result
    }

    public static func plan(_ data: Data) throws -> RouterPlan {
        let object = try json(data)
        try keys(object, allowed: ["schemaVersion", "proxies", "rules", "defaultDestination"])
        guard let proxies = object["proxies"] as? [Any], let rules = object["rules"] as? [Any],
              proxies.count <= 128, rules.count <= 512 else { throw RouterInputError("invalid_plan_shape_or_count") }
        for proxy in proxies {
            try keys(proxy, allowed: ["id", "name", "kind", "host", "port", "udp", "credentialReference"])
        }
        for rule in rules {
            let value = try keys(rule, allowed: ["id", "selector", "destination"])
            let selector = try keys(value["selector"], allowed: ["processPath", "domain"])
            if let domain = selector["domain"], !(domain is NSNull) {
                try keys(domain, allowed: ["kind", "value"])
            }
            try keys(value["destination"], allowed: ["kind", "proxyID"])
        }
        try keys(object["defaultDestination"], allowed: ["kind", "proxyID"])
        return try decode(RouterPlan.self, object: object)
    }

    public static func flow(_ data: Data) throws -> RouterFlow {
        let object = try json(data)
        try keys(object, allowed: ["processPath", "domain", "transport"])
        let value = try decode(RouterFlow.self, object: object)
        if let process = value.processPath, !RouterValidation.validProcessPath(process) {
            throw RouterInputError("invalid_flow_process")
        }
        if let domain = value.domain, !RouterValidation.validDomain(domain) {
            throw RouterInputError("invalid_flow_domain")
        }
        return value
    }

    private static func json(_ data: Data) throws -> [String: Any] {
        guard data.count <= maximumBytes else { throw RouterInputError("input_too_large") }
        guard let value = try? JSONSerialization.jsonObject(with: data), let object = value as? [String: Any] else {
            throw RouterInputError("invalid_json")
        }
        return object
    }
    @discardableResult private static func keys(_ value: Any?, allowed: Set<String>) throws -> [String: Any] {
        guard let object = value as? [String: Any] else { throw RouterInputError("invalid_object") }
        guard Set(object.keys).isSubset(of: allowed) else { throw RouterInputError("unknown_field") }
        return object
    }
    private static func decode<T: Decodable>(_ type: T.Type, object: [String: Any]) throws -> T {
        // Validate and decode the same parsed object, avoiding two-parser discrepancies.
        do { return try JSONDecoder().decode(type, from: JSONSerialization.data(withJSONObject: object)) }
        catch { throw RouterInputError("invalid_field_type_or_missing_field") }
    }
}
