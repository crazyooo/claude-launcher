import Foundation
import Darwin

/// Effective resolver configuration, not cache contents or a DNS reachability test.
enum RouterSystemDNS {
    enum Section: String, Codable { case ordinary, scoped, serviceSpecific }
    struct Resolver: Codable, Equatable {
        let section: Section
        let index: Int
        let fields: [String: String]
        var category: String {
            if section != .ordinary { return section.rawValue }
            return fields["flags"]?.components(separatedBy: ", ").contains("Supplemental") == true ? "supplemental" : "default"
        }
    }
    struct Snapshot { let raw: String; let resolvers: [Resolver]; let canonical: String }
    private struct Canonical: Encodable { let available: Bool; let resolvers: [Resolver] }

    static func parse(_ text: String) throws -> Snapshot {
        guard text.utf8.count <= 65_536, !text.unicodeScalars.contains(where: {
            CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\r" && $0 != "\t"
        }) else { throw RouterSystemError.operationUnsettled }
        let normalized = text.replacingOccurrences(of: "\r\n", with: "\n")
        guard !normalized.contains("\r") else { throw RouterSystemError.operationUnsettled }
        if normalized.trimmingCharacters(in: .whitespacesAndNewlines) == "No DNS configuration available" {
            return try result(text, available: false, resolvers: [])
        }
        let headers: [String: Section] = ["DNS configuration": .ordinary,
            "DNS configuration (for scoped queries)": .scoped, "DNS configuration (for service-specific queries)": .serviceSpecific]
        var section: Section?, seen = Set<Section>(), current: Int?, nextIndex = 1
        var fields: [String: String] = [:], sawReach = false, resolvers: [Resolver] = []
        func finish() throws {
            guard let index = current else { return }
            guard let section, let flags = fields["flags"], sawReach else { throw RouterSystemError.operationUnsettled }
            let tokens = flags.components(separatedBy: ", ")
            guard tokens.contains("Scoped") == (section == .scoped),
                  tokens.contains("Service-specific") == (section == .serviceSpecific) else { throw RouterSystemError.operationUnsettled }
            for prefix in ["nameserver", "search domain", "sortaddr"] {
                let indices = try fields.keys.filter { $0.hasPrefix(prefix + "[") }.map { key -> Int in
                    guard let index = position(key, prefix: prefix) else { throw RouterSystemError.operationUnsettled }
                    return index
                }.sorted()
                guard indices == Array(0..<indices.count) else { throw RouterSystemError.operationUnsettled }
            }
            resolvers.append(.init(section: section, index: index, fields: fields))
            guard resolvers.count <= 256 else { throw RouterSystemError.operationUnsettled }
            current = nil; fields = [:]; sawReach = false
        }
        for line in normalized.components(separatedBy: "\n") {
            if line.trimmingCharacters(in: .whitespaces).isEmpty { continue }
            if let value = headers[line] {
                try finish()
                if let section, section != .ordinary, nextIndex == 1 { throw RouterSystemError.operationUnsettled }
                guard !seen.contains(value), value == .ordinary ? seen.isEmpty : seen.contains(.ordinary),
                      !(value == .scoped && seen.contains(.serviceSpecific)) else { throw RouterSystemError.operationUnsettled }
                seen.insert(value); section = value; nextIndex = 1
            } else if line.hasPrefix("resolver #") {
                try finish()
                let raw = String(line.dropFirst("resolver #".count))
                guard section != nil, let index = Int(raw), String(index) == raw, index == nextIndex else { throw RouterSystemError.operationUnsettled }
                current = index; nextIndex += 1
            } else {
                guard current != nil, line.hasPrefix("  "), let separator = line.firstIndex(of: ":") else { throw RouterSystemError.operationUnsettled }
                let key = line[..<separator].trimmingCharacters(in: .whitespaces)
                let value = line[line.index(after: separator)...].trimmingCharacters(in: .whitespaces)
                if key == "reach" {
                    guard !sawReach, matches(value, #"0x[0-9a-fA-F]{8}( \([^()\r\n]*\))?"#) else { throw RouterSystemError.operationUnsettled }
                    sawReach = true
                } else {
                    guard fields[key] == nil, validField(key, value) else { throw RouterSystemError.operationUnsettled }
                    fields[key] = value
                }
            }
        }
        try finish()
        guard seen.contains(.ordinary), section == .ordinary || nextIndex > 1 else { throw RouterSystemError.operationUnsettled }
        return try result(text, available: true, resolvers: resolvers)
    }
    private static func result(_ raw: String, available: Bool, resolvers: [Resolver]) throws -> Snapshot {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return .init(raw: raw, resolvers: resolvers,
                     canonical: String(decoding: try encoder.encode(Canonical(available: available, resolvers: resolvers)), as: UTF8.self))
    }
    private static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "^(?:" + pattern + ")$", options: .regularExpression) != nil
    }
    private static func position(_ key: String, prefix: String) -> Int? {
        guard key.hasPrefix(prefix + "["), key.hasSuffix("]") else { return nil }
        let digits = key.dropFirst(prefix.count + 1).dropLast()
        guard let index = Int(digits), (0..<256).contains(index), String(index) == digits else { return nil }
        return index
    }
    private static func validField(_ key: String, _ value: String) -> Bool {
        guard value.utf8.count <= 4096 else { return false }
        switch key {
        case "domain", "options": return !value.isEmpty
        case "port", "timeout", "order", "service_identifier":
            guard let number = UInt32(value), String(number) == value else { return false }
            return key != "port" || (number > 0 && number <= 65_535)
        case "if_index":
            guard matches(value, #"[1-9][0-9]* \([A-Za-z0-9_.?-]+\)"#),
                  let digits = value.split(separator: " ").first, let index = UInt32(digits), index > 0 else { return false }
            return String(index) == digits
        case "flags":
            if value.isEmpty { return true }
            let tokens = value.components(separatedBy: ", ")
            let known: Set<String> = ["Scoped", "Service-specific", "Supplemental", "Request A records", "Request AAAA records"]
            return Set(tokens).count == tokens.count && tokens.allSatisfy { known.contains($0) || matches($0, #"0x[0-9a-fA-F]{8}"#) }
        default:
            if position(key, prefix: "search domain") != nil { return !value.isEmpty }
            if position(key, prefix: "nameserver") != nil {
                return RouterSystemInterfaceSnapshot.numericText(value, family: AF_INET) || RouterSystemInterfaceSnapshot.numericText(value, family: AF_INET6)
            }
            if position(key, prefix: "sortaddr") != nil {
                let parts = value.split(separator: "/", omittingEmptySubsequences: false)
                return parts.count == 2 && parts.allSatisfy { RouterSystemInterfaceSnapshot.numericText(String($0), family: AF_INET) }
            }
            return false
        }
    }
}
