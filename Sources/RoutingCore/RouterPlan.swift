import Foundation
import Darwin

/// Product configuration, independent of the installed detector and retired controls.
/// Array order is rule precedence; IDs remain stable when display names change.
public struct RouterPlan: Codable, Equatable {
    public var schemaVersion: Int
    public var proxies: [RouterProxy]
    public var rules: [RouterRule]
    public var defaultDestination: RouterDestination

    public init(schemaVersion: Int = 1, proxies: [RouterProxy], rules: [RouterRule],
                defaultDestination: RouterDestination) {
        self.schemaVersion = schemaVersion
        self.proxies = proxies
        self.rules = rules
        self.defaultDestination = defaultDestination
    }
}

public struct RouterProxy: Codable, Equatable, Identifiable {
    public enum Kind: String, Codable { case http, socks5 }
    public var id: UUID
    public var name: String
    public var kind: Kind
    public var host: String
    public var port: Int
    /// Declared capability, not proof that the upstream supports UDP.
    public var udp: Bool
    /// Opaque identifier only. Secret resolution is not part of offline planning.
    public var credentialReference: UUID?

    public init(id: UUID, name: String, kind: Kind, host: String, port: Int,
                udp: Bool = false, credentialReference: UUID? = nil) {
        self.id = id; self.name = name; self.kind = kind; self.host = host; self.port = port
        self.udp = udp; self.credentialReference = credentialReference
    }
    var coreName: String { "route_" + id.uuidString.lowercased() }
    var supportsUDP: Bool { kind == .socks5 && udp }
}

public struct RouterDestination: Codable, Equatable {
    public enum Kind: String, Codable { case direct, block, proxy }
    public var kind: Kind
    public var proxyID: UUID?
    public init(kind: Kind, proxyID: UUID? = nil) { self.kind = kind; self.proxyID = proxyID }
    public static let direct = Self(kind: .direct)
    public static let block = Self(kind: .block)
    public static func proxy(_ id: UUID) -> Self { .init(kind: .proxy, proxyID: id) }
}

public struct RouterSelector: Codable, Equatable {
    public struct Domain: Codable, Equatable {
        public enum Kind: String, Codable { case exact, suffix }
        public var kind: Kind
        public var value: String
        public init(kind: Kind, value: String) { self.kind = kind; self.value = value }
    }
    public var processPath: String?
    public var domain: Domain?
    public init(processPath: String? = nil, domain: Domain? = nil) {
        self.processPath = processPath; self.domain = domain
    }
}

public struct RouterRule: Codable, Equatable, Identifiable {
    public var id: UUID
    public var selector: RouterSelector
    public var destination: RouterDestination
    public init(id: UUID, selector: RouterSelector, destination: RouterDestination) {
        self.id = id; self.selector = selector; self.destination = destination
    }
}

public struct RouterIssue: Codable, Equatable {
    public enum Severity: String, Codable { case error, warning }
    public let severity: Severity
    public let field: String
    public let code: String
    public init(_ field: String, _ code: String) { self.init(.error, field, code) }
    public init(_ severity: Severity, _ field: String, _ code: String) {
        self.severity = severity; self.field = field; self.code = code
    }
}

public enum RouterValidation {
    public static func issues(in plan: RouterPlan) -> [RouterIssue] {
        guard plan.schemaVersion == 1 else { return [.init("schemaVersion", "unsupported_schema")] }
        var issues: [RouterIssue] = []
        guard plan.proxies.count <= 128, plan.rules.count <= 512 else {
            return [.init("plan", "item_limit_exceeded")]
        }
        let ids = Set(plan.proxies.map(\.id))
        if ids.count != plan.proxies.count { issues.append(.init("proxies", "duplicate_id")) }
        if Set(plan.rules.map(\.id)).count != plan.rules.count { issues.append(.init("rules", "duplicate_id")) }
        func checkDestination(_ destination: RouterDestination, field: String) {
            if destination.kind == .proxy {
                if destination.proxyID.map(ids.contains) != true { issues.append(.init(field, "missing_proxy")) }
            } else if destination.proxyID != nil { issues.append(.init(field, "unexpected_proxy_id")) }
        }
        checkDestination(plan.defaultDestination, field: "defaultDestination")
        for (index, proxy) in plan.proxies.enumerated() {
            let field = "proxies[\(index)]"
            if proxy.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ||
                proxy.name.utf8.count > 160 || proxy.name.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) {
                issues.append(.init(field + ".name", "invalid_name"))
            }
            if !validHost(proxy.host) { issues.append(.init(field + ".host", "invalid_host")) }
            if !(1...65535).contains(proxy.port) { issues.append(.init(field + ".port", "invalid_port")) }
            if proxy.kind == .http && proxy.udp { issues.append(.init(field + ".udp", "http_udp_unsupported")) }
        }
        for (index, rule) in plan.rules.enumerated() {
            let field = "rules[\(index)]"
            if rule.selector.processPath == nil && rule.selector.domain == nil {
                issues.append(.init(field + ".selector", "empty_selector"))
            }
            if let path = rule.selector.processPath, !validProcessPath(path) {
                issues.append(.init(field + ".selector.processPath", "invalid_process_path"))
            }
            if let domain = rule.selector.domain, !validDomain(domain.value) {
                issues.append(.init(field + ".selector.domain", "invalid_domain"))
            }
            checkDestination(rule.destination, field: field + ".destination")
            if let previous = plan.rules.prefix(index).first(where: { covers($0.selector, rule.selector) }) {
                let duplicate = covers(rule.selector, previous.selector)
                issues.append(.init(duplicate ? .error : .warning, field,
                                    duplicate ? "duplicate_selector" : "shadowed_by_earlier_rule"))
            }
        }
        return issues
    }

    static func validDomain(_ value: String) -> Bool {
        guard !value.isEmpty, value.utf8.count <= 253, !isIP(value) else { return false }
        return value.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" &&
            label.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }
    static func isIP(_ value: String) -> Bool {
        guard !value.utf8.contains(0) else { return false }
        var v4 = in_addr(); var v6 = in6_addr()
        return value.withCString { inet_pton(AF_INET, $0, &v4) == 1 || inet_pton(AF_INET6, $0, &v6) == 1 }
    }
    static func validHost(_ value: String) -> Bool { isIP(value) || validDomain(value) }
    static func validProcessPath(_ value: String) -> Bool {
        // Literal ASCII executable paths only in schema v1. No wildcard/regex grammar.
        guard value.hasPrefix("/"), value.utf8.count <= 4096, !value.hasSuffix("/"),
              !value.lowercased().hasSuffix(".app"),
              value.utf8.allSatisfy({ (32...126).contains($0) }),
              !value.contains(where: { ",()*?[]\\\"".contains($0) }) else { return false }
        return value.dropFirst().split(separator: "/", omittingEmptySubsequences: false)
            .allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." && !$0.hasPrefix(" ") && !$0.hasSuffix(" ") }
    }
    static func domainMatches(_ pattern: RouterSelector.Domain, _ value: String) -> Bool {
        let expected = pattern.value.lowercased(), actual = value.lowercased()
        return actual == expected || (pattern.kind == .suffix && actual.hasSuffix("." + expected))
    }
    private static func covers(_ earlier: RouterSelector, _ later: RouterSelector) -> Bool {
        if let process = earlier.processPath, process.lowercased() != later.processPath?.lowercased() { return false }
        if let domain = earlier.domain {
            guard let other = later.domain, domainMatches(domain, other.value),
                  domain.kind == .suffix || other.kind == .exact else { return false }
        }
        return true
    }
}
