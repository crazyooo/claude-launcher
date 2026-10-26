import Foundation
import Darwin

struct EnvironmentRoute {
    let transport: ProbeTransport
    let source: EnvironmentRouteSource
    let code: String
    static func unresolved(_ code: String) -> Self {
        .init(transport: .init(error: "此路径尚未确认。"), source: .unresolved, code: code)
    }
}

struct EnvironmentCLIContext {
    let fingerprint: String
    let routes: [String: EnvironmentRoute]
    let code: String
    var resolved: Bool { code == "configuration_ok" }
}

enum EnvironmentRoutes {
    private static let routingKeys = ClientInspection.routingKeys + ["CLAUDE_CODE_PROCESS_WRAPPER", "CLAUDE_CODE_CUSTOM_OAUTH_URL", "CLAUDE_CODE_PROXY_RESOLVES_HOSTS"]
    private static func routingFingerprint(_ values: [String: String]) -> String {
        fingerprintData(Data(routingKeys.sorted().map { "\($0)=\(values[$0] ?? "")" }.joined(separator: "\n").utf8))
    }
    static func validatedProxy(_ value: String) -> ProbeTransport {
        let invalid = ProbeTransport(error: "代理地址无效，或包含尚未支持的认证信息。")
        guard value.utf8.count <= 2048, value.unicodeScalars.allSatisfy({ $0.value > 32 && $0.value < 127 }),
              !value.contains("%"), !value.contains("\\"),
              let components = URLComponents(string: value), let hostname = components.host else { return invalid }
        let host = hostname.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        guard normalizedIP(host) != nil || validHostname(host) else { return invalid }
        let parsed = ProbeTransport.explicit(value)
        guard parsed.error == nil else { return invalid }
        return parsed
    }

    private static func validHostname(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 253, !host.hasSuffix(".") else { return false }
        return host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { part in
            !part.isEmpty && part.count <= 63 && part.first != "-" && part.last != "-" &&
                part.utf8.allSatisfy { (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || $0 == 45 }
        }
    }

    /// nil means unsupported/ambiguous syntax, never an assumed proxy route.
    static func bypass(_ list: String, host: String, port: Int = 443) -> Bool? {
        guard list.utf8.count <= 16384, !list.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else { return nil }
        if list.isEmpty { return false }
        var matched = false
        for token in list.split(separator: ",", omittingEmptySubsequences: false) {
            var pattern = token.trimmingCharacters(in: .whitespaces).lowercased()
            guard !pattern.isEmpty else { return nil }
            if pattern == "*" { matched = true; continue }
            var selectedPort: Int?
            if pattern.contains(":") {
                let parts = pattern.split(separator: ":", omittingEmptySubsequences: false)
                guard parts.count == 2, let p = Int(parts[1]), (1...65535).contains(p) else { return nil }
                selectedPort = p; pattern = String(parts[0])
            }
            let suffix = pattern.hasPrefix(".") || pattern.hasPrefix("*.")
            if pattern.hasPrefix("*.") { pattern = String(pattern.dropFirst(2)) }
            else if pattern.hasPrefix(".") { pattern = String(pattern.dropFirst()) }
            guard validHostname(pattern) else { return nil }
            if selectedPort != nil && selectedPort != port { continue }
            let normalized = host.lowercased()
            if normalized == pattern || (suffix && normalized.hasSuffix("." + pattern)) { matched = true }
        }
        return matched
    }

    static func configurationURLs(directory: String) -> [URL] {
        var result = [FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude/settings.json"),
                      URL(fileURLWithPath: "/Library/Application Support/ClaudeCode/managed-settings.json")]
        var current = URL(fileURLWithPath: directory).standardizedFileURL
        for _ in 0..<128 {
            result += [current.appendingPathComponent(".claude/settings.json"), current.appendingPathComponent(".claude/settings.local.json")]
            if current.path == "/" { break }
            current.deleteLastPathComponent()
        }
        return Array(Set(result)).sorted { $0.path < $1.path }
    }

    static func readConfiguration(_ url: URL) throws -> [String: Any] {
        guard let data = try EnvironmentStorage.readBytes(url, allowRootOwner: true) else { return [:] }
        guard let text = String(data: data, encoding: .utf8),
              let object = try JSONSerialization.jsonObject(with: Data(JSONComments.strip(text).utf8)) as? [String: Any] else {
            throw EnvironmentStorage.storageError()
        }
        return object
    }

    static func cli(directory: String?, environment: [String: String]?, files: [URL],
                    read: (URL) throws -> [String: Any]) -> EnvironmentCLIContext {
        func failed(_ code: String, _ fingerprint: String) -> EnvironmentCLIContext {
            .init(fingerprint: fingerprint, routes: Dictionary(uniqueKeysWithValues: EnvironmentTarget.cli.hosts.map { ($0, .unresolved(code)) }), code: code)
        }
        guard let directory, directory.hasPrefix("/"), let environment else {
            return failed("cli_context_missing", fingerprintData(Data("missing-cli-context".utf8)))
        }
        var values = environment.filter { routingKeys.contains($0.key) }
        var evidence = ["cwd:" + fingerprintData(Data(directory.utf8)), routingFingerprint(values)]
        var problem: String?
        for file in files {
            do {
                let object = try read(file)
                var relevant: [String: String] = [:]
                if let rawEnv = object["env"] {
                    guard let env = rawEnv as? [String: Any] else { throw EnvironmentStorage.storageError() }
                    for key in routingKeys where env[key] != nil {
                        guard let value = env[key] as? String else { throw EnvironmentStorage.storageError() }
                        relevant[key] = value
                        if let prior = values[key], prior != value { problem = "cli_configuration_ambiguous" }
                        values[key] = value
                    }
                }
                // A configured wrapper may rewrite routing before the client runs.
                for key in ["processWrapper", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "forceLoginMethod"] where object[key] != nil {
                    problem = "cli_custom_configuration"
                    relevant["custom:" + key] = "present"
                }
                evidence.append(fingerprintData(Data(file.path.utf8)) + routingFingerprint(relevant) + relevant.keys.filter { $0.hasPrefix("custom:") }.sorted().joined())
            } catch { problem = "cli_configuration_unreadable"; evidence.append("unreadable:" + fingerprintData(Data(file.path.utf8))) }
        }
        let fingerprint = fingerprintData(Data(evidence.joined(separator: "|").utf8))
        if let home = environment["HOME"], home != NSHomeDirectory() { problem = "cli_custom_configuration" }
        let customKeys = routingKeys.filter { !ClientInspection.proxyKeys.contains($0) && !["NO_PROXY", "no_proxy"].contains($0) }
        if customKeys.contains(where: { !(values[$0] ?? "").isEmpty }) { problem = "cli_custom_configuration" }
        if let problem { return failed(problem, fingerprint) }
        // Claude Code documents HTTP(S)_PROXY. ALL_PROXY support/precedence is
        // not established, so a curl-only success must not stand in for the CLI.
        if ["ALL_PROXY", "all_proxy"].contains(where: { !(values[$0] ?? "").isEmpty }) {
            return failed("cli_configuration_ambiguous", fingerprint)
        }
        for (upper, lower) in [("HTTP_PROXY", "http_proxy"), ("HTTPS_PROXY", "https_proxy")] {
            if let a = values[upper], let b = values[lower], a != b {
                return failed("cli_configuration_ambiguous", fingerprint)
            }
        }
        let proxies = ClientInspection.proxyKeys.compactMap { values[$0] }.filter { !$0.isEmpty }.map(validatedProxy)
        guard !proxies.contains(where: { $0.error != nil || !($0.proxy?.hasPrefix("http://") == true || $0.proxy?.hasPrefix("https://") == true) }) else {
            return failed("proxy_invalid", fingerprint)
        }
        let endpoints = Set(proxies.compactMap(\.proxy))
        guard endpoints.count <= 1 else { return failed("cli_configuration_ambiguous", fingerprint) }
        if let upper = values["NO_PROXY"], let lower = values["no_proxy"], upper != lower {
            return failed("no_proxy_unresolved", fingerprint)
        }
        let exclusions = values["NO_PROXY"] ?? values["no_proxy"] ?? ""
        var routes: [String: EnvironmentRoute] = [:]
        for host in EnvironmentTarget.cli.hosts {
            guard let excluded = bypass(exclusions, host: host) else { return failed("no_proxy_unresolved", fingerprint) }
            routes[host] = .init(transport: .init(proxy: excluded ? nil : endpoints.first),
                                 source: excluded ? .noProxyBypass : (endpoints.isEmpty ? .systemNetworkRoute : .terminalConfiguration), code: "route_ok")
        }
        return .init(fingerprint: fingerprint, routes: routes, code: "configuration_ok")
    }
}
