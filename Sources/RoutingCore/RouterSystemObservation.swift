import Foundation
import CryptoKit
import SystemConfiguration

/// Historical, read-only observation. It never authorizes changing network settings.
public struct RouterSystemObservation: Encodable {
    public let checkedAt: Date
    public let fingerprint: String
    public let complete: Bool
    public let defaultIPv4Interfaces: [String]
    public let defaultIPv6Interfaces: [String]
    public let tunnelCaptureInterfaces: [String]
    public let scopedTunnelInterfaces: [String]
    public let applicationProxyEnabled: Bool?
    public let automaticProxyEnabled: Bool?
    public let connectedVPN: Bool?
    public let userCoreJobPresent: Bool?
    public let unknowns: [String]
    public let networkModified = false
    public let routingVerified = false

    public static func collect(ownerUID: uid_t = getuid()) -> Self {
        collect(ownerUID: ownerUID, run: RouterRuntimeProcess.capture, proxies: {
            guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { throw RouterRuntimeError.operationFailed }
            return values
        })
    }
    static func collect(ownerUID: uid_t = getuid(), run: (String, [String], TimeInterval) throws -> (RouterProcessResult, Data),
                        proxies: () throws -> [String: Any]) -> Self {
        var unknowns: [String] = []
        func query(_ command: String, _ args: [String]) throws -> String {
            let (result, data) = try run(command, args, 3)
            guard result.settled, !result.timedOut, result.exitCode == 0,
                  let text = String(data: data, encoding: .utf8) else { throw RouterRuntimeError.operationFailed }
            return text
        }
        func table(_ family: String) -> RouteTable? {
            do { return try RouteTable.parse(query("/usr/sbin/netstat", ["-rn", "-f", family]), family: family) }
            catch { unknowns.append("route_" + family + "_unavailable"); return nil }
        }
        func proxy() -> ProxySnapshot? {
            do { return try ProxySnapshot.parse(proxies()) }
            catch { unknowns.append("system_proxy_unavailable"); return nil }
        }
        let v4 = table("inet"), v6 = table("inet6"), firstProxy = proxy()
        func vpnService() -> Bool? {
            do { return try parseVPN(query("/usr/sbin/scutil", ["--nc", "list"])) }
            catch { unknowns.append("vpn_service_list_unavailable"); return nil }
        }
        func userService() -> Bool? {
            do {
                let (result, _) = try run("/bin/launchctl", ["print", "gui/\(ownerUID)/" + RouterCoreRelease.label], 3)
                guard result.settled, !result.timedOut, result.exitCode == 0 || result.exitCode == 113 else { throw RouterRuntimeError.operationFailed }
                return result.exitCode == 0
            } catch { unknowns.append("user_core_job_unavailable"); return nil }
        }
        let vpn = vpnService(), userCore = userService()
        let second4 = table("inet"), second6 = table("inet6"), secondProxy = proxy()
        let secondVPN = vpnService(), secondUser = userService()
        if v4 != second4 || v6 != second6 || firstProxy != secondProxy || vpn != secondVPN || userCore != secondUser {
            unknowns.append("network_changed_during_observation")
        }
        if v4?.defaults.isEmpty != false { unknowns.append("ipv4_default_route_not_observed") }
        let tables = [v4, v6].compactMap { $0 }
        let canonical = tables.map { $0.canonical }.joined(separator: "\n") + (firstProxy?.digest ?? "unknown") + "|vpn:\(String(describing: vpn))|core:\(String(describing: userCore))"
        return .init(checkedAt: Date(), fingerprint: hash(Data(canonical.utf8)), complete: unknowns.isEmpty,
                     defaultIPv4Interfaces: v4?.defaults ?? [], defaultIPv6Interfaces: v6?.defaults ?? [],
                     tunnelCaptureInterfaces: Array(Set(tables.flatMap { $0.capture })).sorted(),
                     scopedTunnelInterfaces: Array(Set(tables.flatMap { $0.scoped })).sorted(),
                     applicationProxyEnabled: firstProxy?.explicit, automaticProxyEnabled: firstProxy?.automatic,
                     connectedVPN: vpn, userCoreJobPresent: userCore, unknowns: Array(Set(unknowns)).sorted())
    }
    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    struct RouteTable: Equatable {
        /// Full fields remain available as read-only evidence, never as a route deletion list.
        let rows: [[String]]
        let canonical: String
        let defaults: [String]
        let capture: [String]
        let scoped: [String]
        var stableRows: [[String]] {
            rows.filter { !Self.transientNeighbor(destination: $0[0], flags: $0[2]) }.map { Array($0.prefix(4)) }
        }
        static func == (lhs: Self, rhs: Self) -> Bool { lhs.canonical == rhs.canonical }
        private static func transientNeighbor(destination: String, flags: String) -> Bool {
            // Only known dynamic host-cache flags. Preserve gateways, static routes,
            // prefixes, reject/blackhole routes and unfamiliar flag combinations.
            destination != "default" && !destination.contains("/") && flags.contains("H") &&
            (flags.contains("L") || flags.contains("W")) && flags.allSatisfy { "UHLWIi".contains($0) }
        }
        private static func isIPv4Multicast(_ destination: String) -> Bool {
            let first = destination.split(whereSeparator: { $0 == "." || $0 == "/" }).first
            return first.flatMap { Int($0) }.map { (224...239).contains($0) } ?? false
        }
        static func parse(_ text: String, family: String) throws -> Self {
            let lines = text.components(separatedBy: .newlines).map { $0.split(whereSeparator: \.isWhitespace).map(String.init) }
            guard text.contains(family == "inet" ? "Internet:" : "Internet6:"),
                  let header = lines.firstIndex(where: { $0.first == "Destination" }),
                  lines[header].prefix(4).elementsEqual(["Destination", "Gateway", "Flags", "Netif"]) else { throw RouterRuntimeError.operationFailed }
            var rows: [[String]] = [], topology: [String] = []
            var defaults: Set<String> = [], capture: Set<String> = [], scoped: Set<String> = []
            for row in lines.dropFirst(header + 1) where !row.isEmpty {
                guard row.count >= 4, row[3].utf8.allSatisfy({ (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) }), row[3].count <= 32 else { throw RouterRuntimeError.operationFailed }
                let destination = row[0], flags = row[2], interface = row[3]
                rows.append(row)
                if !transientNeighbor(destination: destination, flags: flags) {
                    topology.append(row.prefix(4).joined(separator: "|"))
                }
                if destination == "default", !flags.contains("I") { defaults.insert(interface) }
                if interface.hasPrefix("utun") || interface.hasPrefix("ppp") || interface.hasPrefix("ipsec") {
                    if flags.contains("I") { scoped.insert(interface) }
                    else if !destination.hasPrefix("fe80:"), !destination.hasPrefix("ff"), !destination.hasPrefix("169.254"), !Self.isIPv4Multicast(destination) {
                        capture.insert(interface)
                    }
                }
            }
            // Even filtered neighbor rows contribute to tunnel/default observations.
            let normalized: [String: Any] = ["family": family, "routes": topology.sorted(),
                "defaults": defaults.sorted(), "capture": capture.sorted(), "scoped": scoped.sorted()]
            let canonical = String(decoding: try JSONSerialization.data(withJSONObject: normalized, options: [.sortedKeys]), as: UTF8.self)
            return .init(rows: rows, canonical: canonical, defaults: defaults.sorted(), capture: capture.sorted(), scoped: scoped.sorted())
        }
    }
    struct ProxySnapshot: Equatable {
        let explicit: Bool
        let automatic: Bool
        let digest: String
        static func parse(_ object: [String: Any]) throws -> Self {
            var explicit = false, automatic = false
            func flag(_ value: Any?) throws -> Bool {
                guard let value else { return false }
                guard let number = value as? NSNumber, number == 0 || number == 1 else { throw RouterRuntimeError.operationFailed }
                return number == 1
            }
            func inspect(_ values: [String: Any]) throws {
                for key in ["HTTPEnable", "HTTPSEnable", "SOCKSEnable"] { if try flag(values[key]) { explicit = true } }
                for key in ["ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"] { if try flag(values[key]) { automatic = true } }
                if let scoped = values["__SCOPED__"] {
                    guard let entries = scoped as? [String: [String: Any]] else { throw RouterRuntimeError.operationFailed }
                    for child in entries.values { try inspect(child) }
                }
                if let supplemental = values["__SUPPLEMENTAL__"] {
                    guard let entries = supplemental as? [[String: Any]] else { throw RouterRuntimeError.operationFailed }
                    for child in entries { try inspect(child) }
                }
            }
            try inspect(object)
            // Only a digest survives; PAC URLs, exception domains and proxy addresses are not exported.
            let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
            return .init(explicit: explicit, automatic: automatic, digest: RouterSystemObservation.hash(data))
        }
    }
    static func parseVPN(_ text: String) throws -> Bool {
        guard text.hasPrefix("Available network connection services") else { throw RouterRuntimeError.operationFailed }
        var connected = false
        let pattern = try NSRegularExpression(pattern: #"^\s*\*?\s*\((Connected|Connecting|Disconnecting|Disconnected)\)\s+"#)
        for line in text.components(separatedBy: .newlines).dropFirst() where !line.trimmingCharacters(in: .whitespaces).isEmpty {
            guard let match = pattern.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)),
                  let range = Range(match.range(at: 1), in: line) else { throw RouterRuntimeError.operationFailed }
            if line[range] != "Disconnected" { connected = true }
        }
        return connected
    }
}

public struct RouterSystemPreview: Encodable {
    public let observation: RouterSystemObservation
    public let blockers: [String]
    public let warnings: [String]
    public let canApply = false
    public let networkModified = false
    public let routingVerified = false
    public init(observation: RouterSystemObservation) {
        self.observation = observation
        var blockers = ["system_routing_not_enabled_in_this_release"]
        if !observation.complete { blockers.append("network_observation_incomplete") }
        if !observation.tunnelCaptureInterfaces.isEmpty || observation.connectedVPN == true { blockers.append("existing_tunnel_routes_require_resolution") }
        if observation.applicationProxyEnabled == true || observation.automaticProxyEnabled == true { blockers.append("application_proxy_changes_process_attribution") }
        if observation.userCoreJobPresent != false { blockers.append("user_core_job_requires_stop_or_inspection") }
        self.blockers = blockers
        warnings = ["scoped_tunnel_routes_alone_do_not_prove_capture", "browser_doh_and_process_helpers_unverified",
                    "existing_connections_do_not_automatically_migrate", "core_exit_fail_closed_not_implemented"]
    }
}
