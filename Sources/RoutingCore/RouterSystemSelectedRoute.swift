import Foundation
import Darwin

/// Read-only kernel selection for two fixed destinations, not application/egress acceptance.
struct RouterSystemSelectedRoute: Equatable {
    enum Family {
        case ipv4, ipv6
        var af: Int32 { self == .ipv4 ? AF_INET : AF_INET6 }
        var target: String { self == .ipv4 ? "1.1.1.1" : "2606:4700:4700::1111" }
    }
    let family: Family
    let destination: String
    let mask: String?
    let gateway: String?
    let interface: String
    let flags: Set<String>

    static func collect(_ family: Family, command: RouterSystemCommand) throws -> Self {
        let (result, bytes) = try command.run(family == .ipv4 ? .selectedRouteIPv4 : .selectedRouteIPv6)
        guard result.settled, !result.timedOut, result.exitCode == 0,
              let text = String(data: bytes, encoding: .utf8) else { throw RouterSystemError.operationUnsettled }
        return try parse(text, family: family)
    }
    static func parse(_ text: String, family: Family) throws -> Self {
        guard text.utf8.count <= 16_384,
              !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" && $0 != "\t" }) else {
            throw RouterSystemError.configurationRejected
        }
        let keys: Set<String> = ["route to", "destination", "mask", "gateway", "interface", "flags"]
        var fields: [String: String] = [:], metricsHeader = false, metricsRow = false
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            let columns = line.split(whereSeparator: \.isWhitespace).map(String.init)
            if columns == ["recvpipe", "sendpipe", "ssthresh", "rtt,msec", "rttvar", "hopcount", "mtu", "expire"] {
                guard !metricsHeader else { throw RouterSystemError.configurationRejected }
                metricsHeader = true; continue
            }
            if metricsHeader {
                guard !metricsRow, columns.count == 8, columns.allSatisfy({ Int64($0) != nil }) else {
                    throw RouterSystemError.configurationRejected
                }
                metricsRow = true; continue // Counters are not stable route configuration.
            }
            guard let colon = line.firstIndex(of: ":") else { throw RouterSystemError.configurationRejected }
            let key = String(line[..<colon]), value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard keys.contains(key), fields[key] == nil, !value.isEmpty else { throw RouterSystemError.configurationRejected }
            fields[key] = value
        }
        guard metricsHeader == metricsRow, let target = fields["route to"],
              numericBytes(target, family: family.af) == numericBytes(family.target, family: family.af),
              let destination = fields["destination"], destination == "default" || RouterSystemInterfaceSnapshot.numericText(destination, family: family.af),
              let interface = fields["interface"], RouterSystemInterfaceSnapshot.validName(interface),
              let flags = fields["flags"], flags.hasPrefix("<"), flags.hasSuffix(">") else {
            throw RouterSystemError.configurationRejected
        }
        let entries = flags.dropFirst().dropLast().split(separator: ",", omittingEmptySubsequences: false).map(String.init)
        guard !entries.isEmpty, Set(entries).count == entries.count,
              entries.allSatisfy({ !$0.isEmpty && $0.utf8.allSatisfy({ (65...90).contains($0) || (48...57).contains($0) || $0 == 95 }) }) else {
            throw RouterSystemError.configurationRejected
        }
        if let mask = fields["mask"], mask != "default", !RouterSystemInterfaceSnapshot.numericText(mask, family: family.af) {
            throw RouterSystemError.configurationRejected
        }
        if let gateway = fields["gateway"], !RouterSystemInterfaceSnapshot.numericText(gateway, family: family.af) {
            throw RouterSystemError.configurationRejected
        }
        return .init(family: family, destination: destination, mask: fields["mask"], gateway: fields["gateway"],
                     interface: interface, flags: Set(entries))
    }
    func selects(_ name: String) -> Bool {
        interface == name && flags.isSuperset(of: ["UP", "GATEWAY"]) &&
        flags.isDisjoint(with: ["REJECT", "BLACKHOLE"]) && gateway != nil &&
        (!gateway!.contains("%") || gateway!.hasSuffix("%" + name))
    }
    private static func numericBytes(_ text: String, family: Int32) -> Data? {
        guard RouterSystemInterfaceSnapshot.numericText(text, family: family), !text.contains("%") else { return nil }
        var storage = in6_addr()
        guard inet_pton(family, text, &storage) == 1 else { return nil }
        return withUnsafeBytes(of: storage) { Data($0.prefix(family == AF_INET ? 4 : 16)) }
    }
}
