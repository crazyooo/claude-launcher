import Foundation
import Darwin

/// Combines independent observations. It never alters interfaces, routes or DNS.
enum RouterSystemRuntimeCorrelation {
    struct Controller: Equatable {
        let process: RouterSystemKernelObservation.ProcessSnapshot
        let listeners: [RouterSystemControllerListener.Signature]
        let declaration: RouterSystemControllerDeclaration
    }
    struct Settlement: Equatable {
        let dispatchSettled: Bool
        let processExited: Bool
        let groupDrained: Bool
    }
    static func capture(instance: UUID, work: RouterSystemWork, digest: String,
                        baseline: RouterSystemBaselineSnapshot, current: RouterSystemBaselineSnapshot,
                        first: Controller, second: Controller,
                        ipv4: RouterSystemSelectedRoute, ipv6: RouterSystemSelectedRoute?) throws -> RouterSystemFootprint {
        try baseline.validate(); try current.validate()
        guard RouterSystemProvider.validDigest(digest), first == second, first.process.work == work,
              first.process.uid == 0, first.process.realUID == 0, !first.listeners.isEmpty,
              first.listeners.allSatisfy({ $0.descriptor >= 0 && $0.generation > 0 }),
              Set(first.listeners.map(\.descriptor)).count == first.listeners.count,
              work.bootID == baseline.captured.bootID, current.captured.bootID == work.bootID,
              current.captured.uptime >= baseline.captured.uptime, current.captured.date >= baseline.captured.date,
              let name = second.declaration.device else { throw RouterSystemError.ownershipUnknown }
        let declaration = second.declaration
        guard let device = current.interfaces.first(where: { $0.name == name }),
              baseline.interfaces.allSatisfy({ $0.name != name && $0.index != device.index }),
              device.mtu == declaration.effectiveMTU,
              device.flags & UInt32(IFF_UP | IFF_POINTOPOINT) == UInt32(IFF_UP | IFF_POINTOPOINT),
              device.flags & UInt32(IFF_LOOPBACK) == 0,
              current.interfaces.filter({ $0.name != name }).sorted(by: { $0.name < $1.name }) == baseline.interfaces.sorted(by: { $0.name < $1.name }) else {
            throw RouterSystemError.networkConflict
        }
        try verifyAddresses(device, ipv6: declaration.tunIPv6Configured)
        guard ipv4.family == .ipv4, ipv4.selects(name) else { throw RouterSystemError.networkConflict }
        if declaration.tunIPv6Configured {
            guard let ipv6, ipv6.family == .ipv6, ipv6.selects(name) else { throw RouterSystemError.networkConflict }
        } else if ipv6 != nil { throw RouterSystemError.configurationRejected }
        let routes = try stableRoutes(current, interface: name)
        guard routes.contains(where: { $0.hasPrefix("inet|") }),
              !declaration.tunIPv6Configured || routes.contains(where: { $0.hasPrefix("inet6|") }) else {
            throw RouterSystemError.networkConflict
        }
        return .init(instance: instance, work: work, configurationDigest: digest, interfaceName: name,
                     interfaceIndex: device.index, addresses: device.addresses.map(\.sortKey).sorted(), routeSignatures: routes)
    }

    static func cleanup(instance: UUID, dispatch: RouterSystemDispatchFence, footprint: RouterSystemFootprint?,
                        baseline: RouterSystemBaselineSnapshot, current: RouterSystemBaselineSnapshot,
                        first: Settlement, second: Settlement,
                        cleanEnvironment: Bool) throws -> RouterSystemCleanupProof {
        try baseline.validate(); try current.validate()
        guard first == second, dispatch.instance == instance else { throw RouterSystemError.operationUnsettled }
        let currentRoutes = try stableRoutes(current), baselineRoutes = try stableRoutes(baseline)
        // Takeover-relevant interface identity is the name+index slot. Per-interface
        // address, flag and MTU rotation (nan0/awdl0 link-local churn, DHCP renewal,
        // live evidence 2026-10-24) is natural drift; a takeover still surfaces as a
        // new interface name or new traffic-carrying routes.
        let interfacesMatch = Set(baseline.interfaces.map { "\($0.name)/\($0.index)" })
            == Set(current.interfaces.map { "\($0.name)/\($0.index)" })
        let routesMatch = baselineRoutes == currentRoutes
        let dnsMatch = try RouterSystemDNS.parse(baseline.dns).canonical == RouterSystemDNS.parse(current.dns).canonical
        // A drifted route table is not by itself evidence of a foreign takeover: macOS
        // route tables change naturally (row churn, _awdl/ipsec rows) and the previous
        // exact-match requirement deadlocked stop — the journal could never leave
        // `stopping` even though the owned TUN/routes/process were fully gone
        // (live evidence 2026-10-23 utun8 orphan, 2026-10-24 route-table drift).
        // A foreign takeover necessarily appears as a NEW row the baseline lacks, on a
        // non-owned interface, with a destination that can carry unicast traffic away
        // from the host. Disappeared rows, owned-interface rows and link-local/
        // multicast/loopback destinations can never inject a tunnel. The proxy/VPN
        // surface is covered by `cleanEnvironment` (independent fresh observation),
        // which the caller must sample at stop time.
        let foreignRows: [String]
        if routesMatch {
            foreignRows = []
        } else {
            let own = footprint?.interfaceName
            foreignRows = Set(currentRoutes).subtracting(baselineRoutes).filter { row in
                var columns = row.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
                guard columns.count > 3 else { return true }
                columns.removeFirst() // family prefix from stableRoutes
                if let own, columns[3] == own { return false }
                return !Self.cannotCarryDefaultUnicast(family: row.hasPrefix("inet6|") ? "inet6" : "inet",
                                                       destination: columns[0])
            }
        }
        let external = baseline.captured.bootID == current.captured.bootID && interfacesMatch && dnsMatch
            && foreignRows.isEmpty && cleanEnvironment
        let interfaceAbsent: Bool, routesAbsent: Bool
        if let footprint {
            guard footprint.instance == instance, footprint.configurationDigest == dispatch.configurationDigest,
                  baseline.interfaces.allSatisfy({ $0.name != footprint.interfaceName && $0.index != footprint.interfaceIndex }) else {
                throw RouterSystemError.ownershipUnknown
            }
            // Name or index reuse is ambiguous. Never delete a resource from a diff.
            interfaceAbsent = current.interfaces.allSatisfy { $0.name != footprint.interfaceName && $0.index != footprint.interfaceIndex }
            let rows = try RouterSystemObservation.RouteTable.parse(current.routesIPv4, family: "inet").rows +
                RouterSystemObservation.RouteTable.parse(current.routesIPv6, family: "inet6").rows
            routesAbsent = rows.allSatisfy { $0[3] != footprint.interfaceName } && Set(currentRoutes).isDisjoint(with: footprint.routeSignatures)
        } else {
            // Execution can create resources before a footprint is saved.
            interfaceAbsent = interfacesMatch; routesAbsent = routesMatch
        }
        return .init(instance: instance, dispatch: dispatch,
                     startWorkSettled: second.dispatchSettled && second.groupDrained, processExited: second.processExited,
                     interfaceAbsent: interfaceAbsent, routesAbsent: routesAbsent, externalStatePreserved: external)
    }

    /// Destinations that can never carry a working tunnel's data plane: a takeover needs
    /// a unicast route (default, split aggregate or prefix) on a non-owned interface, so
    /// AWDL/NaN peer churn, mDNS rows and loopback entries are natural drift, not takeover.
    private static func cannotCarryDefaultUnicast(family: String, destination: String) -> Bool {
        if family == "inet6" {
            return destination == "::1" || destination.hasPrefix("fe80") || destination.hasPrefix("ff")
        }
        let first = destination.split(whereSeparator: { $0 == "." || $0 == "/" }).first
        guard let octet = first.flatMap({ Int($0) }) else { return false }
        return octet == 127 || octet == 169 || (224...239).contains(octet) || octet == 255
    }

    private static func stableRoutes(_ snapshot: RouterSystemBaselineSnapshot, interface: String? = nil) throws -> [String] {
        var result: [String] = []
        for (family, text) in [("inet", snapshot.routesIPv4), ("inet6", snapshot.routesIPv6)] {
            let table = try RouterSystemObservation.RouteTable.parse(text, family: family)
            result += table.stableRows.filter { interface == nil || $0[3] == interface }.map { family + "|" + $0.joined(separator: "|") }
        }
        return result.sorted()
    }
    private static func verifyAddresses(_ device: RouterSystemInterfaceSnapshot.Interface, ipv6: Bool) throws {
        var v4 = 0, v6 = 0
        for value in device.addresses {
            if value.family == AF_INET {
                guard sameIP(value.address, "198.18.0.1", family: AF_INET), sameIP(value.netmask, "255.255.255.252", family: AF_INET) else {
                    throw RouterSystemError.networkConflict
                }
                v4 += 1
            } else if sameIP(value.address, "fdfe:dcba:9876::1", family: AF_INET6) {
                guard ipv6, sameIP(value.netmask, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffc", family: AF_INET6) else {
                    throw RouterSystemError.networkConflict
                }
                v6 += 1
            } else {
                let parts = value.address.split(separator: "%", omittingEmptySubsequences: false)
                guard value.family == AF_INET6,
                      parts.count == 1 || (parts.count == 2 && [device.name, String(device.index)].contains(String(parts[1]))),
                      let address = bytes(String(parts[0]), family: AF_INET6), address[0] == 0xfe, address[1] & 0xc0 == 0x80 else {
                    throw RouterSystemError.networkConflict
                }
            }
        }
        guard v4 == 1, v6 == (ipv6 ? 1 : 0) else { throw RouterSystemError.networkConflict }
    }
    private static func bytes(_ text: String?, family: Int32) -> [UInt8]? {
        guard let text, !text.contains("%"), RouterSystemInterfaceSnapshot.numericText(text, family: family) else { return nil }
        var storage = in6_addr()
        guard inet_pton(family, text, &storage) == 1 else { return nil }
        return withUnsafeBytes(of: storage) { Array($0.prefix(family == AF_INET ? 4 : 16)) }
    }
    private static func sameIP(_ a: String?, _ b: String, family: Int32) -> Bool {
        guard let a = bytes(a, family: family), let b = bytes(b, family: family) else { return false }
        return a == b
    }
}
