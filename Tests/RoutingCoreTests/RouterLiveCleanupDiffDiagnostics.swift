import XCTest
@testable import RoutingCore

/// Temporary diagnostic (2026-10-24): production-exact diff between the stuck instance's
/// saved baseline and a fresh sample, to locate which cleanup dimension reports
/// external_environment_changed on this machine. Read-only; prints evidence, asserts nothing.
final class RouterLiveCleanupDiffDiagnostics: XCTestCase {
    private var repoRoot: String {
        let file = #filePath
        guard let range = file.range(of: "/Tests/") else { fatalError("unexpected test path") }
        return String(file[..<range.lowerBound])
    }

    func testDiffSavedBaselineAgainstFreshSample() throws {
        let path = repoRoot + "/web-notes/matrix-clear-window-20261024/baseline-1e0e4236.json"
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let baseline = try JSONDecoder().decode(RouterSystemBaselineReceipt.self, from: data).snapshot
        try baseline.validate()

        let command = try RouterSystemCommand(ownerUID: 501)
        let current = try RouterSystemBaselineSnapshot.collect(command: command, network: { try RouterSystemObservation.collect() })
        try current.validate()

        print("FINGERPRINT baseline=\(baseline.networkFingerprint) current=\(current.networkFingerprint)")

        // cleanup dimension 1: stable routes (transientNeighbor-filtered, prefix(4))
        func stableRoutes(_ snapshot: RouterSystemBaselineSnapshot) throws -> [String] {
            var result: [String] = []
            for (family, text) in [("inet", snapshot.routesIPv4), ("inet6", snapshot.routesIPv6)] {
                let table = try RouterSystemObservation.RouteTable.parse(text, family: family)
                result += table.stableRows.map { family + "|" + $0.joined(separator: "|") }
            }
            return result.sorted()
        }
        let baselineRoutes = try Set(stableRoutes(baseline)), currentRoutes = try Set(stableRoutes(current))
        let added = currentRoutes.subtracting(baselineRoutes).sorted()
        let removed = baselineRoutes.subtracting(currentRoutes).sorted()
        print("ROUTES added=\(added.count) removed=\(removed.count)")
        added.forEach { print("ROUTE+ \($0)") }
        removed.forEach { print("ROUTE- \($0)") }

        // cleanup dimension 2: interface set, exact Equatable on name-sorted arrays
        let baselineInterfaces = baseline.interfaces.sorted { $0.name < $1.name }
        let currentInterfaces = current.interfaces.sorted { $0.name < $1.name }
        print("INTERFACES match=\(baselineInterfaces == currentInterfaces) baseline=\(baselineInterfaces.count) current=\(currentInterfaces.count)")
        let baselineByName = Dictionary(uniqueKeysWithValues: baselineInterfaces.map { ($0.name, $0) })
        let currentByName = Dictionary(uniqueKeysWithValues: currentInterfaces.map { ($0.name, $0) })
        for name in Set(baselineByName.keys).symmetricDifference(Set(currentByName.keys)).sorted() {
            print("IFACE-SET onlyIn=\(baselineByName[name] == nil ? "current" : "baseline") name=\(name)")
        }
        for name in Set(baselineByName.keys).intersection(Set(currentByName.keys)).sorted() {
            let a = baselineByName[name]!, b = currentByName[name]!
            if a != b {
                print("IFACE-DIFF name=\(name) index \(a.index)->\(b.index) flags \(a.flags)->\(b.flags) mtu \(a.mtu)->\(b.mtu)")
                print("IFACE-DIFF name=\(name) addressesBaseline=\(a.addresses.map(\.address))")
                print("IFACE-DIFF name=\(name) addressesCurrent=\(b.addresses.map(\.address))")
            }
        }

        // cleanup dimension 3: DNS canonical
        let baselineDNS = try RouterSystemDNS.parse(baseline.dns).canonical
        let currentDNS = try RouterSystemDNS.parse(current.dns).canonical
        print("DNS match=\(baselineDNS == currentDNS)")
        if baselineDNS != currentDNS {
            print("DNS baseline=\(baselineDNS)")
            print("DNS current=\(currentDNS)")
        }

        // changes(from:) production projection (what a review would report)
        let changes = try current.changes(from: baseline)
        print("CHANGES \(changes)")

        // foreign rows exactly as Correlation.cleanup computes them (own interface utun8)
        let own = "utun8"
        let foreign = added.filter { row in
            var columns = row.split(separator: "|", omittingEmptySubsequences: false).map(String.init)
            columns.removeFirst()
            return !(columns.count > 3 && columns[3] == own)
        }
        print("FOREIGN \(foreign.count)")
        foreign.forEach { print("FOREIGN+ \($0)") }
    }
}
