import Foundation

public enum ConsoleDiagnostics {
    /// Strict allowlist: do not serialize arbitrary check details or API metadata.
    public static func data(report: PreflightReport?, gates: [ConsoleGate], controller: ControllerSnapshot?, now: Date,
                            recovery: RecoveryCoordinator? = nil) -> Data {
        let known = Set(["baseline", "client", "transport", "unchanged", "service", "plugin-gate", "code-network", "uniform-proxy", "dns", "ipv6"] + CheckTarget.allCases.flatMap { $0.hosts.map { "exit:" + $0 } })
        var result: [String: Any] = [
            "version": "0.5", "exportedAt": now.timeIntervalSince1970,
            "target": report?.target.rawValue ?? "unknown", "protection_verified": false, "launch_authorized": false,
            "controllerSamplePresent": controller != nil,
            "gates": gates.map { ["id": $0.id, "state": $0.level.rawValue] },
            "checks": (report?.checks ?? []).filter { known.contains($0.id) }.map { ["id": $0.id, "result": $0.result.rawValue] }
        ]
        if let recovery { result["recoveryOperation"] = recovery.diagnostic }
        return (try? JSONSerialization.data(withJSONObject: result, options: [.prettyPrinted, .sortedKeys])) ?? Data()
    }
}
