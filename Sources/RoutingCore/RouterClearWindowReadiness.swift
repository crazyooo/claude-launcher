import Foundation

/// Read-only probe for whether a conversation clear-window grant would still be
/// contradicted by known foreign capture processes. Does not stop anything,
/// does not grant `tun-apply-clear-window-v1`, and never claims requireClear passed.
public enum RouterClearWindowReadiness {
    public static let clearWindowID = RouterTunApplyExecuteGate.clearWindowID

    public struct ForeignProcess: Equatable, Sendable {
        public let pid: Int32
        public let path: String
        public let label: String
    }

    public struct Report: Equatable, Sendable {
        public let clearWindowID: String
        public let foreignProcesses: [ForeignProcess]
        public let looksClearOfKnownForeignClients: Bool
        public let canRecommendConversationGrant: Bool
        public let summary: String
        public let routingVerified: Bool
        public let accepted: Bool
    }

    public struct Effects: Sendable {
        public var listProcesses: @Sendable () -> [(pid: Int32, path: String)]
        public init(listProcesses: @escaping @Sendable () -> [(pid: Int32, path: String)]) {
            self.listProcesses = listProcesses
        }

        public static var live: Effects {
            .init(listProcesses: {
                let task = Process()
                task.executableURL = URL(fileURLWithPath: "/bin/ps")
                task.arguments = ["-axo", "pid=,command="]
                let pipe = Pipe()
                task.standardOutput = pipe
                task.standardError = FileHandle.nullDevice
                do {
                    try task.run()
                    task.waitUntilExit()
                } catch {
                    return []
                }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                guard let text = String(data: data, encoding: .utf8) else { return [] }
                return text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { line in
                    let trimmed = line.trimmingCharacters(in: .whitespaces)
                    guard let space = trimmed.firstIndex(of: " ") else { return nil }
                    let pidText = trimmed[..<space]
                    let path = String(trimmed[trimmed.index(after: space)...])
                        .trimmingCharacters(in: .whitespaces)
                    guard let pid = Int32(pidText) else { return nil }
                    return (pid, path)
                }
            })
        }
    }

    private static let knownForeignMarkers: [(needle: String, label: String)] = [
        ("你的代理客户端", "你的代理客户端"),
        ("lmclientCore", "你的代理客户端 lmclientCore"),
        ("Shadowrocket", "小火箭 Shadowrocket"),
        ("/Applications/Clash", "Clash"),
        ("clash-verge", "Clash Verge"),
        ("Surge", "Surge"),
        ("Stash", "Stash"),
        ("Loon", "Loon"),
        ("sing-box", "sing-box"),
        ("v2ray", "v2ray"),
        ("xray", "xray"),
    ]

    /// Privileged helpers alone do not prove traffic capture; GUI/core clients do.
    private static func isResidualPrivilegedHelper(_ path: String) -> Bool {
        path.contains("/Library/PrivilegedHelperTools/")
            || path.localizedCaseInsensitiveContains(".service.bundle")
    }

    public static func probe(effects: Effects = .live) -> Report {
        let hits = effects.listProcesses().compactMap { item -> ForeignProcess? in
            for marker in knownForeignMarkers where item.path.localizedCaseInsensitiveContains(marker.needle) {
                // Ignore our own launcher / mihomo helper strings if they appear.
                if item.path.localizedCaseInsensitiveContains("Claude Launcher") { return nil }
                if item.path.localizedCaseInsensitiveContains("router-runtime") { return nil }
                let label = isResidualPrivilegedHelper(item.path)
                    ? marker.label + " (残余 helper)"
                    : marker.label
                return .init(pid: item.pid, path: item.path, label: label)
            }
            return nil
        }
        // Deduplicate by pid.
        var seen = Set<Int32>()
        let foreign = hits.filter { seen.insert($0.pid).inserted }
        let active = foreign.filter { !isResidualPrivilegedHelper($0.path) }
        let clearOfActive = active.isEmpty
        let residualOnly = clearOfActive && !foreign.isEmpty
        return .init(
            clearWindowID: clearWindowID,
            foreignProcesses: foreign,
            looksClearOfKnownForeignClients: clearOfActive,
            canRecommendConversationGrant: clearOfActive,
            summary: {
                if clearOfActive && foreign.isEmpty {
                    return "只读进程采样未看到已知外场客户端；仍须系统 requireClear（转发 utun/VPN/系统代理）正式通过。不表示已接管。"
                }
                if residualOnly {
                    return "只读进程采样仅见残余 PrivilegedHelper（\(foreign.map(\.label).joined(separator: "、"))），未见活动客户端 GUI/core；可与 requireClear 对照后授予 \(clearWindowID)。本工具不会替你卸载 helper。"
                }
                return "只读进程采样仍看到活动外场客户端：\(active.map(\.label).joined(separator: "、"))。requireClear 会拒绝本工具 TUN；本工具不会替你退出它们。清场窗口 \(clearWindowID) 暂不可授予。"
            }(),
            routingVerified: false,
            accepted: false)
    }
}
