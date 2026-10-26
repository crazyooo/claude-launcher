import Foundation
import Darwin
import SystemConfiguration
import CFNetwork

/// Read-only portrait of how this Mac currently routes traffic.
/// Does not change routes, proxies, or TUN. Does not read Keychain or send proxy credentials.
/// Never claims Desktop/CLI success, routing_verified, or accepted.
public enum CurrentPathPortrait {
    public static let observationHosts = ["claude.ai", "api.anthropic.com", "chatgpt.com", "chat.openai.com"]

    public struct SavedLine: Equatable, Sendable {
        public let id: UUID
        public let name: String
        public let host: String
        public let port: Int
        public init(id: UUID, name: String, host: String, port: Int) {
            self.id = id; self.name = name; self.host = host; self.port = port
        }
    }

    public struct SystemProxyChannel: Equatable, Identifiable, Sendable {
        public let id: String
        public let title: String
        public let enabled: Bool
        public let host: String?
        public let port: Int?
        public let listener: String
        public init(id: String, title: String, enabled: Bool, host: String?, port: Int?, listener: String) {
            self.id = id; self.title = title; self.enabled = enabled
            self.host = host; self.port = port; self.listener = listener
        }
        public var detail: String {
            guard enabled else { return "关闭" }
            let endpoint: String
            if let host, let port { endpoint = "\(host):\(port)" }
            else { endpoint = "已启用但未读到地址" }
            return endpoint + " · " + listenerPhrase(listener)
        }
    }

    public struct TargetObservation: Equatable, Identifiable, Sendable {
        public var id: String { host }
        public let host: String
        public let resolved: String?
        public let routeInterface: String?
        public let routeKind: String
        public let reachability: String
        public init(host: String, resolved: String?, routeInterface: String?, routeKind: String, reachability: String) {
            self.host = host; self.resolved = resolved; self.routeInterface = routeInterface
            self.routeKind = routeKind; self.reachability = reachability
        }
        public var detail: String {
            let address = resolved ?? "未解析到 IPv4"
            let mapped = resolved.map(CurrentPathPortrait.isFakeMappedIPv4) == true ? "（假地址）" : ""
            let route: String
            if let routeInterface {
                route = "路由 \(routeInterface)（\(kindPhrase(routeKind))）"
            } else {
                route = "路由未确认"
            }
            return "\(address)\(mapped) · \(route) · \(reachPhrase(reachability))"
        }
    }

    public struct LineObservation: Equatable, Identifiable, Sendable {
        public var id: UUID { lineID }
        public let lineID: UUID
        public let name: String
        public let host: String
        public let port: Int
        public let routeInterface: String?
        public let routeKind: String
        public let note: String
        public init(lineID: UUID, name: String, host: String, port: Int,
                    routeInterface: String?, routeKind: String, note: String) {
            self.lineID = lineID; self.name = name; self.host = host; self.port = port
            self.routeInterface = routeInterface; self.routeKind = routeKind; self.note = note
        }
    }

    public struct Snapshot: Equatable, Sendable {
        public let capturedAt: Date
        public let summary: String
        public let findings: [String]
        public let nextSteps: [String]
        public let candidates: [SelectedProxyPath.Candidate]
        public let proxies: [SystemProxyChannel]
        public let targets: [TargetObservation]
        public let lines: [LineObservation]
        /// Always false. Recognition is not routing acceptance.
        public let routingVerified: Bool
        /// Always false. Recognition does not write accepted.
        public let accepted: Bool
        public init(capturedAt: Date, summary: String, findings: [String], nextSteps: [String] = [],
                    candidates: [SelectedProxyPath.Candidate], proxies: [SystemProxyChannel],
                    targets: [TargetObservation], lines: [LineObservation],
                    routingVerified: Bool = false, accepted: Bool = false) {
            self.capturedAt = capturedAt; self.summary = summary; self.findings = findings
            self.nextSteps = nextSteps; self.candidates = candidates; self.proxies = proxies
            self.targets = targets; self.lines = lines
            self.routingVerified = false; self.accepted = false
            _ = routingVerified; _ = accepted
        }
    }

    public struct RouteHint: Equatable, Sendable {
        public let interface: String
        public let kind: String
        public init(interface: String, kind: String) {
            self.interface = interface; self.kind = kind
        }
    }

    public struct Effects {
        public var proxies: () -> [String: Any]?
        public var listen: (String, Int) -> String
        public var resolve: (String) -> String?
        public var route: (String) -> RouteHint?
        public var reach: (String) -> String
        public var candidates: () -> [SelectedProxyPath.Candidate]
        public var lineReport: (String) -> SelectedProxyPath.Report
        public init(proxies: @escaping () -> [String: Any]?,
                    listen: @escaping (String, Int) -> String,
                    resolve: @escaping (String) -> String?,
                    route: @escaping (String) -> RouteHint?,
                    reach: @escaping (String) -> String,
                    candidates: @escaping () -> [SelectedProxyPath.Candidate],
                    lineReport: @escaping (String) -> SelectedProxyPath.Report) {
            self.proxies = proxies; self.listen = listen; self.resolve = resolve
            self.route = route; self.reach = reach; self.candidates = candidates
            self.lineReport = lineReport
        }
        public static var live: Effects {
            .init(proxies: readProxyDictionary, listen: probeListener, resolve: resolveIPv4,
                  route: routeHint, reach: reachHost, candidates: physicalCandidates,
                  lineReport: SelectedProxyPath.report)
        }
    }

    public static func capture(lines: [SavedLine], effects: Effects = .live, now: Date = Date()) -> Snapshot {
        let channels = parseProxyChannels(effects.proxies(), listen: effects.listen)
        let physical = effects.candidates()
        let targets = observationHosts.map { host -> TargetObservation in
            guard let address = effects.resolve(host) else {
                return .init(host: host, resolved: nil, routeInterface: nil, routeKind: "unknown", reachability: "unresolved")
            }
            let route = effects.route(address)
            return .init(host: host, resolved: address, routeInterface: route?.interface,
                         routeKind: route?.kind ?? "unknown", reachability: effects.reach(host))
        }
        let lineRows = lines.prefix(32).map { line -> LineObservation in
            observeLine(line, report: effects.lineReport, route: effects.route)
        }
        let findings = composeFindings(proxies: channels, candidates: physical, targets: targets, lines: lineRows)
        let nextSteps = composeNextSteps(proxies: channels, targets: targets, lines: lineRows)
        let summary = composeSummary(findings: findings, candidates: physical, proxies: channels)
        return .init(capturedAt: now, summary: summary, findings: findings, nextSteps: nextSteps,
                     candidates: physical, proxies: channels, targets: targets, lines: lineRows)
    }

    /// Clash / 增强模式常见的假地址段 198.18.0.0/15。
    public static func isFakeMappedIPv4(_ value: String) -> Bool {
        guard let text = normalizedIPv4(value) else { return false }
        let parts = text.split(separator: ".").compactMap { Int($0) }
        guard parts.count == 4 else { return false }
        return parts[0] == 198 && (parts[1] == 18 || parts[1] == 19)
    }

    static func parseProxyChannels(_ object: [String: Any]?, listen: (String, Int) -> String) -> [SystemProxyChannel] {
        let root = object ?? [:]
        func channel(id: String, title: String, enableKey: String, hostKey: String, portKey: String) -> SystemProxyChannel {
            let enabled = boolFlag(root[enableKey])
            let host = stringValue(root[hostKey])
            let port = intValue(root[portKey])
            let listener: String
            if !enabled { listener = "inactive" }
            else if let host, let port, (1...65535).contains(port) {
                listener = listen(host, port)
            } else {
                listener = "unknown"
            }
            return .init(id: id, title: title, enabled: enabled, host: host, port: port, listener: listener)
        }
        return [
            channel(id: "http", title: "HTTP", enableKey: "HTTPEnable", hostKey: "HTTPProxy", portKey: "HTTPPort"),
            channel(id: "https", title: "HTTPS", enableKey: "HTTPSEnable", hostKey: "HTTPSProxy", portKey: "HTTPSPort"),
            channel(id: "socks", title: "SOCKS", enableKey: "SOCKSEnable", hostKey: "SOCKSProxy", portKey: "SOCKSPort")
        ]
    }

    static func composeFindings(proxies: [SystemProxyChannel], candidates: [SelectedProxyPath.Candidate],
                                targets: [TargetObservation], lines: [LineObservation]) -> [String] {
        var items: [String] = []
        if candidates.isEmpty {
            items.append("没有同时具备全局 IPv4 和匹配默认路由的物理接口。不会改用系统路由冒充对照。")
        } else {
            let names = candidates.map(\.name).joined(separator: "、")
            items.append("当前可用的物理接口候选：\(names)。这些名字是现场采样，不会写死。")
        }
        for channel in proxies where channel.enabled {
            switch channel.listener {
            case "refused":
                items.append("系统\(channel.title)代理指向 \(channel.host ?? "?")：\(channel.port.map(String.init) ?? "?")，但本机该端口拒绝连接。浏览器若依赖系统代理可能打不开。")
            case "listening":
                items.append("系统\(channel.title)代理已启用，本机 \(channel.host ?? "127.0.0.1"):\(channel.port.map(String.init) ?? "?") 有进程在听。")
            case "not_local":
                items.append("系统\(channel.title)代理已启用并指向非本机地址；未在本机探测监听。")
            default:
                items.append("系统\(channel.title)代理显示已启用，但未能确认本地监听状态。")
            }
        }
        if proxies.allSatisfy({ !$0.enabled }) {
            items.append("系统 HTTP/HTTPS/SOCKS 代理均未启用。浏览器默认走系统当前路由。")
        }
        let fakeTargets = targets.filter { $0.resolved.map(isFakeMappedIPv4) == true }
        if !fakeTargets.isEmpty {
            let sample = fakeTargets.prefix(2).map(\.host).joined(separator: "、")
            items.append("观察目标（如 \(sample)）解析到 198.18.0.0/15 假地址。这通常表示增强模式/TUN 已接管 DNS；本页「不经系统代理」的探测仍会走这条隧道，不代表你没开代理。")
        }
        let tunnelTargets = targets.filter { $0.routeKind == "tunnel" }
        if !tunnelTargets.isEmpty {
            let names = Array(Set(tunnelTargets.compactMap(\.routeInterface))).sorted().joined(separator: "、")
            items.append("部分观察目标的路由经过隧道接口\(names.isEmpty ? "" : " \(names)")。不经系统代理的探测仍可能经该隧道。")
        }
        for target in targets where target.reachability == "timed_out" {
            items.append("不经系统代理探测 \(target.host) 超时。这只说明当前系统路由路径够不着，不是分流验收，也不证明代理密码错误。")
        }
        for line in lines where line.routeKind == "tunnel" {
            items.append("已保存线路「\(line.name)」入口当前经隧道。默认「测试这条线路」可能失败；可改用路径对照，或在外部隧道让开后再测。")
        }
        for line in lines where line.routeKind == "physical" {
            items.append("已保存线路「\(line.name)」入口当前走物理接口 \(line.routeInterface ?? "未知")。")
        }
        for line in lines where line.routeKind == "unknown" || line.routeKind == "hostname" {
            items.append(line.note)
        }
        items.append("本次识别不提升 routing_verified 或 accepted，也不代表 Desktop/CLI 通过或本工具已接管流量。")
        return Array(items.prefix(24))
    }

    static func composeNextSteps(proxies: [SystemProxyChannel], targets: [TargetObservation],
                                 lines: [LineObservation]) -> [String] {
        var steps: [String] = []
        let tunnelish = lines.contains(where: { $0.routeKind == "tunnel" })
            || targets.contains(where: { $0.routeKind == "tunnel" || ($0.resolved.map(isFakeMappedIPv4) == true) })
        if tunnelish {
            steps.append("测已保存线路：默认「测试这条线路」仍走系统当前路由，经隧道时可能失败。到线路旁用「路径对照」，或等外部隧道让开后再测。")
            steps.append("启用本工具分流前：到「线路与分流 → 系统流量路由」点「检查现有网络」，查看 requireClear 为何拒绝自己的 TUN。")
        } else {
            steps.append("测已保存线路：可在「线路与分流」使用「测试这条线路」。默认仍走系统当前路由。")
        }
        if proxies.contains(where: \.enabled) {
            steps.append("系统代理已启用时，浏览器可能走本机代理端口；本页观察目标故意不经系统代理，避免理解成「没开代理」。")
        }
        steps.append("再到「线路与分流」配置规则。真正按应用、浏览器、域名接管仍属后续验收。")
        steps.append("识别不会改你的代理客户端，也不会静默启用本工具自己的 TUN。")
        return Array(steps.prefix(8))
    }

    static func composeSummary(findings: [String], candidates: [SelectedProxyPath.Candidate],
                               proxies: [SystemProxyChannel]) -> String {
        let enabled = proxies.filter(\.enabled).map(\.title)
        let proxyPart = enabled.isEmpty ? "系统代理关闭" : "系统代理已开（\(enabled.joined(separator: "/"))）"
        let physicalPart = candidates.isEmpty ? "无合格物理候选" : "物理候选 \(candidates.map(\.name).joined(separator: "、"))"
        let head = findings.first(where: { $0.contains("假地址") || $0.contains("隧道") || $0.contains("超时") }) ?? findings.first
        let focus = head.map { "要点：\($0)" } ?? "已完成只读采样。"
        return "当前走线已识别（只读）。\(proxyPart)；\(physicalPart)。\(focus) 识别不是分流验收。"
    }

    static func observeLine(_ line: SavedLine, report: (String) -> SelectedProxyPath.Report,
                            route: (String) -> RouteHint?) -> LineObservation {
        if let ipv4 = normalizedIPv4(line.host) {
            let value = report(ipv4)
            let routed = route(ipv4)
            return .init(lineID: line.id, name: line.name, host: line.host, port: line.port,
                         routeInterface: routed?.interface, routeKind: routed?.kind ?? value.routeKind,
                         note: value.summary)
        }
        return .init(lineID: line.id, name: line.name, host: line.host, port: line.port,
                     routeInterface: nil, routeKind: "hostname",
                     note: "线路「\(line.name)」入口不是 IPv4 数字地址，本次不解析其路由，避免经隧道做 DNS。")
    }

    // MARK: - Live effects

    static func readProxyDictionary() -> [String: Any]? {
        if let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] { return values }
        return CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
    }

    public static func probeListener(_ host: String, _ port: Int) -> String {
        guard (1...65535).contains(port) else { return "unknown" }
        let cleaned = host.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let loopback = cleaned == "127.0.0.1" || cleaned == "localhost" || cleaned == "::1"
        guard loopback else { return "not_local" }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return "unknown" }
        defer { close(fd) }
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { return "unknown" }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = UInt16(port).bigEndian
        guard inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1 else { return "unknown" }
        let started = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        if started == 0 { return "listening" }
        if errno == ECONNREFUSED { return "refused" }
        guard errno == EINPROGRESS else { return "unknown" }
        var pollfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
        let wait = poll(&pollfd, 1, 400)
        if wait == 0 { return "unknown" }
        var error: Int32 = 0
        var length = socklen_t(MemoryLayout<Int32>.size)
        guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 else { return "unknown" }
        if error == 0 { return "listening" }
        if error == ECONNREFUSED { return "refused" }
        return "unknown"
    }

    static func resolveIPv4(_ host: String) -> String? {
        guard host.utf8.count <= 253, host.allSatisfy({ $0.isASCII }), !host.contains(" ") else { return nil }
        let output = ReadCommand.run("/usr/bin/dig", ["+time=2", "+tries=1", "+short", host, "A"],
                                     timeout: 3, environment: cleanEnvironment)
        guard output.code == 0 else { return nil }
        for line in output.text.components(separatedBy: .newlines) {
            let text = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if let ipv4 = normalizedIPv4(text) { return ipv4 }
        }
        return nil
    }

    static func physicalCandidates() -> [SelectedProxyPath.Candidate] {
        SelectedProxyPath.report("1.1.1.1").candidates
    }

    static func routeHint(_ address: String) -> RouteHint? {
        guard let ipv4 = normalizedIPv4(address) else { return nil }
        let output = ReadCommand.run("/sbin/route", ["-n", "get", ipv4], timeout: 2, environment: cleanEnvironment)
        guard output.code == 0, let route = SelectedProxyPath.parseRoute(output.text, expecting: ipv4) else { return nil }
        return .init(interface: route.interface, kind: route.kind)
    }

    static func reachHost(_ host: String) -> String {
        guard host.utf8.count <= 253, host.allSatisfy({ $0.isASCII }) else { return "skipped" }
        let url = "https://\(host)/"
        let output = ReadCommand.run("/usr/bin/curl", [
            "-sS", "-o", "/dev/null", "-w", "%{http_code}",
            "--connect-timeout", "5", "--max-time", "8",
            "-I", "--noproxy", "*", "--proto-default", "https",
            "--tlsv1.2", "--tls-max", "1.3", url
        ], timeout: 10, environment: cleanEnvironment)
        if output.code == 28 || output.text.contains("timed out") || output.text.contains("Timeout") {
            return "timed_out"
        }
        if output.code == 0, let code = Int(output.text.trimmingCharacters(in: .whitespacesAndNewlines)), code > 0 {
            return "reached_\(code)"
        }
        if output.code == 7 { return "refused" }
        return "unreachable"
    }

    private static let cleanEnvironment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]

    private static func boolFlag(_ value: Any?) -> Bool {
        if let number = value as? NSNumber { return number != 0 }
        if let number = value as? Int { return number != 0 }
        if let number = value as? Bool { return number }
        return false
    }
    private static func stringValue(_ value: Any?) -> String? {
        guard let text = value as? String else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
    private static func intValue(_ value: Any?) -> Int? {
        if let number = value as? Int { return number }
        if let number = value as? NSNumber { return number.intValue }
        if let text = value as? String { return Int(text) }
        return nil
    }
    private static func listenerPhrase(_ code: String) -> String {
        switch code {
        case "listening": return "本机有监听"
        case "refused": return "本机端口拒绝连接"
        case "not_local": return "非本机地址，未测监听"
        case "inactive": return "未启用"
        default: return "监听未确认"
        }
    }
    private static func kindPhrase(_ kind: String) -> String {
        switch kind {
        case "tunnel": return "隧道"
        case "physical": return "物理"
        case "loopback": return "回环"
        default: return "未知"
        }
    }
    private static func reachPhrase(_ code: String) -> String {
        if code.hasPrefix("reached_") { return "不经系统代理有回应（HTTP \(code.dropFirst(8))）" }
        switch code {
        case "timed_out": return "不经系统代理超时"
        case "refused": return "不经系统代理被拒绝"
        case "unresolved": return "未解析"
        case "skipped": return "未探测"
        default: return "不经系统代理未确认"
        }
    }
}
