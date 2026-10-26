import Foundation
import Darwin

public enum DetectorEvent: String, Codable {
    case checked, networkChanged, settingsChanged, sleepWake, discarded, storageFailed
    public var title: String {
        switch self {
        case .checked: return "检测完成"
        case .networkChanged: return "网络配置变化，旧结果失效"
        case .settingsChanged: return "检测设置变化"
        case .sleepWake: return "睡眠／唤醒，旧结果失效"
        case .discarded: return "已忽略过期的检测任务"
        case .storageFailed: return "本地记录不可读或不可写"
        }
    }
}

/// Persist classifications, never arbitrary subprocess output, configuration or check details.
public enum DetectorProblem: String, Codable {
    case none, dns, connection, timeout, tls, exitMismatch, pathUnknown, configuration, service, other
    public var advice: String {
        switch self {
        case .none: return "本轮检测完成；结论仅对应所列路径与时间。"
        case .dns: return "检查代理是否连接，以及目标域名能否解析。"
        case .connection: return "检查代理客户端和本地入口端口，再重新检测。"
        case .timeout: return "检查线路连通性，稍后手动重新检测。"
        case .tls: return "核对系统时间、证书和代理设置；不要关闭 TLS 校验。"
        case .exitMismatch: return "核对 Claude 域名分流和所选线路；不要直接把新出口当作确认基准。"
        case .pathUnknown: return "查看路径来源；CLI 请在实际终端和项目目录运行检测命令。"
        case .configuration: return "核对检测设置和客户端网络配置；工具不会代你改写代理。"
        case .service: return "已取得服务异常响应；检查详情中的 HTTP 状态后再试。"
        case .other: return "查看检查详情中的阶段与结果码，处理后重新检测。"
        }
    }
    public static func classify(_ code: String) -> Self {
        // Input selects a fixed enum only. Unknown strings are never written to disk.
        if code.contains("tls") || code.contains("certificate") { return .tls }
        if code.contains("timeout") { return .timeout }
        if code.contains("dns") || code.contains("resolve") { return .dns }
        if code.contains("mismatch") && (code.contains("exit") || code.contains("ip")) { return .exitMismatch }
        if code.contains("connect") { return .connection }
        if code.contains("route") || code.contains("proxy") || code.contains("snapshot") || code.contains("trace") { return .pathUnknown }
        if code.contains("config") || code.contains("baseline") || code.contains("changed") { return .configuration }
        if code.contains("http") || code.contains("service") { return .service }
        return .other
    }
}

// Immutable value fields only; legacy CheckResult predates Sendable annotations.
public struct DetectorLogEntry: Codable, Identifiable, @unchecked Sendable {
    public let id: UUID
    public let at: Date
    public let event: DetectorEvent
    public let target: EnvironmentTarget?
    public let result: CheckResult?
    public let problem: DetectorProblem
    public init(event: DetectorEvent, target: EnvironmentTarget? = nil, result: CheckResult? = nil,
                problem: DetectorProblem = .none, at: Date = Date()) {
        id = UUID(); self.at = at; self.event = event; self.target = target
        self.result = result; self.problem = problem
    }
}

public enum WebsiteResult: String, CaseIterable, Codable {
    case clear = "未发现明显问题", issue = "发现问题", uncertain = "仍不确定"
}

/// Browser Claude check on IPSuper. Do not reverse `api.ipsuper.com` crypto.
public enum IPSuperDetection: String, CaseIterable, Identifiable, Sendable {
    case claude = "IPSuper · Claude 环境检测"

    public var id: String { rawValue }
    public var url: String {
        switch self {
        case .claude: return "https://ipsuper.com/claude/"
        }
    }
}

/// Browser Claude check / guides on Net.Coffee.
public enum NetCoffeeDetection: String, CaseIterable, Identifiable, Sendable {
    case claude = "Net.Coffee · Claude 环境检测"
    /// Stable-use checklist; product「检查详情」围绕此页。
    case claudeCodeGuide = "Net.Coffee · Claude Code 稳定使用指南"

    public var id: String { rawValue }
    public var url: String {
        switch self {
        case .claude: return "https://ip.net.coffee/claude/"
        case .claudeCodeGuide: return "https://ip.net.coffee/claude/claudecode.html"
        }
    }
}

/// Product UI shows exactly these two browser Claude pages.
public enum BrowserSupplementPage: Identifiable, Sendable {
    case ipSuper(IPSuperDetection)
    case netCoffee(NetCoffeeDetection)

    public var id: String {
        switch self {
        case .ipSuper(let page): return page.id
        case .netCoffee(let page): return page.id
        }
    }

    public var title: String {
        switch self {
        case .ipSuper(let page): return page.rawValue
        case .netCoffee(let page): return page.rawValue
        }
    }

    public var url: String {
        switch self {
        case .ipSuper(let page): return page.url
        case .netCoffee(let page): return page.url
        }
    }

    public static let allPages: [BrowserSupplementPage] = [
        .ipSuper(.claude),
        .netCoffee(.claude),
    ]

    /// Same two pages opened by one-click detect.
    public static let oneClickPages: [BrowserSupplementPage] = allPages
}

public struct WebsiteObservation: Codable {
    /// Default browser supplement page: IPSuper Claude environment check.
    public static let source = IPSuperDetection.claude.url
    /// Additional Claude browser check (recorded separately by the user if desired).
    public static let netCoffeeSource = NetCoffeeDetection.claude.url
    public let observedAt: Date
    public let savedAt: Date
    public let observedIP: String
    public let result: WebsiteResult
    public let network: String
    public let settings: String
    public let session: UUID
    public init(observedAt: Date, observedIP: String, result: WebsiteResult, network: String,
                settings: String, session: UUID, now: Date = Date()) throws {
        guard observedAt <= now, observedAt.timeIntervalSince1970.isFinite,
              !network.isEmpty, let ip = normalizedIP(observedIP) else {
            throw LauncherError.message("请填写实际检测时间及有效出口 IP；检测时间不能晚于现在。")
        }
        self.observedAt = observedAt; savedAt = now; self.observedIP = ip; self.result = result
        self.network = network; self.settings = settings; self.session = session
    }
    public func isRecent(network: String, settings: String, session: UUID, now: Date) -> Bool {
        self.session == session && self.network == network && self.settings == settings &&
            observedAt <= savedAt && savedAt <= now && now.timeIntervalSince(observedAt) <= 600
    }
}

/// One bounded JSON log. Replacement is atomic; corrupt existing files are preserved.
public final class DetectorRecords: @unchecked Sendable {
    public static let capacity = 10 * 1024 * 1024
    public let root: URL
    private let limit: Int
    private let lock = NSLock()
    public init(root: URL = Paths.root, capacity: Int = DetectorRecords.capacity) {
        self.root = root; limit = max(1024, min(capacity, Self.capacity))
    }
    private func read<T: Decodable>(_ type: T.Type, name: String, maximum: Int) throws -> T? {
        guard let data = try EnvironmentStorage.readBytes(root.appendingPathComponent(name), maximum: maximum) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }
    private func write(_ data: Data, name: String) throws {
        try EnvironmentStorage.writeBytes(data, to: root.appendingPathComponent(name), maximum: Self.capacity)
    }
    public func logs() throws -> [DetectorLogEntry] {
        lock.lock(); defer { lock.unlock() }
        return try read([DetectorLogEntry].self, name: "detector-events.json", maximum: Self.capacity) ?? []
    }
    public func append(_ entry: DetectorLogEntry) throws {
        try append([entry])
    }
    public func append(_ additions: [DetectorLogEntry]) throws {
        lock.lock(); defer { lock.unlock() }
        try EnvironmentStorage.withLock(at: root.appendingPathComponent("detector-events.lock")) {
        var entries = try read([DetectorLogEntry].self, name: "detector-events.json", maximum: Self.capacity) ?? []
        entries.append(contentsOf: additions)
        let encoder = JSONEncoder()
        var data = try encoder.encode(entries)
        while data.count > limit && entries.count > 1 {
            entries.removeFirst(max(1, entries.count / 8)); data = try encoder.encode(entries)
        }
        guard data.count <= limit else { throw LauncherError.message("检测日志超过容量限制。") }
        try write(data, name: "detector-events.json")
        }
    }
    public func website() throws -> WebsiteObservation? {
        lock.lock(); defer { lock.unlock() }
        return try read(WebsiteObservation.self, name: "detector-website.json", maximum: 16384)
    }
    public func saveWebsite(_ value: WebsiteObservation) throws {
        lock.lock(); defer { lock.unlock() }
        try EnvironmentStorage.withLock(at: root.appendingPathComponent("detector-website.lock")) {
        _ = try read(WebsiteObservation.self, name: "detector-website.json", maximum: 16384)
        try write(JSONEncoder().encode(value), name: "detector-website.json")
        }
    }
    public func export() throws -> Data {
        // Typed decode/encode intentionally excludes all unknown fields, IPs and configuration.
        let entries = try logs()
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        return try encoder.encode(entries)
    }
}
