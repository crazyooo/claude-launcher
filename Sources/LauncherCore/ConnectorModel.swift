import Foundation
import Darwin

public struct ConnectorConfiguration: Codable, Equatable, Sendable {
    public var version = 1
    public var upstreamProtocol = "http"
    public var upstreamHost = "127.0.0.1"
    public var upstreamPort = 1082
    public var expectedIPv4 = "203.0.113.43"
    // Decode legacy values so they can be explicitly rejected, never silently cleared.
    public var expectedIPv6 = ""
    public var listenPort = 0
    public init() {}
    public static let hosts = ["claude.ai", "api.anthropic.com", "platform.claude.com"]
    public static let url = Paths.root.appendingPathComponent("connector.json")
    public func validate() throws {
        guard expectedIPv6.isEmpty else {
            throw LauncherError.message("旧设置含 IPv6 出口基准；请明确移除后重新检查。当前仅接受 IPv4 出口。")
        }
        guard version == 1, ["http", "socks5"].contains(upstreamProtocol),
              upstreamHost == "127.0.0.1", (1...65535).contains(upstreamPort),
              listenPort == 0 || (1024...65535).contains(listenPort), listenPort != upstreamPort,
              normalizedIPv4(expectedIPv4) != nil else {
            throw LauncherError.message("连接器配置无效：仅支持 127.0.0.1 上游、独立监听端口和固定 IPv4 出口。")
        }
    }
    public var upstreamLabel: String { "\(upstreamProtocol)://\(upstreamHost == "::1" ? "[::1]" : upstreamHost):\(upstreamPort)" }
    public var digest: String {
        let encoder = JSONEncoder(); encoder.outputFormatting = .sortedKeys
        return ManagedAddressPolicy.fingerprint((try? encoder.encode(self)) ?? Data())
    }
    public func matches(_ ip: String) -> Bool {
        guard expectedIPv6.isEmpty, let observed = normalizedIPv4(ip),
              let expected = normalizedIPv4(expectedIPv4) else { return false }
        return observed == expected
    }
    public static func read() throws -> Self { let value = try loadJSON(Self.self, from: url); try value.validate(); return value }
}

/// Includes system sleep; wall-clock changes cannot renew a heartbeat or a grant.
func connectorTime() -> Double {
    var base = mach_timebase_info_data_t(); mach_timebase_info(&base)
    return Double(mach_continuous_time()) * Double(base.numer) / Double(base.denom) / 1_000_000_000
}

public struct ConnectorConnection: Codable, Identifiable, Sendable {
    public let id: UUID
    public let host: String
    public let port: UInt16
    public let startedAt: Date
    public var uploaded: UInt64 = 0
    public var downloaded: UInt64 = 0
    public let probe: Bool
}
public struct ConnectorEvent: Codable, Identifiable, Sendable {
    public var id = UUID()
    public var time = Date()
    public let code: String
}
public struct ConnectorSnapshot: Codable, Sendable {
    public var version = 1
    public var instanceID = UUID()
    public var sampledAt = Date()
    public var port: UInt16 = 0
    public var state = "starting"
    public var reason = "starting"
    public var epoch: UInt64 = 0
    public var heartbeatAge: Double = 0
    public var configDigest = ""
    public var upstream = ""
    public var connections: [ConnectorConnection] = []
    public var connectionCount = 0
    public var uploaded: UInt64 = 0
    public var downloaded: UInt64 = 0
    public var events: [ConnectorEvent] = []
    public var observedIP: String?
    public var checkedAt: Date?
    public var protectionVerified = false
    public var launchAuthorized = false
    public var transactionProtocol: Int?
    public var controlProtocol: Int?
    public var coordinatedOperation: String?
    public var transaction: ConnectorTransactionStatus?
    public var holdProtocol: Int?
    public var gatewayLifetime: ConnectorLifetimeIdentity?
    public var hold: ConnectorHoldStatus?
    public init() {}
    public func isCurrent(at now: Date = Date()) -> Bool {
        version == 1 && port > 0 && ["blocked", "checking", "allowed"].contains(state) && !protectionVerified && !launchAuthorized &&
        now >= sampledAt && now.timeIntervalSince(sampledAt) < 4 && heartbeatAge >= 0 && heartbeatAge < 3
    }
    public var trafficEnabled: Bool { state == "allowed" }
    public var explanation: String {
        switch reason {
        case "hold_establishing": return "统一恢复已要求暂停转发；需核对排空状态后才能进入管理员复检。"
        case "orphan_hold": return "存在上次未完成的恢复操作；保持阻断，需明确清理原操作并重启连接器。"
        case "manual_check_passed", "periodic_check_passed": return "连接器出口核对通过；仅经过此连接器的流量受转发控制。应用完整隔离仍待验收。"
        case "heartbeat_expired": return "守卫心跳中断，连接器已关闭转发。"
        case "manual_block": return "已暂停转发，现有连接已关闭。"
        case "probe_failed": return "目标域名探测失败；连接器保持阻断。"
        case "exit_mismatch": return "目标探测出口与固定基准不一致；连接器保持阻断。"
        case "network_changed": return "网络变化或睡眠唤醒，需手动复检。"
        case "upstream_failed": return "上游连接失败，全部转发已阻断。"
        case "configuration_changed": return "配置发生变化，需重新启动连接器并复检。"
        case "gateway_exited": return "连接器进程已退出；需要重新启动并检查。"
        case "checking": return "正在经连接器核对三个目标域名的出口。"
        case "port_conflict": return "监听端口不可用；没有改用直连。"
        default: return "连接器已准备，等待手动检查。完整保护尚未验收。"
        }
    }
}

enum ConnectorOperation: String, Codable {
    case heartbeat, block, beginProbe, revokeProbe, allow, renew
    case reserveTransaction, beginTransactionProbe, prepareTransaction, commitTransaction, cancelTransaction, leaveCoordinatedMode
    case hold, attachTransaction, cancelHold, leaveHold
}
struct ConnectorGatewayCommand: Codable {
    var id = UUID()
    let operation: ConnectorOperation
    var epoch: UInt64 = 0
    var checkID: UUID?
    var authorization: String?
    var manual = false
    var reason: String?
    var transaction: ConnectorTransactionBinding?
    var samples: [String: String]?
    var services: [String: ConnectorServiceResponse]?
    var hold: ConnectorHoldBinding?
}
struct ConnectorGatewayReply: Codable, Sendable {
    let commandID: UUID?
    let accepted: Bool
    let snapshot: ConnectorSnapshot
}

struct ConnectorGrant {
    private(set) var epoch: UInt64 = 0
    private(set) var allowed = false
    private(set) var lastHeartbeat: Double?
    private(set) var evidenceDeadline: Double = 0
    private(set) var capability: Capability?
    private var receipt: Capability?
    struct Capability {
        let id: UUID
        let epoch: UInt64
        let authorization: String
        let deadline: Double
        let manual: Bool
        var remaining: [String: Int]
        var consumed: Bool { remaining.values.allSatisfy { $0 == 0 } }
    }
    mutating func heartbeat(_ now: Double) { lastHeartbeat = now }
    func heartbeatCurrent(_ now: Double) -> Bool { lastHeartbeat.map { now >= $0 && now - $0 < 3 } == true }
    mutating func block() { if epoch < UInt64.max { epoch += 1 }; allowed = false; capability = nil; receipt = nil; evidenceDeadline = 0 }
    mutating func transactionProbe(id: UUID, token: String, now: Double, deadline: Double) -> Bool {
        guard now < deadline, heartbeatCurrent(now), !allowed, capability == nil, token.utf8.count == 64,
              token.allSatisfy({ $0.isHexDigit && $0.isASCII }) else { return false }
        receipt = nil
        capability = .init(id: id, epoch: epoch, authorization: "Basic " + Data("probe:\(token)".utf8).base64EncodedString(),
                           deadline: min(now + 12, deadline), manual: true,
                           remaining: ["claude.ai": 2, "api.anthropic.com": 2, "platform.claude.com": 1])
        return true
    }
    mutating func shortenDeadline(to deadline: Double) { evidenceDeadline = min(evidenceDeadline, deadline) }
    mutating func begin(id: UUID, token: String, manual: Bool, now: Double) -> Bool {
        guard !manual || epoch < UInt64.max, heartbeatCurrent(now), capability == nil, token.utf8.count == 64,
              token.allSatisfy({ $0.isHexDigit && $0.isASCII }), manual || (allowed && now < evidenceDeadline) else { return false }
        if manual { block() }
        receipt = nil
        capability = .init(id: id, epoch: epoch, authorization: "Basic " + Data("probe:\(token)".utf8).base64EncodedString(),
                           deadline: now + 12, manual: manual,
                           remaining: Dictionary(uniqueKeysWithValues: ConnectorConfiguration.hosts.map { ($0, 1) }))
        return true
    }
    mutating func authorize(target: Target, connect: Bool, auth: String?, now: Double) -> Bool? {
        guard target.permitsProxyForwarding, heartbeatCurrent(now) else { return nil }
        if let auth {
            guard var item = capability, item.epoch == epoch, now < item.deadline, connect,
                  target.port == 443, auth == item.authorization,
                  let count = item.remaining[target.host.lowercased()], count > 0 else { return nil }
            item.remaining[target.host.lowercased()] = count - 1
            capability = item; return true
        }
        return allowed && now < evidenceDeadline ? false : nil
    }
    mutating func revoke(id: UUID, now: Double) -> Bool {
        guard let item = capability, item.id == id, item.epoch == epoch, now < item.deadline else { return false }
        receipt = item; capability = nil; return true
    }
    mutating func revokeCompletedTransaction(id: UUID, now: Double) -> Bool {
        guard capability?.consumed == true else { return false }
        return revoke(id: id, now: now)
    }
    mutating func commit(id: UUID, manual: Bool, now: Double) -> Bool {
        guard let item = receipt, item.id == id, item.epoch == epoch, item.consumed,
              item.manual == manual, heartbeatCurrent(now), now < item.deadline,
              manual || (allowed && now < evidenceDeadline) else { return false }
        // Lease is based on probe start, never reset to its completion time.
        evidenceDeadline = item.deadline - 12 + 40
        allowed = true; receipt = nil; return true
    }
    func expired(_ now: Double) -> Bool {
        !heartbeatCurrent(now) || (allowed && now >= evidenceDeadline) || capability.map { now >= $0.deadline } == true
    }
}
