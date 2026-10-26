import Foundation
import AppKit

/// Consent is independent of protected-mode acceptance and survives no policy revision.
public struct OfficialDesktopConsent: Codable, Equatable {
    public var revision: Int
    public var acceptedAt: Date
    public init() { revision = 1; acceptedAt = Date() }
    public var valid: Bool { revision == 1 }
}
public struct ProxyCheckEvidence: Codable {
    public var sampledAt: Date
    public var configDigest: String
    public var expectedIPMatched: Bool
    public func current(for digest: String, now: Date = Date()) -> Bool {
        let age = now.timeIntervalSince(sampledAt)
        return expectedIPMatched && configDigest == digest && age >= 0 && age <= 30
    }
}
public enum OfficialDesktopPolicy {
    public static let explanation = "此模式检查已配置的代理出口，然后普通打开官方 Claude。Claude 使用自身或系统网络设置，启动器不能确认其实际出口相同，也不管理它的进程隔离或故障断流。"
    public static func allows(_ config: Configuration, _ snapshot: Snapshot) -> Bool {
        config.officialDesktopConsent?.valid == true && snapshot.fresh && snapshot.gatewayReady &&
        ["connection-ready", "ready", "running"].contains(snapshot.state) &&
        snapshot.configDigest == config.digest && snapshot.desktopMode == "connection-checked-official" &&
        snapshot.proxyCheck?.current(for:config.digest) == true &&
        normalizedIP(snapshot.observedIP ?? "") == normalizedIP(config.expectedIP)
    }
}
public enum OfficialDesktopLauncher {
    /// This is a native app launch, not the protected sandbox path. No proxy flags,
    /// environment injection, app modifications, or --no-sandbox are used.
    public static func openAfterCheck() throws {
        try StrictProtection.requireVerified()
        let initial = try loadJSON(Configuration.self,from:Paths.config); try initial.validate()
        guard initial.officialDesktopConsent?.valid == true else { throw LauncherError.message("请先确认普通启动模式的边界") }
        var state = try Control.request("check-connection")
        guard state.state != "check-busy" else { throw LauncherError.message("已有检查正在进行，请稍后再打开") }
        let deadline = Date().addingTimeInterval(13)
        while state.state == "checking", Date() < deadline {
            Thread.sleep(forTimeInterval:0.15)
            state = try Control.request("status")
        }
        let current = try loadJSON(Configuration.self,from:Paths.config)
        guard current.digest == initial.digest, OfficialDesktopPolicy.allows(current,state) else { throw LauncherError.message("代理检查未通过或已失效，未打开 Claude") }
        let application = URL(fileURLWithPath:"/Applications/Claude.app")
        guard Bundle(url:application)?.bundleIdentifier == "com.anthropic.claudefordesktop" else { throw LauncherError.message("未找到官方 Claude 应用") }
        let configuration = NSWorkspace.OpenConfiguration(); configuration.activates = true
        var outcome: Result<Void,Error>?
        NSWorkspace.shared.openApplication(at:application,configuration:configuration) { running, error in
            DispatchQueue.main.async {
                if let error { outcome = .failure(error) }
                else if running != nil { outcome = .success(()) }
                else { outcome = .failure(LauncherError.message("系统未返回 Claude 应用实例")) }
            }
        }
        let openedDeadline = Date().addingTimeInterval(15)
        while outcome == nil && Date() < openedDeadline { RunLoop.main.run(until:Date().addingTimeInterval(0.05)) }
        guard let outcome else { throw LauncherError.message("打开请求已提交，但系统响应超时；请查看 Claude 窗口") }
        try outcome.get()
    }
}

extension Snapshot {
    /// Successful proxy evidence does not confer protected-client acceptance.
    mutating func recordProxyCheck(ip: String, at time: Date, config: Configuration) {
        observedIP = ip
        lastExitCheck = time
        proxyCheck = ProxyCheckEvidence(sampledAt: time, configDigest: config.digest,
                                       expectedIPMatched: normalizedIP(ip) == normalizedIP(config.expectedIP))
        state = networkAllowed ? (sessions > 0 ? "running" : "ready") : "connection-ready"
        faultTime = nil
        reason = "代理出口已核对；桌面普通启动不受断流管理"
    }
}
