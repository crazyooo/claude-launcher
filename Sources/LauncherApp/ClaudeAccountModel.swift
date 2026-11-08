import Foundation
import SwiftUI

struct ClaudeAccountIdentity: Equatable {
    var label: String?
    var email: String?
    var organization: String?
    var subscription: String?

    var hasDisplay: Bool {
        !(label ?? "").isEmpty || !(email ?? "").isEmpty || !(organization ?? "").isEmpty
    }

    static func parse(_ value: [String: Any]?) -> ClaudeAccountIdentity {
        guard let value else { return .init() }
        return .init(
            label: value["label"] as? String ?? value["display_name"] as? String ?? value["full_name"] as? String,
            email: value["email"] as? String,
            organization: Self.meaningfulOrganization(value["organization"] as? String),
            subscription: value["subscription"] as? String
        )
    }

    /// Hide Claude's auto personal labels like "email's Organization".
    static func meaningfulOrganization(_ value: String?) -> String? {
        guard var text = value?.trimmingCharacters(in: .whitespacesAndNewlines), !text.isEmpty else {
            return nil
        }
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
        let lower = text.lowercased()
        if lower == "organization" || lower == "personal" || lower == "default" {
            return nil
        }
        if lower.range(of: #"'s\s+organization\s*$"#, options: .regularExpression) != nil {
            return nil
        }
        return text
    }
}

struct ClaudeAccountUsage: Equatable {
    var subscription: String?
    var sessionPercent: Double?
    var weekPercent: Double?
    var sessionResets: String?
    var weekResets: String?
    var fetchedAt: String?

    var hasDisplay: Bool {
        subscription != nil || sessionPercent != nil || weekPercent != nil
    }

    var planLabel: String {
        switch (subscription ?? "").lowercased() {
        case "", "free", "none", "claude_free", "claude_ai": return "Free"
        case "pro", "claude_pro": return "Pro"
        case "max", "claude_max", "ultra": return "Max"
        case "team", "claude_team": return "Team"
        case "enterprise", "claude_enterprise": return "Enterprise"
        default: return subscription ?? "未知"
        }
    }

    static func parse(_ value: [String: Any]?) -> ClaudeAccountUsage {
        guard let value else { return .init() }
        let session = value["session"] as? [String: Any]
        let week = value["week"] as? [String: Any]
        return .init(
            subscription: value["subscription"] as? String,
            sessionPercent: number(session?["utilization"]),
            weekPercent: number(week?["utilization"]),
            sessionResets: session?["resets_at"] as? String,
            weekResets: week?["resets_at"] as? String,
            fetchedAt: value["fetched_at"] as? String
        )
    }

    private static func number(_ value: Any?) -> Double? {
        if let value = value as? Double { return value }
        if let value = value as? Int { return Double(value) }
        if let value = value as? NSNumber { return value.doubleValue }
        return nil
    }
}

struct ClaudeAccountSlot: Identifiable, Equatable {
    var id: String { name }
    let name: String
    let isCurrent: Bool
    let hasArchive: Bool
    let sizeBytes: Int
    let mtime: String?
    let identity: ClaudeAccountIdentity
    let usage: ClaudeAccountUsage

    var subtitle: String {
        if isCurrent { return "当前" }
        if hasArchive { return "已保存" }
        return "空位"
    }

    static func formatBytes(_ value: Int) -> String {
        if value < 1024 { return "\(value) B" }
        let units = ["KB", "MB", "GB"]
        var size = Double(value)
        var index = -1
        while size >= 1024 && index < units.count - 1 {
            size /= 1024
            index += 1
        }
        return String(format: "%.1f %@", size, units[max(0, index)])
    }
}

@MainActor final class ClaudeAccountModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var refreshing = false
    @Published private(set) var operationTitle = ""
    @Published private(set) var message = ""
    @Published private(set) var current: String?
    @Published private(set) var liveExists = false
    @Published private(set) var desktopRunning = false
    static let slotNames = ["A", "B", "C", "D"]
    @Published private(set) var slots: [ClaudeAccountSlot] = slotNames.map {
        .init(name: $0, isCurrent: false, hasArchive: false, sizeBytes: 0, mtime: nil, identity: .init(), usage: .init())
    }
    @Published private(set) var liveIdentity = ClaudeAccountIdentity()
    @Published var openAfterSwitch: Bool {
        didSet { defaults.set(openAfterSwitch, forKey: Self.openKey) }
    }

    private let effects: ClaudeProtectEffects
    private let toolsRoot: String
    private let defaults: UserDefaults
    private static let openKey = "claude.account.openAfterSwitch"
    private var script: String { toolsRoot + "/claude_account_switch.py" }

    init(
        effects: ClaudeProtectEffects = ClaudeProtectEffects(),
        toolsRoot: String? = nil,
        defaults: UserDefaults = .standard
    ) {
        self.effects = effects
        self.toolsRoot = toolsRoot ?? Bundle.main.resourceURL?.path
            ?? FileManager.default.currentDirectoryPath + "/tools"
        self.defaults = defaults
        openAfterSwitch = defaults.object(forKey: Self.openKey) as? Bool ?? false
    }

    func refresh() {
        guard !refreshing else { return }
        refreshing = true
        Task {
            defer { refreshing = false }
            let reply = await run(["status"], timeout: 20)
            applyStatus(reply)
        }
    }

    func switchTo(_ slot: String) {
        guard !busy, Self.slotNames.contains(slot) else { return }
        busy = true
        message = ""
        operationTitle = "正在切换到账号 \(slot)…"
        Task {
            defer {
                busy = false
                operationTitle = ""
                refresh()
            }
            var args = ["switch", "--to", slot, "--i-confirm-switch"]
            if openAfterSwitch { args.append("--open") }
            let reply = await run(args, timeout: 120)
            if reply.succeeded, let json = reply.json, json["ok"] as? Bool == true {
                let opened = json["opened"] as? Bool ?? false
                if json["status"] as? String == "already_current" {
                    message = "当前已是账号 \(slot)" + (opened ? "；已尝试打开 Claude。" : "。")
                } else {
                    message = "已切换到账号 \(slot)" + (opened ? "，并尝试打开 Claude。" : "。未自动打开 Claude。")
                }
                if let openError = json["open_error"] as? String, !openError.isEmpty {
                    message += " 打开 Claude 未成功，请手动打开。"
                }
            } else {
                message = "切换未完成：" + Self.failure(reply)
            }
        }
    }

    func adoptCurrent(as slot: String) {
        guard !busy, Self.slotNames.contains(slot) else { return }
        busy = true
        message = ""
        operationTitle = "正在保存为账号 \(slot)…"
        Task {
            defer {
                busy = false
                operationTitle = ""
                refresh()
            }
            let reply = await run(["adopt", "--as", slot, "--i-confirm-adopt"], timeout: 120)
            if reply.succeeded, reply.json?["ok"] as? Bool == true {
                message = "已保存为账号 \(slot)。空位可用来登录其他账号。"
            } else {
                message = "保存未完成：" + Self.failure(reply)
            }
        }
    }

    func refreshUsage(for slot: String? = nil) {
        let target = slot ?? current
        guard !busy, let target, Self.slotNames.contains(target) else {
            message = "请先保存或选择一个账号，再刷新额度。"
            return
        }
        busy = true
        message = ""
        operationTitle = "正在读取账号 \(target) 的订阅与额度…"
        Task {
            defer {
                busy = false
                operationTitle = ""
                refresh()
            }
            let reply = await run(
                ["refresh-usage", "--slot", target, "--i-confirm-refresh-usage"],
                timeout: 60
            )
            if reply.succeeded, let json = reply.json, json["ok"] as? Bool == true,
               let usage = json["usage"] as? [String: Any] {
                let parsed = ClaudeAccountUsage.parse(usage)
                message = "已更新账号 \(target)：\(parsed.planLabel)"
                    + (parsed.sessionPercent.map { String(format: " · 会话 %.0f%%", $0) } ?? "")
                    + (parsed.weekPercent.map { String(format: " · 本周 %.0f%%", $0) } ?? "")
            } else {
                message = "额度未取得：" + Self.failure(reply)
            }
        }
    }

    private func applyStatus(_ reply: ProtectCommandResult) {
        guard let json = reply.json,
              json["product"] as? String == "claude_account_switch",
              json["ok"] as? Bool == true else {
            message = refreshing && message.isEmpty ? "账号状态未取得：" + Self.failure(reply) : message
            if message.isEmpty { message = "账号状态未取得：" + Self.failure(reply) }
            return
        }
        current = json["current"] as? String
        liveExists = json["live_exists"] as? Bool ?? false
        desktopRunning = json["desktop_running"] as? Bool ?? false
        liveIdentity = .parse(json["live_identity"] as? [String: Any])
        var next: [ClaudeAccountSlot] = []
        if let map = json["slots"] as? [String: Any] {
            for name in Self.slotNames {
                let item = map[name] as? [String: Any] ?? [:]
                next.append(.init(
                    name: name,
                    isCurrent: item["is_current"] as? Bool ?? false,
                    hasArchive: item["has_archive"] as? Bool ?? false,
                    sizeBytes: item["size_bytes"] as? Int ?? 0,
                    mtime: item["mtime"] as? String,
                    identity: .parse(item["identity"] as? [String: Any]),
                    usage: .parse(item["usage"] as? [String: Any])
                ))
            }
        }
        if next.count == Self.slotNames.count { slots = next }
    }

    private func run(_ arguments: [String], timeout: TimeInterval) async -> ProtectCommandResult {
        await effects.run(.init(
            executable: "/usr/bin/python3",
            arguments: ["-I", "-S", "-B", script] + arguments,
            timeout: timeout
        ))
    }

    static func failure(_ result: ProtectCommandResult) -> String {
        if result.timedOut { return "命令超时。请确认 Claude Desktop 已退出后重试。" }
        if let reason = result.json?["reason"] as? String {
            let detail = result.json?["detail"] as? String ?? ""
            let explanations: [String: String] = [
                "desktop_still_running": "Claude Desktop 仍在运行，请先退出",
                "confirmation_required": "缺少确认参数",
                "interrupted_archive_present": "存在中断的归档现场，已拒绝覆盖",
                "interrupted_restore_present": "存在中断的还原现场，已拒绝覆盖",
                "slot_occupied": "目标槽位已有归档",
                "live_empty": "当前没有可归档的 Desktop 数据",
                "invalid_slot": "账号必须是 A、B、C 或 D",
                "missing_token": "本地没有可用登录会话，请先打开并登录 Claude Desktop",
                "cloudflare_blocked": "网站防护拦截，请先打开一次 Claude Desktop 后再刷新",
                "session_invalid": "该账号登录会话已失效，请切换过去重新登录后再刷新",
                "usage_unavailable": "用量接口不可用",
                "slot_missing": "该账号还没有本地数据"
            ]
            let head = explanations[reason] ?? reason
            let suffix = detail.isEmpty ? "" : "（\(detail)）"
            return String((head + suffix).prefix(240))
        }
        let text = (result.error.isEmpty ? result.output : result.error)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? "未取得可确认的结果（退出码 \(result.exitCode)）。" : String(text.prefix(240))
    }
}
