import SwiftUI
import CryptoKit

@MainActor final class ClaudeProtectModel: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var refreshing = false
    @Published private(set) var operationTitle = ""
    @Published private(set) var message = ""
    @Published private(set) var refreshMessage = ""
    @Published private(set) var guardSummary = "尚未读取。"
    @Published private(set) var pfSummary = "尚未读取。"
    @Published private(set) var previewNote = ""
    @Published private(set) var l4Healthy: Bool?
    @Published private(set) var l3Armed: Bool?
    @Published private(set) var mutationOutcomeUnknown = false

    private let effects: ClaudeProtectEffects
    private let toolsRoot: String
    private var statusEpoch = 0
    private var queuedRefresh = false
    private let wrapper = "/Library/PrivilegedHelperTools/local.crazymax.claude-protect/claude-protect"
    private var privilegedScript: String { toolsRoot + "/claude_protect_privileged.py" }
    private var pfScript: String { toolsRoot + "/claude_protect_pf.py" }
    private var guardScript: String { toolsRoot + "/claude_protect_guard.py" }

    init(effects: ClaudeProtectEffects = ClaudeProtectEffects(), toolsRoot: String? = nil) {
        self.effects = effects
        // Prefer the complete Resources folder, which also contains hook dependencies.
        self.toolsRoot = toolsRoot ?? Bundle.main.resourceURL?.path
            ?? FileManager.default.currentDirectoryPath + "/tools"
    }

    func refresh() {
        guard !refreshing else { queuedRefresh = true; return }
        refreshing = true
        refreshMessage = "正在读取系统状态…"
        let epoch = statusEpoch
        Task {
            async let guardResult = runScript(guardScript, ["status"], timeout: 25)
            async let rootResult = runWrapper(["status"], timeout: 15)
            let root = await rootResult
            let pf = root.succeeded && root.json?["product"] as? String == "claude_protect_l3"
                ? root : await runScript(pfScript, ["status"], timeout: 15)
            let guardReply = await guardResult
            if epoch == statusEpoch {
                let guardJSON = guardReply.json
                l4Healthy = guardJSON?["product"] as? String == "claude_protect_l4"
                    ? guardJSON?["healthy"] as? Bool : nil
                guardSummary = Self.formatGuard(guardJSON)
                let pfJSON = pf.succeeded ? pf.json : nil
                l3Armed = Self.armed(pfJSON)
                pfSummary = Self.formatPF(pfJSON)
                refreshMessage = l3Armed == nil || l4Healthy == nil
                    ? "部分状态未取得，请稍后刷新；上次操作的提示保留在下方。"
                    : "系统状态已刷新；规则开启不等于防护效果已验证。"
            }
            refreshing = false
            if queuedRefresh || epoch != statusEpoch {
                queuedRefresh = false
                refresh()
            }
        }
    }

    func previewL3() {
        guard !busy else { return }
        busy = true; message = ""; operationTitle = "正在检查规则…"
        Task {
            defer { busy = false; operationTitle = "" }
            if await prepareConf() != nil {
                previewNote = "规则检查通过；开启时会重新检查当前网卡。"
                message = "可以点击「开启禁止直连」。"
            }
        }
    }

    func enableL3() { changeBlock(enable: true) }
    func disableL3() { changeBlock(enable: false) }

    private func changeBlock(enable: Bool) {
        guard !busy, !mutationOutcomeUnknown else { return }
        busy = true; statusEpoch += 1; message = ""; l3Armed = nil
        Task {
            defer {
                statusEpoch += 1; busy = false; operationTitle = ""
                refresh() // Status has its own message and cannot erase an operation error.
            }
            var arguments: [String]
            if enable {
                operationTitle = "正在生成并检查规则…"
                guard let prepared = await prepareConf() else { return }
                arguments = ["enable", "--conf", prepared.path, "--conf-sha256", prepared.sha,
                             "--i-confirm-apply", "--i-confirm-window", "claude-protect-pf-user-confirm-v1",
                             "--i-acknowledge-network-mutation"]
            } else { arguments = ["unload", "--i-confirm-unload"] }

            operationTitle = "正在检查系统授权入口…"
            let installation = await verifyInstallation()
            guard installation.succeeded,
                  installation.json?["status"] as? String == "verified",
                  installation.json?["security_version"] as? Int == 2 else {
                message = "防护授权需要安全升级，请按快速开始安装新版授权入口；本次未执行更改。"
                return
            }
            operationTitle = "等待 macOS 管理员授权（最长 2 分钟）…"
            let result = await runAdmin(arguments)
            if result.timedOut || result.error.contains("(-1712)") {
                mutationOutcomeUnknown = true
                message = "系统操作超时，结果未确认。刷新仍可使用；为避免重复改动，本次会话暂停开关操作。系统命令可能已执行，请先核对状态。"
                return
            }
            let json = result.json
            let expected = enable ? "applied_anchor" : "unloaded_anchor"
            if result.succeeded, json?["product"] as? String == "claude_protect_l3",
               json?["status"] as? String == expected,
               json?["armed"] as? Bool == enable {
                message = enable
                    ? "系统已确认规则开启。请继续核对 Claude 的实际网络；这不代表防护效果已验证。"
                    : "本工具的拦截规则已关闭。"
            } else {
                message = (enable ? "开启未完成：" : "关闭未完成：") + Self.failure(result)
            }
        }
    }

    func runL4Check(dryRun: Bool) {
        guard !busy else { return }
        busy = true; message = ""; operationTitle = "正在检查代理入口…"
        Task {
            defer { busy = false; operationTitle = "" }
            let reply = await runScript(guardScript, dryRun ? ["check", "--dry-run"] : ["check"], timeout: 30)
            guard let json = reply.json, json["product"] as? String == "claude_protect_l4",
                  let healthy = json["healthy"] as? Bool else {
                l4Healthy = nil; message = "检查未完成：" + Self.failure(reply); return
            }
            l4Healthy = healthy; guardSummary = Self.formatGuard(json)
            if healthy { message = "代理入口正常，未关闭任何 Claude 进程。" }
            else if dryRun { message = "代理入口异常；本次只检查，未关闭进程。" }
            else { message = "代理入口异常，已尝试关闭 \((json["terminated"] as? [Any])?.count ?? 0) 个相关进程。" }
        }
    }

    private func prepareConf() async -> (path: String, sha: String)? {
        previewNote = ""
        let generated = await runScript(pfScript, ["generate"], timeout: 15)
        guard generated.succeeded, let json = generated.json,
              json["status"] as? String == "generated", let conf = json["conf"] as? String,
              !conf.isEmpty, let sha = json["conf_sha256"] as? String,
              sha == SHA256.hash(data: Data(conf.utf8)).map({ String(format: "%02x", $0) }).joined() else {
            message = "规则生成失败：" + Self.failure(generated); return nil
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("claude-protect-\(UUID())")
        let file = directory.appendingPathComponent("protect.pf")
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false,
                                                    attributes: [.posixPermissions: 0o700])
            try conf.write(to: file, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        } catch { message = "规则文件无法保存：" + error.localizedDescription; return nil }
        let dry = await runScript(pfScript, ["dry-run", "--conf", file.path], timeout: 15)
        guard dry.succeeded, dry.json?["status"] as? String == "dry_run_ok",
              dry.json?["conf_sha256"] as? String == sha else {
            message = "规则检查失败：" + Self.failure(dry); return nil
        }
        return (file.path, sha)
    }

    private func runScript(_ script: String, _ arguments: [String], timeout: TimeInterval) async -> ProtectCommandResult {
        await effects.run(.init(executable: "/usr/bin/python3", arguments: ["-I", "-S", "-B", script] + arguments, timeout: timeout))
    }
    private func verifyInstallation() async -> ProtectCommandResult {
        await runScript(privilegedScript, ["verify-installation"], timeout: 15)
    }
    private func runWrapper(_ arguments: [String], timeout: TimeInterval) async -> ProtectCommandResult {
        let installation = await verifyInstallation()
        guard installation.succeeded,
              installation.json?["status"] as? String == "verified",
              installation.json?["security_version"] as? Int == 2 else {
            return .init(exitCode: 78, error: "防护授权尚未安全升级。")
        }
        // Only read-only status is ever sent through passwordless sudo.
        guard arguments == ["status"] else { return .init(exitCode: 78, error: "操作不允许。") }
        return await effects.run(.init(executable: "/usr/bin/sudo", arguments: ["-n", wrapper] + arguments, timeout: timeout))
    }
    private func runAdmin(_ arguments: [String]) async -> ProtectCommandResult {
        let shell = ([wrapper] + arguments).map(Self.quote).joined(separator: " ")
        let escaped = shell.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let script = "with timeout of 110 seconds\n do shell script \"\(escaped)\" with administrator privileges\nend timeout"
        return await effects.run(.init(executable: "/usr/bin/osascript", arguments: ["-e", script], timeout: 120))
    }
    private static func quote(_ text: String) -> String {
        "'" + text.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    static func armed(_ json: [String: Any]?) -> Bool? {
        guard json?["product"] as? String == "claude_protect_l3",
              json?["status"] as? String == "status", json?["soft"] as? Bool != true,
              let armed = json?["armed"] as? Bool else { return nil }
        return armed
    }
    private static func failure(_ result: ProtectCommandResult) -> String {
        if result.timedOut { return "命令超时，请刷新状态后再判断。" }
        if let reason = result.json?["reason"] as? String {
            let detail = result.json?["detail"] as? String ?? ""
            let explanations = [
                "enable_hook_failed": "系统防火墙初始化未完成",
                "hook_operation_incomplete_restore_or_inspect": "上次防火墙操作尚未完成，需先检查恢复记录",
                "interfaces_changed_regenerate_required": "网卡发生变化，请重新检查规则后开启",
                "conf_sha256_mismatch": "规则文件已变化，请重新检查规则",
                "pfctl_rejected": "系统防火墙拒绝执行，请刷新状态",
                "pfctl_dry_run_rejected": "系统未通过规则语法检查"
            ]
            return String(((explanations[reason] ?? reason) + (detail.isEmpty ? "" : "（\(detail)）")).prefix(240))
        }
        if result.error.contains("(-128)") { return "已取消系统授权，未确认执行结果。" }
        let text = (result.error.isEmpty ? result.output : result.error).trimmingCharacters(in: .whitespacesAndNewlines)
        return text.isEmpty ? "未取得可确认的结果（退出码 \(result.exitCode)）。" : String(text.prefix(240))
    }
    private static func formatGuard(_ value: [String: Any]?) -> String {
        guard value?["product"] as? String == "claude_protect_l4", let healthy = value?["healthy"] as? Bool else {
            return "代理入口状态未取得，请重试刷新。"
        }
        return "本地代理入口（端口 \(value?["proxy_port"] as? Int ?? 1082)）" + (healthy ? "正常。" : "异常；请先检查代理客户端。")
    }
    private static func formatPF(_ value: [String: Any]?) -> String {
        guard let armed = armed(value) else { return "尚未取得完整系统状态，暂不能判断是否开启。" }
        return armed ? "系统规则已开启；实际防护效果仍需验证。" : "「禁止直连」未开启。"
    }
}
