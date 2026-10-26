import Foundation
import AppKit

public struct ClientNetworkInspection {
    public let checks: [NetworkCheck]
    public let transport: ProbeTransport?
}
/// Allows recovery checks to use one strict, bounded local snapshot throughout.
struct ClientInspectionSource {
    let installed, running: Bool
    let readObject: (URL) throws -> [String: Any]
    let wrapperInstalled: () -> Bool
    var fallbackTransport: ProbeTransport? = nil
    var configurationFiles: [URL]? = nil
}
public enum ClientInspection {
    public static let vscodeSettings = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Code/User/settings.json")
    public static let vscodeWrapper = NSHomeDirectory() + "/.local/bin/claude-vscode-preflight"
    public static let proxyKeys = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]
    public static let routingKeys = proxyKeys + ["NO_PROXY", "no_proxy", "ANTHROPIC_BASE_URL", "CLAUDE_CONFIG_DIR", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "NODE_OPTIONS"]
    static func appCandidates(_ target: CheckTarget) -> [URL] {
        let name = target == .vscode ? "Visual Studio Code.app" : "Claude.app"
        let expected = target == .vscode ? "com.microsoft.VSCode" : "com.anthropic.claudefordesktop"
        var candidates = [URL(fileURLWithPath: "/Applications/" + name), FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Applications/" + name)]
        if let registered = NSWorkspace.shared.urlForApplication(withBundleIdentifier: expected) { candidates.append(registered) }
        var seen = Set<URL>()
        return candidates.map(\.standardizedFileURL).filter { seen.insert($0).inserted }
    }
    public static func app(_ target: CheckTarget) -> URL? {
        let expected = target == .vscode ? "com.microsoft.VSCode" : "com.anthropic.claudefordesktop"
        return appCandidates(target).first { Bundle(url: $0)?.bundleIdentifier == expected }
    }
    static func files(directory: String?) -> [URL] {
        var result = [vscodeSettings, FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".claude/settings.json"),
                      URL(fileURLWithPath: "/Library/Application Support/ClaudeCode/managed-settings.json")]
        if let directory {
            var current = URL(fileURLWithPath: directory).standardizedFileURL.resolvingSymlinksInPath()
            while current.path != "/" {
                result += [current.appendingPathComponent(".claude/settings.json"), current.appendingPathComponent(".claude/settings.local.json"), current.appendingPathComponent(".vscode/settings.json")]
                current.deleteLastPathComponent()
            }
        }
        return Array(Set(result)).sorted { $0.path < $1.path }
    }
    public static func environmentFingerprint(_ environment: [String: String]) -> String {
        fingerprintData(Data(routingKeys.sorted().map { "\($0)=\(environment[$0] ?? "")" }.joined(separator: "\n").utf8))
    }
    public static func fingerprint(target: CheckTarget, directory: String?) -> String {
        var components = files(directory: directory).map { url in
            url.path + ":" + ((try? Data(contentsOf: url)).map(fingerprintData) ?? "absent")
        }
        if let app = app(target), let data = try? Data(contentsOf: app.appendingPathComponent("Contents/Info.plist")) { components.append(fingerprintData(data)) }
        let index = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".vscode/extensions/extensions.json")
        components.append((try? Data(contentsOf: index)).map(fingerprintData) ?? "absent")
        components.append((try? Data(contentsOf: URL(fileURLWithPath: vscodeWrapper))).map(fingerprintData) ?? "absent")
        components.append((try? Data(contentsOf: Paths.root.appendingPathComponent("installation.json"))).map(fingerprintData) ?? "absent")
        return fingerprintData(Data(components.joined(separator: "\n").utf8))
    }
    public static func officialExtensionInstalled() -> Bool {
        let root = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".vscode/extensions")
        guard let data = try? Data(contentsOf: root.appendingPathComponent("extensions.json")),
              let extensions = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return false }
        return extensions.contains {
            ($0["identifier"] as? [String: Any])?["id"] as? String == "anthropic.claude-code"
        }
    }
    public static func inspect(target: CheckTarget, directory: String?, environment: [String: String]?) -> ClientNetworkInspection {
        let installed = app(target) != nil && (target != .vscode || officialExtensionInstalled())
        let running = NSWorkspace.shared.runningApplications.contains { $0.bundleIdentifier == (target == .vscode ? "com.microsoft.VSCode" : "com.anthropic.claudefordesktop") }
        return inspect(target: target, directory: directory, environment: environment,
                       source: .init(installed: installed, running: running, readObject: readObject, wrapperInstalled: wrapperInstalled))
    }
    static func inspect(target: CheckTarget, directory: String?, environment: [String: String]?,
                        source: ClientInspectionSource) -> ClientNetworkInspection {
        let readObject = source.readObject, wrapperInstalled = source.wrapperInstalled
        let installed = source.installed
        var checks: [NetworkCheck] = []
        checks.append(.init("client", "官方客户端", installed ? .passed : .failed,
                            installed ? "已找到官方应用\(target == .vscode ? "和 Claude Code 插件" : "")。" : "未找到官方应用或 Claude Code 插件。"))
        let running = source.running
        checks.append(.init("existing", "已运行实例", .info, required: false,
                            running ? "已有应用实例；通过后激活现有窗口。既有会话不受新启动检查追溯约束。" : "未发现该应用正在运行。"))
        if target != .vscode {
            checks.append(.init("desktop-boundary", "桌面检查范围", .info, required: false,
                                target == .desktopCode ? "检查本机 Claude/API 域名；打开后自行切换 Code。远端 Code／虚拟机网络不由本机探测证明。" : "按 macOS 为目标域名选择的代理探测；进程规则及应用自定义网络仍需运行后验证。"))
            return .init(checks: checks, transport: nil)
        }
        do {
            var merged = environment ?? [:]
            let settings = try readObject(vscodeSettings)
            let wrapper = settings["claudeCode.claudeProcessWrapper"] as? String
            let owned = wrapper == vscodeWrapper && wrapperInstalled()
            checks.append(.init("plugin-gate", "插件启动门禁", owned ? .passed : .failed,
                                owned ? "默认用户配置已接入；包装器会检查每次经它启动的进程。自定义配置档案／远程工作区需另行适配。" : "插件启动门禁未安装或脚本已修改。"))
            for item in settings["claudeCode.environmentVariables"] as? [[String: String]] ?? [] {
                if let key = item["name"], let value = item["value"], routingKeys.contains(key) { merged[key] = value }
            }
            // Conflicting scoped settings are not silently replaced by process env.
            for file in source.configurationFiles ?? files(directory: directory) where file != vscodeSettings {
                let object = try readObject(file)
                if let env = object["env"] as? [String: Any] {
                    for key in routingKeys where env[key] != nil {
                        guard let value = env[key] as? String else { throw LauncherError.message("网络环境配置包含非文本值。") }
                        if let previous = merged[key], previous != value { throw LauncherError.message("插件／项目／进程的网络配置冲突，需统一后再启动。") }
                        merged[key] = value
                    }
                }
                if object["claudeCode.environmentVariables"] != nil || object["claudeCode.claudeProcessWrapper"] != nil || object["http.proxy"] != nil {
                    throw LauncherError.message("检测到项目级网络覆盖，需核对其有效配置后再启动。")
                }
            }
            if routingKeys.filter({ !proxyKeys.contains($0) && !["NO_PROXY", "no_proxy"].contains($0) }).contains(where: { !(merged[$0] ?? "").isEmpty }) {
                throw LauncherError.message("检测到自定义 API、云服务、配置目录或 TLS 设置，当前官方端点检查不能代表该路径。")
            }
            if ["NO_PROXY", "no_proxy"].contains(where: { !(merged[$0] ?? "").isEmpty }) {
                throw LauncherError.message("Code 配置了代理绕过列表；需核对后再接入，未自动清除。")
            }
            let values = Set(proxyKeys.compactMap { merged[$0] }.filter { !$0.isEmpty })
            guard values.count <= 1 else { throw LauncherError.message("Code 的多个代理环境变量不一致。") }
            let transport: ProbeTransport?
            if let value = values.first { transport = .explicit(value) }
            else if let proxy = settings["http.proxy"] as? String, !proxy.isEmpty { transport = .explicit(proxy) }
            else { transport = nil }
            let effective = transport ?? source.fallbackTransport ?? ProbeTransport.system(host: "api.anthropic.com")
            if let proxy = effective.proxy, proxy.hasPrefix("socks") { throw LauncherError.message("Claude Code 需要 HTTP 代理，当前 SOCKS 入口未适配。") }
            checks.append(.init("code-network", "Code 网络配置", effective.error == nil ? .passed : .unknown,
                                transport?.error ?? (transport == nil ? "新插件进程按当前系统代理注入 HTTP(S)_PROXY；不修改全局环境。" : "已读取 Code 独立代理；按此入口探测。")))
            return .init(checks: checks, transport: transport)
        } catch {
            checks.append(.init("code-network", "Code 网络配置", .unknown, "\(error.localizedDescription)"))
            return .init(checks: checks, transport: .init(error: "Code 网络配置未确认。"))
        }
    }
    public static func wrapperInstalled() -> Bool {
        guard FileManager.default.isExecutableFile(atPath: vscodeWrapper),
              let manifest = try? readObject(Paths.root.appendingPathComponent("installation.json")),
              let scripts = manifest["scripts"] as? [String: String],
              let expected = scripts["claude-vscode-preflight"],
              let actual = try? sha256(URL(fileURLWithPath: vscodeWrapper)) else { return false }
        return actual == expected
    }
    public static func readObject(_ url: URL) throws -> [String: Any] {
        guard FileManager.default.fileExists(atPath: url.path) else { return [:] }
        do {
            let data = try Data(contentsOf: url)
            guard data.count < 2_000_000, let source = String(data: data, encoding: .utf8),
                  let object = try JSONSerialization.jsonObject(with: Data(JSONComments.strip(source).utf8)) as? [String: Any] else { throw LauncherError.message("invalid") }
            return object
        } catch { throw LauncherError.message("存在无法读取的客户端配置，已保留原文件。") }
    }
    public static func validateWrappedBinary(_ path: String) -> Bool {
        let file = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath()
        let base = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".vscode/extensions").resolvingSymlinksInPath()
        guard file.path.hasPrefix(base.path + "/"), file.lastPathComponent == "claude",
              FileManager.default.isExecutableFile(atPath: file.path) else { return false }
        let relative = String(file.path.dropFirst(base.path.count + 1)).split(separator: "/")
        guard relative.count >= 4, relative[0].hasPrefix("anthropic.claude-code-"), relative[1] == "resources",
              ["native-binary", "native-binaries"].contains(String(relative[2])) else { return false }
        let package = base.appendingPathComponent(String(relative[0])).appendingPathComponent("package.json")
        guard let object = try? readObject(package) else { return false }
        return object["publisher"] as? String == "anthropic" && object["name"] as? String == "claude-code"
    }
    public static func codeEnvironment(_ original: [String: String], transport: ProbeTransport) throws -> [String: String] {
        guard transport.error == nil else { throw LauncherError.message("代理路径未确定。") }
        if let proxy = transport.proxy, !proxy.hasPrefix("http://") && !proxy.hasPrefix("https://") {
            throw LauncherError.message("Claude Code 需要 HTTP 代理；当前 SOCKS 入口未适配。")
        }
        var result = original
        for key in proxyKeys { result.removeValue(forKey: key) }
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            if let proxy = transport.proxy { result[key] = proxy }
        }
        return result
    }
}

enum JSONComments {
    static func strip(_ source: String) -> String {
        let chars = Array(source); var output = ""; var index = 0; var quoted = false; var escaped = false
        while index < chars.count {
            let c = chars[index]; let next: Character? = index + 1 < chars.count ? chars[index + 1] : nil
            if quoted {
                output.append(c)
                if escaped { escaped = false } else if c == "\\" { escaped = true } else if c == "\"" { quoted = false }
                index += 1; continue
            }
            if c == "\"" { quoted = true; output.append(c); index += 1; continue }
            if c == "/" && next == "/" { while index < chars.count && chars[index] != "\n" { index += 1 }; continue }
            if c == "/" && next == "*" {
                index += 2
                while index + 1 < chars.count && !(chars[index] == "*" && chars[index + 1] == "/") { index += 1 }
                index += 2; output.append(" "); continue
            }
            if c == "," {
                // Handle trailing commas in a second pass after comments are stripped.
                output.append(c)
            } else { output.append(c) }
            index += 1
        }
        let clean = Array(output); output = ""; quoted = false; escaped = false
        for i in clean.indices {
            let c = clean[i]
            if quoted { output.append(c); if escaped { escaped = false } else if c == "\\" { escaped = true } else if c == "\"" { quoted = false }; continue }
            if c == "\"" { quoted = true }
            if c == ",", let next = clean.dropFirst(i + 1).first(where: { !$0.isWhitespace }), next == "}" || next == "]" { continue }
            output.append(c)
        }
        return output
    }
}
