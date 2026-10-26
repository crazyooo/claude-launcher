import Foundation
import Darwin

public enum PreflightLaunch {
    /// No output on stdout: the VS Code extension uses it for its protocol.
    public static func wrap(binary: String, arguments: [String]) throws -> Never {
        try StrictProtection.requireVerified()
        guard ClientInspection.validateWrappedBinary(binary) else {
            throw LauncherError.message("包装目标不是本机官方 VS Code 插件的 Claude 可执行文件。")
        }
        let original = ProcessInfo.processInfo.environment
        let directory = FileManager.default.currentDirectoryPath
        let settings = try PreflightSettings.read()
        let report = NetworkInspector.inspect(target: .vscode, settings: settings, directory: directory, environment: original)
        let current = NetworkInspector.context(settings: try PreflightSettings.read(), target: .vscode, directory: directory, environment: original)
        guard report.permits(context: current) else { throw LauncherError.message(report.summary) }
        let inspection = ClientInspection.inspect(target: .vscode, directory: directory, environment: original)
        let paths = CheckTarget.vscode.hosts.map { inspection.transport ?? ProbeTransport.system(host: $0) }
        guard inspection.checks.allSatisfy({ !$0.required || $0.result == .passed }),
              zip(CheckTarget.vscode.hosts, paths).allSatisfy({ host, path in
                  report.observations.contains { $0.host == host && $0.transport == path.label }
              }), paths.allSatisfy({ $0 == paths.first }) else {
            throw LauncherError.message("各 Claude 域名选择了不同代理入口，无法用统一 Code 环境表达。")
        }
        let environment = try ClientInspection.codeEnvironment(original, transport: paths[0])
        guard report.permits(context: NetworkInspector.context(settings: try PreflightSettings.read(), target: .vscode,
                                                               directory: directory, environment: original)) else {
            throw LauncherError.message("执行前网络或配置变化，未启动 Code。")
        }
        // Clear only proxy keys. Preserve other environment, cwd, stdin and arguments.
        for key in ClientInspection.proxyKeys { unsetenv(key) }
        for (key, value) in environment { setenv(key, value, 1) }
        let argv = [binary] + arguments
        let pointers = argv.map { strdup($0) } + [nil]
        execv(binary, pointers)
        throw LauncherError.message("Claude Code 进程执行失败。")
    }
}
