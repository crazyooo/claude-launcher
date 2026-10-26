import Foundation
import Darwin
import AppKit

/// Local conditions only. Network probes and process isolation require separate evidence.
public struct RecoveryLocalTargetReport {
    public let target: CheckTarget
    public let startedAt, completedAt: Date
    let startedTick, completedTick: Double
    public let context: String
    public let checks: [NetworkCheck]

    public func satisfiesLocalRequirements(target expected: CheckTarget, context current: String, now: Date = Date()) -> Bool {
        satisfiesLocalRequirements(target: expected, context: current, now: now, tick: connectorTime())
    }
    func satisfiesLocalRequirements(target expected: CheckTarget, context current: String, now: Date, tick: Double) -> Bool {
        let required = Set(["baseline", "client", "local-readable", "unchanged"] +
                           (target == .vscode ? ["plugin-gate", "code-network"] : []))
        let ids = checks.map(\.id), age = now.timeIntervalSince(startedAt)
        return startedTick.isFinite && completedTick.isFinite && tick.isFinite && startedTick >= 0 &&
            completedTick >= startedTick && tick >= completedTick && tick <= startedTick + 30 &&
            target == expected && PFControlContext.hex(context, length: 64) && context == current &&
            age >= 0 && age <= 30 && completedAt >= startedAt && completedAt <= now &&
            Set(ids).count == ids.count && required.allSatisfy { id in
                checks.contains { $0.id == id && $0.required && $0.result == .passed }
            } && checks.allSatisfy { !$0.required || $0.result == .passed }
    }
}

/// Reads at most 2,000,000 bytes before parsing. Only ENOENT is absence, never a read failure.
enum RecoveryLocalFile {
    static let limit = 2_000_000
    static let failure = LauncherError.message("本地客户端文件无法完整核对；已保留原文件。")
    struct Value {
        let data: Data
        let executable: Bool
        let fingerprint: String
    }
    private static func canExecute(_ url: URL) throws -> Bool {
        if access(url.path, X_OK) == 0 { return true }
        guard errno == EACCES else { throw failure }
        return false
    }
    static func read(_ url: URL) throws -> Value? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd < 0 { if errno == ENOENT { return nil }; throw failure }
        defer { close(fd) }
        var before = stat(), after = stat(), linked = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG,
              (0...limit).contains(Int(before.st_size)) else { throw failure }
        let executable = try canExecute(url)
        var data = Data(), bytes = [UInt8](repeating: 0, count: 65_536)
        while true {
            let count = Darwin.read(fd, &bytes, min(bytes.count, limit + 1 - data.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, data.count + count <= limit else { throw failure }
            if count == 0 { break }; data.append(contentsOf: bytes.prefix(count))
        }
        guard try canExecute(url) == executable,
              fstat(fd, &after) == 0, lstat(url.path, &linked) == 0,
              before.st_size == data.count, before.st_size == after.st_size,
              before.st_dev == linked.st_dev, before.st_ino == linked.st_ino,
              before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
              before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
              before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec,
              before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec,
              after.st_mode == linked.st_mode, before.st_mode == after.st_mode else { throw failure }
        let meta = "\(before.st_dev):\(before.st_ino):\(before.st_mode):\(before.st_size):\(before.st_mtimespec.tv_sec):\(before.st_mtimespec.tv_nsec):\(before.st_ctimespec.tv_sec):\(before.st_ctimespec.tv_nsec)"
        return .init(data: data, executable: executable,
                     fingerprint: fingerprintData(Data((meta + ":x=\(executable):" + fingerprintData(data)).utf8)))
    }
    static func object(_ value: Value?) throws -> [String: Any] {
        guard let value else { return [:] }
        guard let text = String(data: value.data, encoding: .utf8),
              let object = try JSONSerialization.jsonObject(with: Data(JSONComments.strip(text).utf8)) as? [String: Any] else {
            throw failure
        }
        return object
    }
}

struct RecoveryLocalSnapshot {
    let context: String
    let source: ClientInspectionSource
}

public enum RecoveryLocalTargetInspector {
    public static func context(settings: PreflightSettings, connector: ConnectorConfiguration, target: CheckTarget,
                               directory: String? = nil, environment: [String: String] = [:]) throws -> String {
        try snapshot(settings: settings, connector: connector, target: target, directory: directory, environment: environment).context
    }
    public static func inspect(settings: PreflightSettings, connector: ConnectorConfiguration, target: CheckTarget,
                               directory: String? = nil, environment: [String: String] = [:]) -> RecoveryLocalTargetReport {
        inspect(settings: settings, connector: connector, target: target, directory: directory, environment: environment,
                capture: { try snapshot(settings: settings, connector: connector, target: target, directory: directory, environment: environment) })
    }
    static func inspect(settings: PreflightSettings, connector: ConnectorConfiguration, target: CheckTarget,
                        directory: String? = nil, environment: [String: String] = [:],
                        capture: () throws -> RecoveryLocalSnapshot, clock: () -> Date = Date.init,
                        monotonic: () -> Double = connectorTime) -> RecoveryLocalTargetReport {
        let startedTick = monotonic(), started = clock(); var checks: [NetworkCheck] = [], digest = ""
        do {
            try settings.validate(); try connector.validate()
            guard settings.matches(connector.expectedIPv4) else { throw RecoveryLocalFile.failure }
            checks.append(.init("baseline", "本地出口基准", .passed, "预检与连接器使用相同的已确认 IPv4 基准。"))
        } catch { checks.append(.init("baseline", "本地出口基准", .failed, "预检与连接器基准缺失、无效或不一致。")) }
        do {
            let before = try capture(); digest = before.context
            let local = ClientInspection.inspect(target: target, directory: directory, environment: environment, source: before.source)
            // Do not copy old system-route descriptions into a Connector recovery report.
            checks += local.checks.filter { ["client", "plugin-gate", "code-network"].contains($0.id) }.map { check in
                if check.id == "code-network", check.result == .passed {
                    return .init(check.id, check.title, .passed,
                                 "本地 Code 配置未发现已知冲突；这不证明现有进程使用连接器。")
                }
                return check
            }
            if local.transport != nil {
                checks.append(.init("declared-route", "客户端声明的代理", .info, required: false,
                                    "Code 声明了独立代理入口；语法检查不证明它指向连接器或已受保护。"))
            }
            checks.append(.init("local-readable", "本地文件可核对", .passed, "检查使用完整、有界的本地配置快照。"))
            let unchanged = try capture().context == before.context
            checks.append(.init("unchanged", "本地配置稳定", unchanged ? .passed : .failed,
                                unchanged ? "检查前后客户端、配置与包装器指纹相同。" : "检查期间本地配置变化。"))
        } catch {
            if checks.contains(where: { $0.id == "local-readable" }) {
                checks.append(.init("unchanged", "本地配置稳定", .unknown, "后置快照无法核对，未沿用前置结果。"))
            } else {
                checks.append(.init("local-readable", "本地文件可核对", .unknown, "本地文件缺失、不可读或格式无效，未沿用旧结果。"))
            }
        }
        checks.append(.init("scope", "证据范围", .info, required: false,
                            "仅检查本地条件；出口与服务响应须经连接器另行核对。桌面 Code 指桌面内 Code，不包含独立 CLI。"))
        return .init(target: target, startedAt: started, completedAt: clock(),
                     startedTick: startedTick, completedTick: monotonic(), context: digest, checks: checks)
    }

    static func canonicalDirectory(_ directory: String?) throws -> String? {
        guard let directory else { return nil }
        guard directory.hasPrefix("/"), !directory.utf8.contains(0), directory.utf8.count <= 4096 else { throw RecoveryLocalFile.failure }
        let url = URL(fileURLWithPath: directory).standardizedFileURL.resolvingSymlinksInPath()
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RecoveryLocalFile.failure }; close(fd)
        guard url.pathComponents.count <= 128 else { throw RecoveryLocalFile.failure }
        return url.path
    }

    static func snapshot(settings: PreflightSettings, connector: ConnectorConfiguration, target: CheckTarget,
                         directory: String?, environment: [String: String],
                         read: (URL) throws -> RecoveryLocalFile.Value? = RecoveryLocalFile.read,
                         locateApps: (CheckTarget) -> [URL] = ClientInspection.appCandidates) throws -> RecoveryLocalSnapshot {
        let directory = try canonicalDirectory(directory)
        let configurationFiles = ClientInspection.files(directory: directory)
        let infoFiles = Set(locateApps(target).map { $0.standardizedFileURL.appendingPathComponent("Contents/Info.plist") })
        var fileURLs = configurationFiles + Array(infoFiles)
        let extensionIndex = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".vscode/extensions/extensions.json")
        let wrapper = URL(fileURLWithPath: ClientInspection.vscodeWrapper), manifest = Paths.root.appendingPathComponent("installation.json")
        if target == .vscode { fileURLs += [extensionIndex, wrapper, manifest] }
        var values: [URL: RecoveryLocalFile.Value] = [:], components: [String] = []
        for url in Set(fileURLs).sorted(by: { $0.path < $1.path }) {
            let value = try read(url)
            if let value { values[url] = value }
            components.append(url.path + ":" + (value?.fingerprint ?? "absent"))
        }
        var objects: [URL: [String: Any]] = [:]
        for url in configurationFiles { objects[url] = try RecoveryLocalFile.object(values[url]) }
        var installed = false
        for url in infoFiles {
            guard let info = values[url] else { continue }
            guard let plist = try PropertyListSerialization.propertyList(from: info.data, format: nil) as? [String: Any] else {
                throw RecoveryLocalFile.failure
            }
            if plist["CFBundleIdentifier"] as? String == (target == .vscode ? "com.microsoft.VSCode" : "com.anthropic.claudefordesktop") {
                installed = true
            }
        }
        var ownedWrapper = false
        if target == .vscode {
            var extensionInstalled = false
            if let index = values[extensionIndex] {
                guard let entries = try JSONSerialization.jsonObject(with: index.data) as? [[String: Any]] else { throw RecoveryLocalFile.failure }
                extensionInstalled = entries.contains { ($0["identifier"] as? [String: Any])?["id"] as? String == "anthropic.claude-code" }
            }
            installed = installed && extensionInstalled
            let ownership = try RecoveryLocalFile.object(values[manifest])
            if let file = values[wrapper], file.executable,
               let expected = (ownership["scripts"] as? [String: String])?["claude-vscode-preflight"] {
                ownedWrapper = fingerprintData(file.data) == expected
            }
        }
        components += ["local-target-v1", target.rawValue, settings.fingerprint, connector.digest,
                       directory ?? "no-directory", ClientInspection.environmentFingerprint(environment)]
        let source = ClientInspectionSource(installed: installed, running: false, readObject: { url in
            guard let object = objects[url] else { throw RecoveryLocalFile.failure }; return object
        }, wrapperInstalled: { ownedWrapper }, fallbackTransport: .init(), configurationFiles: configurationFiles)
        return .init(context: fingerprintData(Data(components.joined(separator: "\n").utf8)), source: source)
    }
}
