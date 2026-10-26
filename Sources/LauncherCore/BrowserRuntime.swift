import Foundation
import Darwin

public struct BrowserProfile: Codable, Identifiable {
    public var id = UUID()
    public var name: String
    public var seed = UInt32.random(in: 1...UInt32.max)
    public var language = "en-US"
    public var timezone = "America/New_York"
    public init(name: String) { self.name = name }
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, name.count <= 80,
              !name.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains), seed > 0,
              BrowserRuntime.languages.contains(language), TimeZone.knownTimeZoneIdentifiers.contains(timezone) else {
            throw LauncherError.message("浏览器档案名称、语言、时区或种子无效。")
        }
    }
}

public enum BrowserRuntime {
    public static let root = Paths.root.appendingPathComponent("browser")
    public static let engineVersion = "148.0.7778.215"
    public static let languages: Set<String> = ["en-US", "en-CA", "en-GB", "en-SG", "en-AU", "en", "zh-Hans", "zh-Hant", "fr", "de", "es", "it", "ja", "ko"]
    public static func arguments(profile: BrowserProfile, directory: URL, port: UInt16) throws -> [String] {
        try profile.validate()
        guard port >= 1024, directory.isFileURL else { throw LauncherError.message("浏览器端口或资料目录无效。") }
        let os = ProcessInfo.processInfo.operatingSystemVersion
        return ["--user-data-dir=\(directory.path)", "--profile-directory=Default",
                "--fingerprint=\(profile.seed)", "--fingerprint-platform=macos",
                "--fingerprint-platform-version=\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)",
                "--fingerprint-brand=Chrome", "--fingerprint-brand-version=\(engineVersion)",
                "--fingerprint-hardware-concurrency=\(ProcessInfo.processInfo.processorCount)",
                "--lang=\(profile.language)", "--accept-lang=\(profile.language),\(profile.language.split(separator: "-")[0])",
                "--timezone=\(profile.timezone)", "--proxy-server=http://127.0.0.1:\(port)", "--proxy-bypass-list=<-loopback>",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp", "--disable-non-proxied-udp", "--disable-quic",
                "--disable-spoofing=font,audio,gpu,canvas,clientrects", "--no-first-run", "--no-default-browser-check", "about:blank"]
    }
    /// Profile metadata is independent from desktop cookies and original CCBaga data.
    public static func save(_ profile: BrowserProfile) throws {
        try profile.validate(); try ConnectorIPC.privateDirectory(create: true)
        let directory = Paths.root.appendingPathComponent("browser-profiles")
        var info = stat()
        if lstat(directory.path, &info) != 0 {
            guard errno == ENOENT else { throw LauncherError.message("档案目录不可读。") }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        }
        guard directory.resolvingSymlinksInPath() == directory.standardizedFileURL,
              lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw LauncherError.message("档案目录权限或路径无效。") }
        let file = directory.appendingPathComponent(profile.id.uuidString + ".json")
        if lstat(file.path, &info) == 0 {
            guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_nlink == 1,
                  info.st_mode & 0o077 == 0, info.st_size <= 16384 else { throw LauncherError.message("已有档案无效，已保留。") }
            let existing = try loadJSON(BrowserProfile.self, from: file)
            try existing.validate()
            guard existing.id == profile.id, existing.seed == profile.seed else { throw LauncherError.message("已有档案身份或种子不匹配，已保留。") }
        } else if errno != ENOENT { throw LauncherError.message("已有档案不可读。") }
        try saveJSON(profile, to: file)
    }
    public static func profiles() throws -> [BrowserProfile] {
        let directory = Paths.root.appendingPathComponent("browser-profiles")
        guard FileManager.default.fileExists(atPath: directory.path) else { return [] }
        var info = stat()
        guard directory.resolvingSymlinksInPath() == directory.standardizedFileURL,
              lstat(directory.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == getuid(), info.st_mode & 0o077 == 0 else { throw LauncherError.message("档案目录权限或路径无效。") }
        let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
        guard files.count <= 256 else { throw LauncherError.message("档案数量超过上限。") }
        return try files.filter { $0.pathExtension == "json" }.map { file in
            guard lstat(file.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
                  info.st_uid == getuid(), info.st_nlink == 1, info.st_mode & 0o077 == 0,
                  info.st_size <= 16384 else { throw LauncherError.message("档案文件权限或类型无效。") }
            let profile = try loadJSON(BrowserProfile.self, from: file)
            guard file.deletingPathExtension().lastPathComponent == profile.id.uuidString else { throw LauncherError.message("档案身份不匹配。") }
            try profile.validate(); return profile
        }.sorted { $0.name < $1.name }
    }
    /// Browser launch is deliberately subject to the same unfulfilled strict
    /// gate; engine installation alone is not a network isolation acceptance.
    public static func requireLaunch() throws { try StrictProtection.requireVerified() }
}

public struct BrowserInstallStatus: Sendable {
    public let installed: Bool
    public let message: String
}
public enum BrowserInstaller {
    public static func perform(_ action: String, script: URL) -> BrowserInstallStatus {
        guard ["inspect", "install"].contains(action), script.lastPathComponent == "browser_install.py" else {
            return .init(installed: false, message: "浏览器组件不可用。")
        }
        let result = ReadCommand.run("/usr/bin/python3", ["-E", "-s", "-B", script.path, action], timeout: action == "install" ? 2400 : 300, terminationGrace: 45)
        guard let data = result.text.data(using: .utf8), let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              value["browser_started"] as? Bool == false, let reason = value["reason"] as? String else {
            return .init(installed: false, message: "安装或检查未完成；已保留本地资料，未启动浏览器。")
        }
        if result.code == 0, ["browser_installed_not_started", "browser_verified_not_started"].contains(reason) {
            return .init(installed: true, message: "官方 B 内核已验证安装，尚未启动。")
        }
        let messages = ["browser_not_installed": "尚未安装浏览器内核。",
                        "verification_failed_spctl": "Gatekeeper 未通过，安装已停止。",
                        "verification_failed_codesign": "代码签名验证失败，安装已停止。",
                        "download_digest_mismatch": "下载摘要不匹配，安装已停止。",
                        "browser_installed_detach_pending": "引擎已安装，但安装卷尚未卸载。"]
        return .init(installed: false, message: messages[reason] ?? "浏览器安装或验证失败；资料已保留，未启动浏览器。")
    }
}
