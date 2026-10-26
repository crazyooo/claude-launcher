import Foundation

public struct RouterCoreCheckReport: Encodable {
    public let coreVersion: String
    public let binaryVerified: Bool
    public let configurationAccepted: Bool
    public let validationNetworkDenied: Bool
    public let routingVerified: Bool
    public let networkSettingsModified: Bool
    public let summary: RouterRuntimeSummary
}

public struct RouterSystemCoreCheckReport: Encodable {
    public let coreVersion = RouterCoreRelease.version
    public let binaryVerified = true
    public let configurationAccepted = true
    public let validationNetworkDenied = true
    public let routingVerified = false
    public let networkSettingsModified = false
    public let summary: RouterSystemConfigurationSummary
}

public enum RouterCoreCheck {
    public static func temporaryWorkspace() throws -> URL {
        guard let path = RouterRuntimeFiles.physicalPath(FileManager.default.temporaryDirectory) else { throw RouterRuntimeError.unsafeFile }
        return URL(fileURLWithPath: path).appendingPathComponent("claude-router-core-checks")
    }
    public static func run(core: URL, configuration: RouterRuntimeConfiguration, workspace: URL) throws -> RouterCoreCheckReport {
        try run(core: core, configuration: configuration, workspace: workspace,
                loadCore: RouterCoreRelease.verifiedBytes, execute: RouterRuntimeProcess.run)
    }

    public static func runSystem(core: URL, configuration: RouterSystemConfiguration, workspace: URL) throws -> RouterSystemCoreCheckReport {
        try checkBytes(core: core, data: configuration.privateJSON, workspace: workspace,
                       loadCore: RouterCoreRelease.verifiedBytes, execute: RouterRuntimeProcess.run)
        return .init(summary: configuration.summary)
    }

    static func run(core: URL, configuration: RouterRuntimeConfiguration, workspace: URL,
                    loadCore: (URL) throws -> Data,
                    execute: (String, [String], TimeInterval) throws -> RouterProcessResult) throws -> RouterCoreCheckReport {
        try checkBytes(core: core, data: configuration.privateJSON, workspace: workspace, loadCore: loadCore, execute: execute)
        return .init(coreVersion: RouterCoreRelease.version, binaryVerified: true, configurationAccepted: true,
                     validationNetworkDenied: true, routingVerified: false, networkSettingsModified: false, summary: configuration.summary)
    }

    static func checkBytes(core: URL, data: Data, workspace: URL,
                           loadCore: (URL) throws -> Data,
                           execute: (String, [String], TimeInterval) throws -> RouterProcessResult) throws {
        let coreBytes = try loadCore(core)
        let files = RouterRuntimeFiles(root: workspace)
        let directory = try files.createGeneration(), config = directory.appendingPathComponent("config.json")
        let executable = directory.appendingPathComponent("mihomo")
        try files.writeNew(coreBytes, to: executable, executable: true)
        try files.writeNew(data, to: config)
        guard try files.readPrivate(executable, maximum: 128 * 1024 * 1024) == coreBytes,
              try files.readPrivate(config) == data else { throw RouterRuntimeError.unsafeFile }
        let result = try execute("/usr/bin/sandbox-exec", ["-p", "(version 1)(allow default)(deny network*)",
                                executable.path, "-t", "-d", directory.path, "-f", config.path], 15)
        guard result.settled else { throw RouterRuntimeError.processUnsettled }
        guard !result.timedOut else { throw RouterRuntimeError.processTimedOut }
        guard result.exitCode == 0 else { throw RouterRuntimeError.configurationRejected }
        guard try files.readPrivate(config) == data,
              try files.readPrivate(executable, maximum: 128 * 1024 * 1024) == coreBytes else { throw RouterRuntimeError.unsafeFile }
    }
}
