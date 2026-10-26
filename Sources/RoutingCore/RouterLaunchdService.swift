import Foundation
import CryptoKit
import Darwin

public struct RouterServicePreview: Codable {
    public let id: UUID
    public let summary: RouterRuntimeSummary
    public let createdAt: Date
    public let expiresAt: Date
    public let effect: String
}

public struct RouterRetainedOperation: Equatable {
    public let id: UUID
    public let phase: String
}

public struct RouterServiceStatus: Encodable {
    public let state: String
    public let instance: UUID?
    public let reason: String
    public let controllerHealthy: Bool
    public let routingVerified = false
    public let networkSettingsModified = false
}

/// launchd owns the core directly. Birth identity is still checked after removing a job.
/// Only control-only instances are available here. System routing requires a separate root provider.
public final class RouterLaunchdService {
    private let files: RouterRuntimeFiles
    private let command: (String, [String], TimeInterval) throws -> (RouterProcessResult, Data)
    private let observeProcess: (Int32) -> RouterProcessObservation
    private let verifyCore: (URL) throws -> Void
    private let connectionBody: (UInt16, String, TimeInterval) throws -> Data
    private let connectionListener: (RouterProcessIdentity, UInt16, TimeInterval) throws -> RouterSystemControllerListener.Observation
    private var domain: String { "gui/\(getuid())" }
    private var target: String { domain + "/" + RouterCoreRelease.label }
    private var activeURL: URL { files.root.appendingPathComponent("active.json") }
    enum Phase: String, Codable { case pendingStart, running, pendingStop, stopped }
    struct Active: Codable { let id: UUID; var phase: Phase; var process: RouterProcessIdentity?; var exitConfirmed = false }
    struct Receipt: Codable {
        let preview: RouterServicePreview
        let configurationDigest: String
        let plistDigest: String
        let arguments: [String]
    }
    public convenience init(root: URL) { self.init(root: root, command: RouterRuntimeProcess.capture) }
    init(root: URL, command: @escaping (String, [String], TimeInterval) throws -> (RouterProcessResult, Data),
         observeProcess: @escaping (Int32) -> RouterProcessObservation = RouterProcessIdentity.observe,
         verifyCore: @escaping (URL) throws -> Void = RouterCoreRelease.verify,
         connectionBody: @escaping (UInt16, String, TimeInterval) throws -> Data = {
             try RouterSystemControllerHTTP.connections(port: $0, secret: $1, until: $2)
         },
         connectionListener: @escaping (RouterProcessIdentity, UInt16, TimeInterval) throws -> RouterSystemControllerListener.Observation = {
             try RouterSystemControllerListener.observeUser($0, port: $1, deadline: $2)
         }) {
        files = .init(root: root); self.command = command; self.observeProcess = observeProcess; self.verifyCore = verifyCore
        self.connectionBody = connectionBody; self.connectionListener = connectionListener
    }
    public static var userRoot: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/ClaudeLauncher/router-runtime")
    }
    private func generation(_ id: UUID) -> URL { files.root.appendingPathComponent(id.uuidString.lowercased()) }
    private func digest(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
    private func receipt(_ id: UUID) throws -> Receipt {
        let value = try JSONDecoder().decode(Receipt.self, from: files.readPrivate(generation(id).appendingPathComponent("receipt.json")))
        guard value.preview.id == id, value.preview.summary.mode == "controlOnly",
              value.preview.summary.coreVersion == RouterCoreRelease.version else { throw RouterRuntimeError.ownershipUnknown }
        return value
    }
    private func active() throws -> Active? {
        var info = stat()
        if lstat(activeURL.path, &info) != 0 {
            if errno == ENOENT { return nil }; throw RouterRuntimeError.ownershipUnknown
        }
        return try JSONDecoder().decode(Active.self, from: files.readPrivate(activeURL))
    }
    /// A local journal identity, never evidence of a live or healthy process.
    public func retainedOperation() throws -> RouterRetainedOperation? {
        var info = stat()
        if lstat(files.root.path, &info) != 0 {
            if errno == ENOENT { return nil }
            throw RouterRuntimeError.ownershipUnknown
        }
        try files.validateDirectory(files.root)
        guard let record = try active() else { return nil }
        let value = try receipt(record.id)
        guard !value.preview.summary.tunEnabled, !value.preview.summary.routingVerified,
              !value.preview.summary.networkSettingsModified,
              let after = try active(), after.id == record.id, after.phase == record.phase,
              after.process == record.process, after.exitConfirmed == record.exitConfirmed else {
            throw RouterRuntimeError.ownershipUnknown
        }
        return .init(id: record.id, phase: record.phase.rawValue)
    }

    private func save(_ value: Active) throws { try files.replacePrivate(JSONEncoder().encode(value), at: activeURL) }
    private func process(_ output: String, id: UUID, allowPreExec: Bool = false) throws -> RouterProcessIdentity {
        let lines = output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.contains("state = running"), let line = lines.first(where: { $0.hasPrefix("pid = ") }),
              let pid = Int32(line.dropFirst(6)), case .present(let identity) = observeProcess(pid),
              identity.executable == generation(id).appendingPathComponent("mihomo").path ||
                (allowPreExec && identity.executable == "/usr/bin/sandbox-exec") else { throw RouterRuntimeError.ownershipUnknown }
        return identity
    }
    static func jobProvesExit(_ output: String) -> Bool {
        let lines = output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        return lines.contains("state = not running") && !lines.contains(where: { $0.hasPrefix("pid = ") }) &&
            lines.contains(where: { $0.hasPrefix("runs = ") && (Int($0.dropFirst(7)) ?? 0) > 0 }) &&
            lines.contains(where: { $0.hasPrefix("last exit code = ") || $0.hasPrefix("last terminating signal = ") })
    }
    static func continues(_ previous: RouterProcessIdentity, as current: RouterProcessIdentity, corePath: String) -> Bool {
        previous.pid == current.pid && previous.seconds == current.seconds && previous.microseconds == current.microseconds &&
            current.executable == corePath && (previous.executable == corePath || previous.executable == "/usr/bin/sandbox-exec")
    }
    private func job(until deadline: TimeInterval? = nil) throws -> String? {
        let timeout = deadline.map { min(3, $0 - ProcessInfo.processInfo.systemUptime) } ?? 3
        guard timeout > 0 else { throw RouterConnectionFailure.stale }
        let (result, data) = try command("/bin/launchctl", ["print", target], timeout)
        guard result.settled, !result.timedOut else { throw RouterRuntimeError.ownershipUnknown }
        if result.exitCode == 113 { return nil }
        guard result.exitCode == 0, let value = String(data: data, encoding: .utf8) else { throw RouterRuntimeError.ownershipUnknown }
        return value
    }
    static func matchesJob(_ output: String, plist: String, arguments: [String]) -> Bool {
        let lines = output.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) }
        guard lines.contains("path = " + plist), lines.contains("program = " + (arguments.first ?? "")),
              let start = lines.firstIndex(of: "arguments = {"),
              let end = lines[(start + 1)...].firstIndex(of: "}") else { return false }
        return Array(lines[(start + 1)..<end]) == arguments
    }
    private func owned(_ output: String, _ receipt: Receipt) throws {
        let plist = generation(receipt.preview.id).appendingPathComponent("agent.plist")
        guard digest(try files.readPrivate(plist)) == receipt.plistDigest,
              Self.matchesJob(output, plist: plist.path, arguments: receipt.arguments) else { throw RouterRuntimeError.ownershipUnknown }
    }

    static func controlSandbox(port: UInt16, execute: (String, [String], TimeInterval) throws -> RouterProcessResult) throws -> String {
        guard port > 1024 else { throw RouterRuntimeError.invalidController }
        let profile = "(version 1)(allow default)(deny network*)(allow network-inbound (local ip \"localhost:\(port)\"))"
        let check = try execute("/usr/bin/sandbox-exec", ["-p", profile, "/usr/bin/true"], 3)
        guard check.settled else { throw RouterRuntimeError.processUnsettled }
        guard !check.timedOut else { throw RouterRuntimeError.processTimedOut }
        guard check.exitCode == 0 else { throw RouterRuntimeError.configurationRejected }
        return profile
    }

    public func prepare(plan: RouterPlan, core: URL, port: UInt16 = 19491) throws -> RouterServicePreview {
        try files.locked {
            guard try job() == nil else { throw RouterRuntimeError.alreadyLoaded }
            guard try active().map({ $0.phase == .stopped }) ?? true else { throw RouterRuntimeError.ownershipUnknown }
            let sandbox = try Self.controlSandbox(port: port) { try command($0, $1, $2).0 }
            let secret = try RouterRuntimeCompiler.randomSecret()
            let config = try RouterRuntimeCompiler.compile(plan, controllerPort: port, secret: secret)
            _ = try RouterCoreCheck.run(core: core, configuration: config, workspace: RouterCoreCheck.temporaryWorkspace())
            let directory = try files.createGeneration()
            guard let id = UUID(uuidString: directory.lastPathComponent) else { throw RouterRuntimeError.operationFailed }
            let executable = directory.appendingPathComponent("mihomo"), configURL = directory.appendingPathComponent("config.json")
            try files.writeNew(RouterCoreRelease.verifiedBytes(core), to: executable, executable: true)
            try files.writeNew(config.privateJSON, to: configURL)
            // Only local management traffic is possible in this mode, including if a config is accidentally broadened.
            let arguments = ["/usr/bin/sandbox-exec", "-p", sandbox, executable.path, "-d", directory.path, "-f", configURL.path]
            let plist = try PropertyListSerialization.data(fromPropertyList: [
                "Label": RouterCoreRelease.label, "ProgramArguments": arguments,
                "RunAtLoad": true, "KeepAlive": false, "ProcessType": "Background", "ExitTimeOut": 5,
                "EnvironmentVariables": ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"],
                "StandardOutPath": "/dev/null", "StandardErrorPath": "/dev/null"
            ], format: .xml, options: 0)
            try files.writeNew(plist, to: directory.appendingPathComponent("agent.plist"))
            let now = Date()
            let preview = RouterServicePreview(id: id, summary: config.summary, createdAt: now, expiresAt: now.addingTimeInterval(600),
                effect: "Start one user launchd core with authenticated loopback management only; no TUN, DNS interception or proxy listeners. Ends at logout or explicit stop.")
            let value = Receipt(preview: preview, configurationDigest: digest(config.privateJSON), plistDigest: digest(plist), arguments: arguments)
            try files.writeNew(JSONEncoder().encode(value), to: directory.appendingPathComponent("receipt.json"))
            return preview
        }
    }

    public func start(_ id: UUID) throws -> RouterServiceStatus {
        try files.locked {
            let value = try receipt(id)
            if let current = try job() {
                guard try active()?.id == id else { throw RouterRuntimeError.alreadyLoaded }
                try owned(current, value)
                return .init(state: "registered", instance: id, reason: "existing_instance_not_restarted", controllerHealthy: false)
            }
            guard try active().map({ $0.phase == .stopped }) ?? true else { throw RouterRuntimeError.ownershipUnknown }
            guard value.preview.createdAt <= Date(), Date() < value.preview.expiresAt else { throw RouterRuntimeError.stalePlan }
            let directory = generation(id), plist = directory.appendingPathComponent("agent.plist")
            try verifyCore(directory.appendingPathComponent("mihomo"))
            guard digest(try files.readPrivate(directory.appendingPathComponent("config.json"))) == value.configurationDigest,
                  digest(try files.readPrivate(plist)) == value.plistDigest else { throw RouterRuntimeError.ownershipUnknown }
            try checkPort(value.preview.summary.controllerPort)
            // Persist identity before bootstrap. Lost replies are reconciled by this same label and instance.
            try save(Active(id: id, phase: .pendingStart, process: nil))
            let (result, _) = try command("/bin/launchctl", ["bootstrap", domain, plist.path], 8)
            guard result.settled, !result.timedOut else { throw RouterRuntimeError.ownershipUnknown }
            guard let current = try job() else { throw RouterRuntimeError.operationFailed }
            try owned(current, value)
            if let identity = try? process(current, id: id, allowPreExec: true) {
                try save(Active(id: id, phase: .pendingStart, process: identity))
            } else if Self.jobProvesExit(current) {
                var record = Active(id: id, phase: .pendingStart, process: nil); record.exitConfirmed = true; try save(record)
            }
            return .init(state: "registered", instance: id, reason: "awaiting_controller_health", controllerHealthy: false)
        }
    }

    public func stop(_ id: UUID) throws -> RouterServiceStatus {
        try files.locked {
            guard var record = try active(), record.id == id else { throw RouterRuntimeError.ownershipUnknown }
            if let current = try job() {
                try owned(current, receipt(id))
                if let identity = try? process(current, id: id, allowPreExec: true) { record.process = identity }
                if Self.jobProvesExit(current) { record.exitConfirmed = true }
                // Preserve the launchd record until it provides process identity or terminal evidence.
                guard record.process != nil || record.exitConfirmed else { throw RouterRuntimeError.ownershipUnknown }
                record.phase = .pendingStop; try save(record)
                let (result, _) = try command("/bin/launchctl", ["bootout", target], 8)
                guard result.settled, !result.timedOut else { throw RouterRuntimeError.ownershipUnknown }
            }
            guard try job() == nil else { throw RouterRuntimeError.ownershipUnknown }
            if record.phase != .stopped && !record.exitConfirmed {
                guard let identity = record.process else { throw RouterRuntimeError.ownershipUnknown }
                let deadline = ProcessInfo.processInfo.systemUptime + 5
                while !observeProcess(identity.pid).provesExit(of: identity) && ProcessInfo.processInfo.systemUptime < deadline {
                    Thread.sleep(forTimeInterval: 0.05)
                }
                guard observeProcess(identity.pid).provesExit(of: identity) else {
                    return .init(state: "stopping", instance: id, reason: "owned_process_exit_unconfirmed", controllerHealthy: false)
                }
            }
            record.phase = .stopped; try save(record)
            return .init(state: "stopped", instance: id, reason: "owned_job_removed", controllerHealthy: false)
        }
    }

    public func status() async throws -> RouterServiceStatus {
        // Do not create runtime directories merely to display status.
        guard FileManager.default.fileExists(atPath: files.root.path) else {
            guard try job() == nil else { throw RouterRuntimeError.ownershipUnknown }
            return .init(state: "stopped", instance: nil, reason: "not_prepared", controllerHealthy: false)
        }
        let snapshot: (Receipt, String, RouterProcessIdentity)? = try files.locked {
            guard let current = try job() else {
                if var record = try active(), record.phase != .stopped {
                    if !record.exitConfirmed {
                        guard let identity = record.process, observeProcess(identity.pid).provesExit(of: identity) else {
                            throw RouterRuntimeError.ownershipUnknown
                        }
                    }
                    record.phase = .stopped; try save(record)
                }
                return nil
            }
            guard var record = try active(), record.phase != .pendingStop, record.phase != .stopped else { throw RouterRuntimeError.ownershipUnknown }
            let id = record.id
            let value = try receipt(id); try owned(current, value)
            let identity = try process(current, id: id)
            if let previous = record.process, !Self.continues(previous, as: identity, corePath: generation(id).appendingPathComponent("mihomo").path) {
                throw RouterRuntimeError.ownershipUnknown
            }
            record.process = identity; record.phase = .running; try save(record)
            let config = try files.readPrivate(generation(id).appendingPathComponent("config.json"))
            guard digest(config) == value.configurationDigest,
                  let object = try JSONSerialization.jsonObject(with: config) as? [String: Any], let secret = object["secret"] as? String else {
                throw RouterRuntimeError.ownershipUnknown
            }
            return (value, secret, identity)
        }
        guard let (value, secret, identity) = snapshot else { return .init(state: "stopped", instance: nil, reason: "job_absent", controllerHealthy: false) }
        let healthy = (try? await RouterLocalRequest.version(port: value.preview.summary.controllerPort, secret: secret)) != nil
        return try files.locked {
            guard let record = try active(), record.id == value.preview.id, record.phase == .running,
                  let current = try job(), try process(current, id: record.id) == identity else { throw RouterRuntimeError.ownershipUnknown }
            try owned(current, value)
            return .init(state: healthy ? "running" : "fault", instance: value.preview.id,
                         reason: healthy ? "control_only_healthy" : "controller_unavailable", controllerHealthy: healthy)
        }
    }

    public func connections(request: UUID, instance: UUID? = nil) throws -> RouterConnectionSnapshot {
        do {
            return try files.observingExisting {
                let deadline = ProcessInfo.processInfo.systemUptime + 5
                struct Evidence: Equatable {
                    let active: Data
                    let receipt: Data
                    let process: RouterProcessIdentity
                    let listeners: [RouterSystemControllerListener.Signature]
                    let material: RouterConnectionMaterial
                    let binding: RouterConnectionBinding
                    let port: UInt16
                }
                let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys]
                var first: Evidence?
                func observe() throws -> RouterConnectionBinding {
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterConnectionFailure.stale }
                    guard let record = try active() else { throw RouterConnectionFailure.noActiveInstance }
                    guard record.phase == .running, !record.exitConfirmed else {
                        throw record.phase == .stopped ? RouterConnectionFailure.noActiveInstance : .unavailable
                    }
                    guard let identity = record.process, let current = try job(until: deadline),
                          try process(current, id: record.id) == identity else { throw RouterConnectionFailure.identityChanged }
                    let value = try receipt(record.id); try owned(current, value)
                    guard !value.preview.summary.tunEnabled, !value.preview.summary.routingVerified,
                          !value.preview.summary.networkSettingsModified else { throw RouterConnectionFailure.identityChanged }
                    let config = try files.readPrivate(generation(record.id).appendingPathComponent("config.json"))
                    guard digest(config) == value.configurationDigest else { throw RouterConnectionFailure.identityChanged }
                    let object = try RouterStrictJSON.object(config, maximumBytes: 2_100_000, maximumValues: 80_000)
                    let port = value.preview.summary.controllerPort
                    guard port > 1024, object["external-controller"] as? String == "127.0.0.1:\(port)" else {
                        throw RouterConnectionFailure.identityChanged
                    }
                    let material = try RouterConnectionMaterial.read(object)
                    try verifyCore(generation(record.id).appendingPathComponent("mihomo"))
                    guard case .observed(let listeners) = try connectionListener(identity, port, deadline), !listeners.isEmpty else {
                        throw RouterConnectionFailure.identityChanged
                    }
                    struct Epoch: Encodable { let boot: UUID; let process: RouterProcessIdentity }
                    let binding = RouterConnectionBinding(mode: .userManaged, installation: nil, instance: record.id,
                        epoch: digest(try encoder.encode(Epoch(boot: RouterSystemKernelObservation.bootID(), process: identity))),
                        configurationDigest: value.configurationDigest)
                    let evidence = Evidence(active: try encoder.encode(record), receipt: try encoder.encode(value),
                        process: identity, listeners: listeners, material: material, binding: binding, port: port)
                    if let first, first != evidence { throw RouterConnectionFailure.identityChanged }
                    first = evidence
                    return binding
                }
                return try RouterConnectionCollector.read(request: request, expectedInstance: instance, mode: .userManaged,
                    observe: observe, readBody: { _ in
                        guard let sample = first else { throw RouterConnectionFailure.identityChanged }
                        return (try self.connectionBody(sample.port, sample.material.secret, deadline), sample.material.redactions)
                    }, clock: { (Date(), ProcessInfo.processInfo.systemUptime) })
            }
        } catch { throw RouterConnectionWire.classify(error) }
    }

    private func checkPort(_ port: UInt16) throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RouterRuntimeError.operationFailed }; defer { close(fd) }
        var address = sockaddr_in(); address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET); address.sin_port = port.bigEndian
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard result == 0 else { throw RouterRuntimeError.portOccupied }
    }
}
