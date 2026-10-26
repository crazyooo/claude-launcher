import Foundation

/// Builds injectable `RouterPFArmingExecuteGate.SideEffects` that shell out to
/// `tools/router_pf_failclosed.py`. **Not** the production UI default — the live
/// model stays `.unwired` until an operator explicitly attaches this loader.
///
/// This loader only reports outcomes from the script JSON; it never invents
/// `routing_verified` / `accepted`. Real apply still requires dual confirm flags
/// inside the script (and root).
///
/// Live-verified recipe (2026-10-24 arming): this host's Python site layer ships an
/// injected `sitecustomize` shim that breaks the script (`mkdir(exist_ok=True)`
/// raising PermissionError), so the interpreter **must** run with `-S`. Apply needs
/// root: `.osascriptAdmin` wraps the invocation like the verified manual sequence.
/// The artifact must exist and be applicable before apply — build it through
/// `Recipe.prepare` (generate → dry-run), never by hand-editing.
public enum RouterPFArmingScriptEffects {
    public enum Elevation: Equatable, Sendable {
        /// Run the interpreter directly (no root — apply will refuse with
        /// `root_required_for_apply`; useful for status and refusal-path tests).
        case direct
        /// Wrap the invocation in `osascript … with administrator privileges`,
        /// matching the live-verified arming sequence.
        case osascriptAdmin
    }

    public enum Command: String, Sendable {
        case apply, status, unload
    }

    public struct Config: Equatable, Sendable {
        public let python: String
        public let pythonFlags: [String]
        public let script: String
        public let artifactPath: String
        public let planDigest: String
        public let acknowledgeMutation: Bool
        public let confirmWindow: Bool
        public let elevation: Elevation

        public init(python: String = "/opt/homebrew/bin/python3",
                    pythonFlags: [String] = ["-S"],
                    script: String,
                    artifactPath: String,
                    planDigest: String,
                    acknowledgeMutation: Bool = false,
                    confirmWindow: Bool = false,
                    elevation: Elevation = .direct) {
            self.python = python
            self.pythonFlags = pythonFlags
            self.script = script
            self.artifactPath = artifactPath
            self.planDigest = planDigest
            self.acknowledgeMutation = acknowledgeMutation
            self.confirmWindow = confirmWindow
            self.elevation = elevation
        }
    }

    public struct RunResult: Equatable, Sendable {
        public let payload: [String: String]
        public let exitCode: Int32
        public var armed: Bool { payload["armed"] == "1" }
        public var modified: Bool { payload["pf_modified"] == "1" }
        public var loaded: Bool { payload["pf_rules_loaded"].map { $0 == "1" } ?? armed }
        public var status: String { payload["status"] ?? payload["reason"] ?? "unknown" }
    }

    // MARK: - Invocation building (internal for offline gate tests)

    static func applyArguments(config: Config) -> [String] {
        var args = [config.script, "apply",
                    "--artifact", config.artifactPath,
                    "--plan-digest", config.planDigest]
        if config.confirmWindow { args.append("--i-confirm-pf-arming-user-confirm-v1") }
        if config.acknowledgeMutation { args.append("--i-acknowledge-network-mutation") }
        return args
    }

    static func commandArguments(command: Command, config: Config, confirmUnload: Bool) -> [String] {
        switch command {
        case .apply:
            return applyArguments(config: config)
        case .status:
            return [config.script, "status"]
        case .unload:
            var args = [config.script, "unload"]
            if confirmUnload { args.append("--i-confirm-unload") }
            return args
        }
    }

    /// POSIX sh single-quote for one argv element.
    static func shellQuoted(_ value: String) -> String {
        "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Elevation wrapper. `.direct` runs the interpreter in place; `.osascriptAdmin`
    /// delegates the root prompt to AppleScript exactly like the live sequence.
    static func wrappedInvocation(config: Config, arguments: [String])
        -> (executable: String, arguments: [String]) {
        switch config.elevation {
        case .direct:
            return (config.python, config.pythonFlags + arguments)
        case .osascriptAdmin:
            let command = ([config.python] + config.pythonFlags + arguments)
                .map(shellQuoted).joined(separator: " ")
            // AppleScript string literal: embedded double quotes must be escaped.
            let escaped = command.replacingOccurrences(of: "\"", with: "\\\"")
            return ("/usr/bin/osascript",
                    ["-e", "do shell script \"\(escaped)\" with administrator privileges"])
        }
    }

    /// Run one script command and parse its JSON payload. Spawn failure returns a
    /// RunResult with an empty payload and a spawn-failed reason instead of throwing.
    public static func run(config: Config, command: Command,
                           confirmUnload: Bool = false) -> RunResult {
        let arguments = commandArguments(command: command, config: config, confirmUnload: confirmUnload)
        let invocation = wrappedInvocation(config: config, arguments: arguments)
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: invocation.executable)
        proc.arguments = invocation.arguments
        let out = Pipe(); let err = Pipe()
        proc.standardOutput = out; proc.standardError = err
        do {
            try proc.run(); proc.waitUntilExit()
        } catch {
            return RunResult(payload: ["reason": "script_loader_spawn_failed:\(error)"], exitCode: -1)
        }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        guard let text = String(data: data, encoding: .utf8),
              let json = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any] else {
            return RunResult(payload: ["reason": "script_loader_unparseable_output"], exitCode: proc.terminationStatus)
        }
        var payload: [String: String] = [:]
        for (key, value) in object {
            switch value {
            case let flag as Bool: payload[key] = flag ? "1" : "0"
            case let text as String: payload[key] = text
            case let number as NSNumber: payload[key] = number.stringValue
            default: break
            }
        }
        return RunResult(payload: payload, exitCode: proc.terminationStatus)
    }

    /// Returns SideEffects that invoke `apply` when both confirm flags are set in Config.
    /// Without flags — or when the preview digest does not bind the configured plan —
    /// the loader refuses without spawning a mutating apply.
    public static func make(config: Config) -> RouterPFArmingExecuteGate.SideEffects {
        .init(loadFailClosed: { preview in
            // Digest gate: the executing preview must be the configured plan, and the
            // configured digest must be a full sha256. (Never an `||` bypass.)
            guard config.planDigest.count == 64, preview.planDigest == config.planDigest else {
                return .init(networkModified: false, pfRulesLoaded: false, armed: false,
                             detail: "script_loader_plan_digest_gate")
            }
            guard config.confirmWindow, config.acknowledgeMutation else {
                return .init(networkModified: false, pfRulesLoaded: false, armed: false,
                             detail: "script_loader_refused_missing_dual_confirm_flags")
            }
            let result = run(config: config, command: .apply)
            guard result.exitCode == 0, !result.payload.isEmpty else {
                return .init(networkModified: result.modified, pfRulesLoaded: false, armed: false,
                             detail: "script_loader \(result.status) exit=\(result.exitCode)")
            }
            return .init(networkModified: result.modified, pfRulesLoaded: result.loaded,
                         armed: result.armed,
                         detail: "script_loader status=\(result.status) exit=\(result.exitCode)")
        })
    }

    // MARK: - Recipe: approved targets → applicable artifact → apply-ready Config

    public enum RecipeError: Error, Equatable {
        case addressesRequired
        case digestShapeInvalid
        case generationFailed(reason: String)
        case artifactNotApplicable(blockers: [String])
        case artifactAddressMismatch
        case dryRunFailed(reason: String)
    }

    /// Operator-approved arming inputs. Addresses are **explicit** — resolution
    /// (dig @1.1.1.1 domain A/AAAA) is an operator step, never auto-resolved here,
    /// so the recipe cannot silently arm a stale or attacker-chosen address.
    public struct Recipe {
        public let python: String
        public let pythonFlags: [String]
        public let script: String
        public let planPath: String
        public let planDigest: String
        public let addresses: [String]
        public let outputDir: String

        public init(python: String = "/opt/homebrew/bin/python3",
                    pythonFlags: [String] = ["-S"],
                    script: String, planPath: String, planDigest: String,
                    addresses: [String], outputDir: String) {
            self.python = python
            self.pythonFlags = pythonFlags
            self.script = script
            self.planPath = planPath
            self.planDigest = planDigest
            self.addresses = addresses
            self.outputDir = outputDir
        }

        func direct(arguments: [String]) -> RunResult {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: python)
            proc.arguments = pythonFlags + arguments
            let out = Pipe()
            proc.standardOutput = out
            proc.standardError = Pipe()
            do { try proc.run(); proc.waitUntilExit() }
            catch { return RunResult(payload: ["reason": "spawn_failed:\(error)"], exitCode: -1) }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            var payload: [String: String] = [:]
            if let text = String(data: data, encoding: .utf8),
               let json = text.data(using: .utf8),
               let object = try? JSONSerialization.jsonObject(with: json) as? [String: Any] {
                for (key, value) in object {
                    switch value {
                    case let flag as Bool: payload[key] = flag ? "1" : "0"
                    case let text as String: payload[key] = text
                    case let number as NSNumber: payload[key] = number.stringValue
                    default: break
                    }
                }
            }
            return RunResult(payload: payload, exitCode: proc.terminationStatus)
        }

        /// generate → validate artifact → dry-run. No PF mutation at any step.
        /// Returns the apply-ready Config on success.
        public func prepare() throws -> Config {
            guard !addresses.isEmpty else { throw RecipeError.addressesRequired }
            guard planDigest.count == 64 else { throw RecipeError.digestShapeInvalid }
            var args = [script, "generate", "--plan", planPath, "--plan-digest", planDigest]
            for address in addresses.sorted() { args += ["--address", address] }
            args += ["--output", outputDir]
            let generated = direct(arguments: args)
            guard generated.exitCode == 0, generated.status == "generated" else {
                throw RecipeError.generationFailed(reason: generated.status)
            }
            let artifactPath = (outputDir as NSString).appendingPathComponent("failclosed.artifact.json")
            let confPath = (outputDir as NSString).appendingPathComponent("failclosed.pf.conf")
            guard let data = FileManager.default.contents(atPath: artifactPath),
                  let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw RecipeError.generationFailed(reason: "artifact_unreadable")
            }
            let applicable = (object["applicable"] as? Bool) == true
            let blockers = (object["blockers"] as? [String]) ?? []
            guard applicable, blockers.isEmpty else {
                throw RecipeError.artifactNotApplicable(blockers: blockers)
            }
            let artifactAddresses = Set((object["addresses"] as? [String]) ?? [])
            guard artifactAddresses == Set(addresses) else {
                throw RecipeError.artifactAddressMismatch
            }
            let dry = direct(arguments: [script, "dry-run", "--pf-conf", confPath])
            guard dry.exitCode == 0, dry.status == "dry_run_ok" else {
                throw RecipeError.dryRunFailed(reason: dry.status)
            }
            return Config(python: python, pythonFlags: pythonFlags, script: script,
                          artifactPath: artifactPath, planDigest: planDigest)
        }
    }
}
