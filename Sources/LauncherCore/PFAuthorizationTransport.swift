import Foundation
import Darwin

/// Invoked only after a user click. Credentials stay in the macOS authorization UI.
public enum PFAuthorizationTransport {
    /// Caller must hold the App journal lock, persist `intent` before this call, then
    /// CAS+fsync the supplied armed intent in the callback. Restored operations never call this automatically.
    public static func submitGated(_ intent: PFAuthorizationIntent, permit: PFAuthorizationStartPermit,
                                   persistBeforeStart: (PFAuthorizationIntent) throws -> Void) -> PFAuthorizationResult {
        guard !intent.startMayHaveBeenSent, intent.identity == nil else { return .init(.unknown, settled: false) }
        // A CLI argument, setting or saved journal cannot choose the executable.
        let bundle = Bundle.main.bundleURL
        guard bundle.pathExtension == "app", Bundle.main.executableURL?.lastPathComponent == "ClaudeLauncher" else {
            return .init(.unknown)
        }
        let helper = bundle.appendingPathComponent("Contents/MacOS/launcher-tool")
        var info = stat()
        guard lstat(helper.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
              info.st_mode & 0o022 == 0, FileManager.default.isExecutableFile(atPath: helper.path) else {
            return .init(.unknown)
        }
        let output = GatedAuthorizationProcess.capture(executable: helper.path,
            arguments: ["pf-authorization-gate", intent.executionID.uuidString], intent: intent, permit: permit,
            persistBeforeStart: persistBeforeStart)
        return .init(output.complete ? decode(output.data, for: intent.request) : .unknown, settled: output.settled)
    }

    static func script(for request: PFRecoveryRequest) -> String {
        let context = request.context
        // No path, endpoint, secret or arbitrary argument can come from app settings.
        let arguments = ["--id", context.plan_id, "--request-id", request.id,
                         "--expected-revision", String(context.receipt_revision),
                         "--plan-sha256", context.plan_sha256, "--runtime-sha256", context.runtime_sha256,
                         "--service-instance", context.service_instance]
        let command = "/usr/bin/python3 -I -S -B '/Library/Application Support/Claude Launcher PF/pf_control.py' recheck " +
            arguments.joined(separator: " ") + " 2>/dev/null; /usr/bin/true"
        // Preserve structured root errors despite exit 78. Exit zero is NOT success;
        // decode requires an exact result frame and the matching receipt.
        let literal = command.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        return """
        try
            set payload to do shell script "\(literal)" with administrator privileges
            return "PF_CONTROL_JSON_V1" & linefeed & payload
        on error number code
            if code is -128 then
                return "PF_CONTROL_CANCELLED_V1"
            end if
            return "PF_CONTROL_ERROR_V1"
        end try
        """
    }

    private struct Acknowledgement: Decodable {
        let reason: String
        let protection_verified, launch_authorized: Bool
        let recovery: PFRecoveryReceipt
    }

    static func decode(_ data: Data, for request: PFRecoveryRequest) -> PFAuthorizationOutcome {
        guard data.count <= 16_384, let text = String(data: data, encoding: .utf8) else { return .unknown }
        if text == "PF_CONTROL_CANCELLED_V1\n" { return .cancelled }
        let prefix = "PF_CONTROL_JSON_V1\n"
        guard text.hasPrefix(prefix),
              let value = try? JSONDecoder().decode(Acknowledgement.self, from: Data(text.dropFirst(prefix.count).utf8)),
              !value.protection_verified, !value.launch_authorized,
              ["recheck_requested", "recheck_existing_result"].contains(value.reason),
              value.recovery.correlatedStatus(for: request) != nil else { return .unknown }
        return .acknowledged
    }

    typealias Capture = BoundedProcess.Capture
    static func capture(executable: String, arguments: [String], timeout: TimeInterval) -> Capture {
        BoundedProcess.capture(executable: executable, arguments: arguments, timeout: timeout)
    }
}
