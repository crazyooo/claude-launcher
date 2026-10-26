import Foundation

public struct RouterCommandResult {
    public let data: Data
    public let exitCode: Int32
}

/// Offline command dispatcher; never prepares the app data directory or calls a controller.
public enum RouterCommand {
    public static func run(_ arguments: [String], readFile: (String) throws -> Data = RouterInput.read) -> RouterCommandResult {
        struct Failure: Encodable {
            let mode = "offline_router"
            let networkModified = false
            let code: String
            let usage = "router validate PLAN.json | router preview PLAN.json | router explain PLAN.json FLOW.json"
        }
        struct Validation: Encodable {
            let mode = "offline_validation"
            let networkModified = false
            let runtimeVerified = false
            let valid: Bool
            let issues: [RouterIssue]
        }
        func output<T: Encodable>(_ value: T, code: Int32) throws -> RouterCommandResult {
            let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            return .init(data: try encoder.encode(value), exitCode: code)
        }
        do {
            guard let command = arguments.first,
                  (["validate", "preview"].contains(command) && arguments.count == 2) ||
                    (command == "explain" && arguments.count == 3) else {
                return try output(Failure(code: "invalid_arguments"), code: 64)
            }
            let plan = try RouterInput.plan(readFile(arguments[1]))
            switch command {
            case "validate":
                let issues = RouterValidation.issues(in: plan)
                let valid = !issues.contains { $0.severity == .error }
                return try output(Validation(valid: valid, issues: issues), code: valid ? 0 : 2)
            case "preview":
                let preview = try MihomoRoutingCompiler.preview(plan)
                return try output(preview, code: preview.fragment == nil ? 2 : 0)
            default:
                let flow = try RouterInput.flow(readFile(arguments[2]))
                let result = try RouterExplainer.explain(plan, flow: flow)
                return try output(result, code: result.status == "undetermined" ? 3 : 0)
            }
        } catch {
            let code = (error as? RouterInputError)?.code ?? "input_or_encoding_failed"
            // Encoding this fixed ASCII fallback cannot reflect an input filename/secret.
            return (try? output(Failure(code: code), code: 65)) ?? .init(data: Data("{\"code\":\"encoding_failed\"}".utf8), exitCode: 65)
        }
    }
}
