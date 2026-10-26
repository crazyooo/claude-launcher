import Foundation
import OSLog

/// Startup errors must be actionable without exposing the private installation or routing plan.
enum RouterSystemHostDiagnostic {
    enum Phase: String, CaseIterable {
        case installation, reaping, journal, stage, baseline, dispatch, runtime, serving
        case processIdentity = "process_identity"
        case hostLease = "host_lease"
        case socketActivation = "socket_activation"
    }
    private static let logger = Logger(subsystem: "local.crazymax.claude-router.system-host", category: "startup")

    enum SocketStep: String, CaseIterable {
        case code, directories, manifest, plist
        case declarationBefore = "declaration_before", declarationAfter = "declaration_after"
        case nodeBefore = "node_before", nodeAfter = "node_after"
        case activation, descriptorCount = "descriptor_count"
        case listenerRead = "listener_read", listenerFamily = "listener_family"
        case listenerType = "listener_type", listenerKind = "listener_kind", listenerAccept = "listener_accept"
        case nameRead = "name_read", addressParse = "address_parse"
        case descriptorFlags = "descriptor_flags"
        case nodeDirectory = "node_directory", nodeRead = "node_read", nodeType = "node_type"
        case nodeOwner = "node_owner", nodeGroup = "node_group", nodeMode = "node_mode", nodeLinks = "node_links"
        case nodeReread = "node_reread", nodeStable = "node_stable"
    }

    static func socketMessage(_ step: SocketStep, error: Error, value: Int? = nil) -> String {
        let reason = (error as? RouterSystemError)?.rawValue ?? "unexpectedError"
        let numeric = (step == .activation || step == .descriptorCount)
            ? value.map { " value=\($0)" } ?? "" : ""
        return "host_socket_failed step=\(step.rawValue) reason=\(reason)" + numeric
    }

    /// Adds bounded diagnostics without translating errors or retrying the operation.
    static func socketStep<T>(_ step: SocketStep, value: Int? = nil,
                              perform: () throws -> T) rethrows -> T {
        do { return try perform() }
        catch {
            let text = socketMessage(step, error: error, value: value)
            logger.error("\(text, privacy: .public)")
            throw error
        }
    }

    static func requireSocket(_ condition: Bool, at step: SocketStep) throws {
        try socketStep(step) {
            guard condition else { throw RouterSystemError.ownershipUnknown }
        }
    }

    static func message(_ phase: Phase, error: Error) -> String {
        let reason = (error as? RouterSystemError)?.rawValue ?? "unexpectedError"
        return "host_failed stage=\(phase.rawValue) reason=\(reason)"
    }
    static func record(_ phase: Phase, error: Error) {
        let text = message(phase, error: error)
        logger.error("\(text, privacy: .public)")
    }
}
