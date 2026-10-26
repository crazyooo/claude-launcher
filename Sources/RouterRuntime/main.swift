import Foundation
import RoutingCore
import Darwin

// Separate executable: no retired LauncherCore controls or automatic app-directory preparation.
func output<T: Encodable>(_ value: T, exitCode: Int32) -> Never {
    let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
    if let data = try? encoder.encode(value) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])) }
    exit(exitCode)
}
struct Failure: Encodable {
    let code: String
    let routingVerified = false
    let networkSettingsModified = false
}
let arguments = Array(CommandLine.arguments.dropFirst())
do {
    guard getuid() != 0 else { throw RouterRuntimeError.unsafeFile }
    let service = RouterLaunchdService(root: RouterLaunchdService.userRoot)
    if arguments == ["inspect"] { output(RouterSystemPreview(observation: .collect()), exitCode: 0) }
    if arguments == ["status"] {
        Task {
            do { output(try await service.status(), exitCode: 0) }
            catch { output(Failure(code: (error as? RouterRuntimeError)?.rawValue ?? "runtime_status_failed"), exitCode: 1) }
        }
        dispatchMain()
    }
    if arguments.count == 2, ["start", "stop"].contains(arguments[0]), let id = UUID(uuidString: arguments[1]) {
        output(try arguments[0] == "start" ? service.start(id) : service.stop(id), exitCode: 0)
    }
    guard arguments.count == 3, ["check", "prepare"].contains(arguments[0]) else {
        output(Failure(code: "usage: router-runtime check|prepare CORE PLAN.json; start|stop PREVIEW_ID; status|inspect"), exitCode: 64)
    }
    let core = URL(fileURLWithPath: arguments[1])
    let plan = try RouterInput.plan(RouterInput.read(arguments[2]))
    if arguments[0] == "prepare" { output(try service.prepare(plan: plan, core: core), exitCode: 0) }
    let config = try RouterRuntimeCompiler.compile(plan, controllerPort: 19491, secret: RouterRuntimeCompiler.randomSecret())
    let report = try RouterCoreCheck.run(core: core, configuration: config,
                                        workspace: RouterCoreCheck.temporaryWorkspace())
    output(report, exitCode: 0)
} catch {
    output(Failure(code: (error as? RouterRuntimeError)?.rawValue ?? "runtime_input_or_credential_failed"), exitCode: 1)
}
