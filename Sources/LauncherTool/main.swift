import Foundation
import LauncherCore
import RoutingCore
import Darwin

func fail(_ message: String) -> Never { FileHandle.standardError.write(Data((message+"\n").utf8)); exit(1) }
func launch(kind: String, arguments: [String], tool: URL) throws -> Never {
    let launchLock = open(Paths.root.appendingPathComponent("launch.lock").path,O_CREAT|O_RDWR,0o600)
    guard launchLock >= 0, flock(launchLock,LOCK_EX|LOCK_NB) == 0 else { throw LauncherError.message("启动请求正在处理，请稍后再试") }
    defer { close(launchLock) }
    let config = try loadJSON(Configuration.self,from:Paths.config); try config.validate()
    if kind == "desktop", config.officialDesktopConsent?.valid == true {
        throw LauncherError.message("已选择桌面普通启动，请使用 official-desktop 命令")
    }
    let state = try loadJSON(Snapshot.self,from:Paths.status)
    guard state.fresh, state.networkAllowed, state.gatewayReady, state.configDigest == config.digest,
          kind == "cli" ? state.cliCompatible : state.desktopCompatible,
          Compatibility.permits(kind:kind,config:config,tool:tool) else { throw LauncherError.message("受保护启动被拒绝：先在启动器中完成配置、兼容性验收并重新检查") }
    let native = URL(fileURLWithPath:kind == "cli" ? Paths.cli : Paths.desktop).resolvingSymlinksInPath().path
    var targetArguments = arguments
    if kind == "desktop" {
        guard !Sessions.active().contains(where:{$0.kind == "desktop"}) else { throw LauncherError.message("桌面会话已经运行") }
        targetArguments = ["--proxy-server=http://127.0.0.1:\(config.gatewayPort)","--proxy-bypass-list=<-loopback>"]
    }
    for (key,value) in Isolation.environment(ProcessInfo.processInfo.environment,port:config.gatewayPort) { setenv(key,value,1) }
    let latest = try loadJSON(Snapshot.self,from:Paths.status)
    guard latest.fresh, latest.networkAllowed, latest.configDigest == config.digest,
          (try loadJSON(Configuration.self,from:Paths.config)).digest == config.digest,
          !Sessions.unmanaged(known:Sessions.active(),excludingOfficialDesktop:config.officialDesktopConsent?.valid == true) else { throw LauncherError.message("启动条件已变化或发现未受管理实例") }
    try Sessions.register(kind:kind)
    // Reapply the same sandbox on every self-spawn. No environment marker grants trust.
    let argv = ["/usr/bin/sandbox-exec","-p",Isolation.profile(port:config.gatewayPort),native] + targetArguments
    let pointers = argv.map { strdup($0) } + [nil]
    // Close inherited descriptors so children cannot keep the guard's heartbeat pipe alive.
    for descriptor in 3..<Int32(min(sysconf(_SC_OPEN_MAX),65536)) { close(descriptor) }
    execv(argv[0],pointers)
    throw LauncherError.message("隔离启动失败")
}
let tool = URL(fileURLWithPath:CommandLine.arguments[0]).standardizedFileURL.resolvingSymlinksInPath()
let arguments = Array(CommandLine.arguments.dropFirst())
do {
    if arguments.first == "router" {
        let result = RouterCommand.run(Array(arguments.dropFirst()))
        FileHandle.standardOutput.write(result.data)
        FileHandle.standardOutput.write(Data([10]))
        exit(result.exitCode)
    }
    if arguments.first == "inspect" {
        guard arguments.count == 2, let target = EnvironmentTarget(rawValue: arguments[1]) else {
            throw LauncherError.message("用法：inspect desktop|cli|diagnostic")
        }
        let settings = try EnvironmentSettings.read()
        let report = EnvironmentInspector.inspect(target: target, settings: settings,
            directory: target == .cli ? FileManager.default.currentDirectoryPath : nil,
            environment: target == .cli ? ProcessInfo.processInfo.environment : nil)
        if target == .cli { try EnvironmentReportStore.saveCLI(report) }
        let recommendation = report.recommendation(settings: try EnvironmentSettings.read(),
                                                   currentNetwork: EnvironmentInspector.networkFingerprint())
        struct InspectionOutput: Encodable {
            let recommendation: EnvironmentRecommendation
            let title: String
            let detail: String
            let report: EnvironmentReport
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        print(String(decoding: try encoder.encode(InspectionOutput(recommendation: recommendation,
            title: recommendation.title, detail: recommendation.detail, report: report)), as: UTF8.self))
        exit(recommendation == .ready ? 0 : (recommendation == .attention ? 2 : 3))
    }
    if arguments.first == "pf-authorization-gate" {
        guard arguments.count == 2, let executionID = UUID(uuidString: arguments[1]) else {
            throw LauncherError.message("授权执行身份无效。")
        }
        try PFAuthorizationGate.run(executionID: executionID)
    }
    if arguments.first == "connector-gateway" {
        guard arguments.count == 2 else { throw LauncherError.message("连接器需要独立配置。") }
        let config = try loadJSON(ConnectorConfiguration.self, from: URL(fileURLWithPath: arguments[1]))
        let gateway = ConnectorGateway(config: config, lifetimeDirectory: URL(fileURLWithPath: arguments[1]).deletingLastPathComponent().resolvingSymlinksInPath()); try gateway.run(); dispatchMain()
    }
    if arguments.first == "connector-guard" {
        guard arguments.count == 1 else { throw LauncherError.message("连接器守卫不接受其他参数。") }
        let supervisor = ConnectorSupervisor(tool: tool); try supervisor.run(); RunLoop.main.run(); exit(0)
    }
    if arguments.first == "connector" {
        guard arguments.count == 2 else { throw LauncherError.message("用法：connector status|block|check") }
        let result = try ConnectorIPC.request(arguments[1])
        print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self)); exit(0)
    }
    if arguments.first == "connector-hold-control" {
        guard arguments.count == 2 else { throw LauncherError.message("用法：connector-hold-control REQUEST.json（v2 恢复屏障；受保护启动仍锁定）") }
        let request = try ConnectorIPC.loadRequest(from: arguments[1], as: ConnectorHoldRequest.self)
        let result = try ConnectorIPC.request(request)
        print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self))
        exit(result.accepted ? 0 : 78)
    }
    if arguments.first == "connector-control" {
        guard arguments.count == 2 else { throw LauncherError.message("用法：connector-control REQUEST.json（prepare/status/commit/cancel/leave；受保护启动仍锁定）") }
        let request = try ConnectorIPC.loadRequest(from: arguments[1])
        let result = try ConnectorIPC.request(request)
        print(String(decoding: try JSONEncoder().encode(result), as: UTF8.self))
        // Acceptance means queued/observed, never that forwarding or protected launch passed.
        exit(result.accepted ? 0 : 78)
    }
    if let command = arguments.first, StrictProtection.launchCommands.contains(command) {
        do { try StrictProtection.requireVerified() }
        catch {
            FileHandle.standardError.write(Data((error.localizedDescription + "\n").utf8))
            exit(78)
        }
    }
    if arguments.first == "preflight" {
        guard arguments.count == 2, let target = CheckTarget(rawValue: arguments[1]) else {
            throw LauncherError.message("用法：preflight desktop|desktopCode|vscode")
        }
        let settings = try PreflightSettings.read()
        let report = NetworkInspector.inspect(target: target, settings: settings)
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]; encoder.dateEncodingStrategy = .iso8601
        print(String(decoding: try encoder.encode(report), as: UTF8.self))
        exit(report.permits(context: NetworkInspector.context(settings: try PreflightSettings.read(), target: target)) ? 0 : 78)
    }
    if arguments.first == "preflight-wrap" {
        guard arguments.count >= 2 else { throw LauncherError.message("缺少插件可执行文件。") }
        do { try PreflightLaunch.wrap(binary: arguments[1], arguments: Array(arguments.dropFirst(2))) }
        catch { FileHandle.standardError.write(Data(("Claude 网络检查：" + error.localizedDescription + "\n").utf8)); exit(78) }
    }
    if arguments.first == "shadowrocket-status" {
        guard arguments.count == 1 else { throw LauncherError.message("用法：shadowrocket-status") }
        let data = try JSONEncoder().encode(ShadowrocketLocal.read())
        print(String(decoding: data, as: UTF8.self))
        exit(0)
    }
    try Paths.prepare()
    switch arguments.first ?? "status" {
    case "gateway":
        let configURL = arguments.count > 1 ? URL(fileURLWithPath:arguments[1]) : Paths.config
        let config = try loadJSON(Configuration.self,from:configURL); try config.validate()
        let gateway = Gateway(config:config,credential:config.authentication ? try Vault.read() : nil)
        try gateway.run(); dispatchMain()
    case "guard":
        let guardian = Guardian(tool:tool); try guardian.run(); RunLoop.main.run()
    case "status", "check", "check-connection", "block", "reload":
        let state = try Control.request(arguments.first ?? "status")
        let data = try JSONEncoder().encode(state); print(String(data:data,encoding:.utf8)!)
    case "run": try launch(kind:"cli",arguments:Array(arguments.dropFirst()),tool:tool)
    case "official-desktop":
        try OfficialDesktopLauncher.openAfterCheck()
        print("官方 Claude 已打开；普通模式，不受启动器断流管理")
    case "desktop": try launch(kind:"desktop",arguments:[],tool:tool)
    case "wrap":
        guard arguments.count >= 2,
              URL(fileURLWithPath:arguments[1]).resolvingSymlinksInPath() == URL(fileURLWithPath:Paths.cli).resolvingSymlinksInPath() else { throw LauncherError.message("包装目标不是当前 Claude Code 原生入口；升级后需重新验证") }
        try launch(kind:"cli",arguments:Array(arguments.dropFirst(2)),tool:tool)
    case "fingerprint":
        let config = try loadJSON(Configuration.self,from:Paths.config)
        guard arguments.count == 2, ["cli","desktop"].contains(arguments[1]) else { throw LauncherError.message("用法：fingerprint cli|desktop") }
        print(try Compatibility.fingerprint(kind:arguments[1],port:config.gatewayPort,tool:tool))
    default: throw LauncherError.message("检测：inspect desktop|cli|diagnostic；旧命令：shadowrocket-status | status | check | check-connection | block | reload | run [args] | desktop | official-desktop | wrap executable [args] | fingerprint cli|desktop")
    }
} catch { fail(error.localizedDescription) }
