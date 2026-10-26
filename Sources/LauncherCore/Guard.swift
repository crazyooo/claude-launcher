import Foundation
import Network
import AppKit
import Darwin

public final class Guardian {
    private let queue = DispatchQueue(label:"launcher.guard.state")
    private let writeLock = NSLock()
    private var input: FileHandle?
    private var gateway: Process?
    private var snapshot = Snapshot()
    private var config: Configuration?
    private var generation = 0
    private var checking = false
    private var heartbeatTimer: DispatchSourceTimer?
    private var monitor: NWPathMonitor?
    private var observers: [NSObjectProtocol] = []
    private var lockFD: Int32 = -1
    private let tool: URL
    private var ticks = 0
    private var lastPath: String?
    private var lastTick = ProcessInfo.processInfo.systemUptime
    public init(tool: URL) { self.tool = tool }
    public func run() throws {
        try Paths.prepare()
        lockFD = open(Paths.root.appendingPathComponent("guard.lock").path,O_CREAT|O_RDWR,0o600)
        guard lockFD >= 0, flock(lockFD,LOCK_EX|LOCK_NB) == 0 else { throw LauncherError.message("守卫已运行") }
        _ = fcntl(lockFD,F_SETFD,FD_CLOEXEC)
        try Control.serve { command in self.queue.sync { self.handle(command) } }
        queue.sync { self.reload() }
        let timer = DispatchSource.makeTimerSource(queue:queue)
        timer.schedule(deadline:.now(),repeating:1)
        timer.setEventHandler { self.tick() }; heartbeatTimer = timer; timer.resume()
        let monitor = NWPathMonitor(); monitor.pathUpdateHandler = { path in self.queue.async {
            let signature = "\(path.status)-\(path.availableInterfaces.map { "\($0.name):\(path.usesInterfaceType($0.type))" }.sorted())-\(path.supportsIPv4)-\(path.supportsIPv6)"
            if self.lastPath != nil { self.fault("blocked","网络已变化，请重新检查并恢复") }
            self.lastPath = signature
        } }; self.monitor = monitor; monitor.start(queue:DispatchQueue(label:"launcher.guard.path"))
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName:name,object:nil,queue:nil) { _ in self.queue.async { self.fault("blocked","睡眠或唤醒后需要重新检查") } })
        }
        signal(SIGTERM,SIG_IGN); signal(SIGINT,SIG_IGN)
        for sig in [SIGTERM,SIGINT] {
            let source = DispatchSource.makeSignalSource(signal:sig,queue:queue)
            source.setEventHandler { self.fault("guard","守卫已停止"); self.writeLock.lock(); try? self.input?.close(); self.input = nil; self.writeLock.unlock(); exit(0) }
            source.resume(); signalSources.append(source)
        }
    }
    private var signalSources: [DispatchSourceSignal] = []
    private func send(_ command: String) {
        writeLock.lock(); defer { writeLock.unlock() }
        do { try input?.write(contentsOf:Data((command+"\n").utf8)) } catch { /* Gateway independently fails closed. */ }
    }
    private func persist() { snapshot.updated = Date(); try? saveJSON(snapshot,to:Paths.status) }
    private func note(_ text: String) {
        snapshot.events.insert(Event(message:text),at:0); snapshot.events = Array(snapshot.events.prefix(80))
    }
    private func fault(_ state: String, _ reason: String) {
        generation += 1; checking = false; send("BLOCK"); snapshot.networkAllowed = false; snapshot.proxyCheck = nil
        if snapshot.state != state || snapshot.reason != reason { snapshot.faultTime = Date(); note(reason) }
        snapshot.state = state; snapshot.reason = reason; persist()
    }
    private func reload() {
        fault("unconfigured","请完成首次配置")
        writeLock.lock(); try? input?.close(); input = nil; writeLock.unlock()
        if let previous = gateway, previous.isRunning { previous.terminate()
            let deadline = Date().addingTimeInterval(0.4)
            while previous.isRunning && Date() < deadline { Thread.sleep(forTimeInterval:0.02) }
            if previous.isRunning { kill(previous.processIdentifier,SIGKILL) }
            previous.waitUntilExit() }; gateway = nil; snapshot.gatewayReady = false
        do {
            let value = try loadJSON(Configuration.self,from:Paths.config); try value.validate(); config = value; snapshot.configDigest = value.digest
            snapshot.desktopMode = value.officialDesktopConsent?.valid == true ? "connection-checked-official" : "protected"
            if value.authentication { _ = try Vault.read() }
            let process = Process(); process.executableURL = tool; process.arguments = ["gateway"]
            let pipe = Pipe(), output = Pipe(); process.standardInput = pipe; process.standardOutput = output; process.standardError = FileHandle.nullDevice
            let currentGeneration = generation
            var buffered = Data()
            output.fileHandleForReading.readabilityHandler = { handle in
                let data = handle.availableData
                if data.isEmpty { handle.readabilityHandler = nil; return }
                self.queue.async {
                    guard currentGeneration <= self.generation, self.gateway === process else { return }
                    buffered.append(data)
                    while let end = buffered.firstIndex(of:10) {
                        let line = String(data:buffered[..<end],encoding:.utf8); buffered.removeSubrange(...end)
                        if line == "READY" { self.snapshot.gatewayReady = true; self.fault("blocked","网关已就绪，等待手动检查") }
                        if line == "LISTENER_FAILED" { self.fault("port","网关监听失败：请检查端口占用") }
                    }
                }
            }
            process.terminationHandler = { _ in self.queue.async {
                guard self.gateway === process else { return }
                self.snapshot.gatewayReady = false
                if self.snapshot.state != "port" { self.fault("guard","网关已退出，现有连接已断开") }
            } }
            try process.run(); gateway = process
            writeLock.lock(); input = pipe.fileHandleForWriting; writeLock.unlock()
            fault("blocked","网关启动中")
        } catch { config = nil; fault("unconfigured","配置无效或认证信息不可用，请检查设置") }
        persist()
    }
    private func tick() {
        let now = ProcessInfo.processInfo.systemUptime
        if now - lastTick > 2.5 { fault("guard","守卫调度中断，需重新检查") }; lastTick = now
        if let config, (try? loadJSON(Configuration.self,from:Paths.config))?.digest != config.digest {
            fault("blocked","配置已变化，请重新加载并检查")
        }
        send("HEARTBEAT"); ticks += 1
        if ticks % 3 == 0 {
            let sessions = Sessions.active(); snapshot.sessions = sessions.count
            if Sessions.unmanaged(known:sessions, excludingOfficialDesktop:config?.officialDesktopConsent?.valid == true) { fault("unmanaged","检测到未受管理的 Claude，请手动退出该实例") }
            if snapshot.networkAllowed && !checking { snapshot.state = sessions.isEmpty ? "ready" : "running" }
        }
        if let check = snapshot.proxyCheck, !check.current(for:config?.digest ?? "") {
            snapshot.proxyCheck = nil
            if snapshot.state == "connection-ready" { snapshot.state = "blocked"; snapshot.reason = "代理检查已过期；点击打开时会重新检查" }
        }
        if ticks % 30 == 0, snapshot.networkAllowed, !checking { check(manual:false) }
        persist()
    }
    private func handle(_ command: String) -> Snapshot {
        switch command {
        case "status": break
        case "block": fault("blocked","已手动阻断受管理会话")
        case "reload": reload()
        case "check": if !checking { check(manual:true) }
        case "check-connection":
            if checking {
                var busy = snapshot
                busy.state = "check-busy"; busy.proxyCheck = nil
                busy.reason = "已有检查正在进行，请稍后重试"
                return busy
            }
            check(manual:true, connectionOnly:true)
        default: break
        }
        return snapshot
    }
    private func check(manual: Bool, connectionOnly: Bool = false) {
        if connectionOnly && config?.officialDesktopConsent?.valid != true {
            fault("blocked","尚未同意官方桌面普通启动模式"); return
        }
        guard let config, snapshot.gatewayReady, gateway?.isRunning == true else {
            fault(self.config == nil ? "unconfigured" : "guard",self.config == nil ? "请完成首次配置" : "网关未运行，请重新加载配置"); return
        }
        if Sessions.unmanaged(known:Sessions.active(), excludingOfficialDesktop:config.officialDesktopConsent?.valid == true) { fault("unmanaged","请先退出未受管理的 Claude"); return }
        if connectionOnly {
            // Keep existing protected traffic unchanged until an actual failure.
            generation += 1
            snapshot.proxyCheck = nil
            snapshot.state = "checking"
            snapshot.reason = "正在核对代理出口"
            persist()
        } else if manual { fault("checking","正在检查代理、出口及客户端兼容性") }
        checking = true; let ticket = generation
        let activeKinds = Set(Sessions.active().map(\.kind))
        queue.asyncAfter(deadline:.now()+12) {
            if self.generation == ticket && self.checking { self.fault("guard","完整检查超过 12 秒，连接已阻断") }
        }
        DispatchQueue.global(qos:.utility).async {
            // Explicit HTTP proxy, empty no_proxy, fixed HTTPS destination; curl never falls back.
            let result = try? Subprocess.capture("/usr/bin/curl",["--silent","--show-error","--fail","--max-time","8","--connect-timeout","4","--noproxy","","--proxy","http://127.0.0.1:\(config.probePort)","--proto","=https","https://api.ipify.org"],timeout:9)
            let ip = result.flatMap { $0.0 == 0 ? normalizedIP($0.1) : nil }
            let sampled = Date()
            if ip == nil { self.queue.async { if self.generation == ticket { self.fault("proxy","代理或出口探测不可达；连接已阻断") } }; return }
            if ip != normalizedIP(config.expectedIP) { self.queue.async {
                if self.generation == ticket { self.snapshot.observedIP = ip; self.snapshot.lastExitCheck = sampled; self.fault("exit","实际出口与已确认的固定 IP 不一致") }
            }; return }
            if connectionOnly {
                self.queue.async {
                    guard self.generation == ticket else { return }
                    self.checking = false
                    guard let ip else { self.fault("proxy","代理探测无有效出口"); return }
                    self.snapshot.recordProxyCheck(ip:ip,at:sampled,config:config)
                    self.note("代理检查通过，允许普通打开官方桌面")
                    // No ALLOW, no compatibility acceptance and no managed Desktop session.
                    self.persist()
                }
                return
            }
            let cli = Compatibility.permits(kind:"cli",config:config,tool:self.tool)
            let desktop = Compatibility.permits(kind:"desktop",config:config,tool:self.tool)
            self.queue.async {
                guard self.generation == ticket else { return }; self.checking = false
                self.snapshot.cliCompatible = cli; self.snapshot.desktopCompatible = desktop
                guard let ip else { self.fault("proxy","代理或出口探测不可达；连接已阻断"); return }
                self.snapshot.observedIP = ip; self.snapshot.lastExitCheck = sampled
                guard ip == normalizedIP(config.expectedIP) else { self.fault("exit","实际出口与已确认的固定 IP 不一致"); return }
                guard (cli || desktop), (!activeKinds.contains("cli") || cli), (!activeKinds.contains("desktop") || desktop) else { self.fault("incompatible","出口已核对；客户端完整兼容性验收尚未通过"); return }
                guard self.snapshot.gatewayReady, self.gateway?.isRunning == true else { self.fault("guard","网关未运行"); return }
                if manual {
                    self.send("HEARTBEAT"); self.send("ALLOW"); self.snapshot.networkAllowed = true
                    self.snapshot.state = self.snapshot.sessions == 0 ? "ready" : "running"; self.snapshot.faultTime = nil
                    self.snapshot.reason = "检查通过，仅已验收的客户端可启动"; self.note("手动恢复成功")
                }
                self.persist()
            }
        }
    }
}
