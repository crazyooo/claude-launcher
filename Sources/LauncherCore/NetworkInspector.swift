import Foundation
import CFNetwork
import SystemConfiguration
import AppKit

struct CommandOutput { let code: Int32; let text: String }
enum ReadCommand {
    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 5,
                    environment: [String: String]? = nil, input: Data? = nil, terminationGrace: TimeInterval = 0.05) -> CommandOutput {
        let task = Process(); task.executableURL = URL(fileURLWithPath: executable); task.arguments = arguments
        if let environment { task.environment = environment }
        let pipe = Pipe(); task.standardOutput = pipe; task.standardError = FileHandle.nullDevice
        let stdin = Pipe()
        task.standardInput = input == nil ? FileHandle.nullDevice : stdin
        do { try task.run() } catch { return .init(code: -1, text: "") }
        if let input {
            // Input is restricted to a small credential envelope, never argv or environment.
            DispatchQueue.global(qos: .utility).async {
                try? stdin.fileHandleForWriting.write(contentsOf: input)
                try? stdin.fileHandleForWriting.close()
            }
        }
        // These commands have bounded output (curl additionally enforces max-filesize).
        let reader = OutputReader()
        let group = DispatchGroup(); group.enter()
        DispatchQueue.global(qos: .utility).async {
            reader.set(pipe.fileHandleForReading.readDataToEndOfFile()); group.leave()
        }
        let deadline = Date().addingTimeInterval(timeout)
        while task.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.025) }
        if task.isRunning {
            task.terminate()
            let cleanupDeadline = connectorTime() + max(0.05, terminationGrace)
            while task.isRunning && connectorTime() < cleanupDeadline { Thread.sleep(forTimeInterval: 0.025) }
            if task.isRunning { kill(task.processIdentifier, SIGKILL) }
        }
        task.waitUntilExit()
        guard group.wait(timeout: .now() + 1) == .success else { return .init(code: -2, text: "") }
        return .init(code: task.terminationStatus, text: String(decoding: reader.get().prefix(131072), as: UTF8.self))
    }
}
private final class OutputReader: @unchecked Sendable {
    private let lock = NSLock(); private var data = Data()
    func set(_ value: Data) { lock.lock(); data = value; lock.unlock() }
    func get() -> Data { lock.lock(); defer { lock.unlock() }; return data }
}

public struct ProbeTransport: Equatable {
    public let proxy: String?
    public let error: String?
    public init(proxy: String? = nil, error: String? = nil) { self.proxy = proxy; self.error = error }
    public var label: String { error ?? proxy ?? "系统路由（含当前 VPN/TUN）" }
    public static func explicit(_ value: String) -> ProbeTransport {
        guard let u = URLComponents(string: value), ["http", "https", "socks5h"].contains(u.scheme ?? ""),
              let host = u.host, !host.isEmpty, let port = u.port, (1...65535).contains(port),
              u.user == nil, u.password == nil, u.query == nil, u.fragment == nil, u.path.isEmpty || u.path == "/" else {
            return .init(error: "代理地址无效或包含认证信息；认证代理尚需钥匙串适配。")
        }
        let cleanHost = host.hasPrefix("[") && host.hasSuffix("]") ? String(host.dropFirst().dropLast()) : host
        return .init(proxy: "\(u.scheme!)://\(cleanHost.contains(":") ? "[\(cleanHost)]" : cleanHost):\(port)")
    }
    public static func system(host: String) -> ProbeTransport {
        guard let raw = CFNetworkCopySystemProxySettings()?.takeRetainedValue(),
              let url = URL(string: "https://\(host)/cdn-cgi/trace"),
              let proxies = CFNetworkCopyProxiesForURL(url as CFURL, raw).takeRetainedValue() as? [[String: Any]],
              let first = proxies.first else {
            return .init(error: "无法读取系统代理选择。")
        }
        return systemEntry(first)
    }
    static func systemEntry(_ first: [String: Any]) -> ProbeTransport {
        guard let type = first[kCFProxyTypeKey as String] as? String else { return .init(error: "无法读取系统代理类型。") }
        if type == kCFProxyTypeNone as String { return .init() }
        // macOS Secure Web Proxy means HTTP CONNECT for HTTPS destinations,
        // not TLS to the proxy itself.
        let schemes = [kCFProxyTypeHTTP as String: "http", kCFProxyTypeHTTPS as String: "http", kCFProxyTypeSOCKS as String: "socks5h"]
        guard let scheme = schemes[type], let address = first[kCFProxyHostNameKey as String] as? String,
              let port = first[kCFProxyPortNumberKey as String] as? Int else {
            return .init(error: "当前使用 PAC／自动代理；尚未确定此域名的代理路径。")
        }
        return explicit("\(scheme)://\(address.contains(":") ? "[\(address)]" : address):\(port)")
    }
}

public enum NetworkInspector {
    public static func context(settings: PreflightSettings, target: CheckTarget, directory: String? = nil,
                               environment: [String: String]? = nil) -> String {
        composeContext(settings: settings, target: target, directory: directory, environment: environment, network: networkFingerprint())
    }
    private static func networkFingerprint() -> String {
        let proxy = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] ?? [:]
        let proxyData = (try? JSONSerialization.data(withJSONObject: proxy, options: .sortedKeys)) ?? Data()
        let network = ReadCommand.run("/usr/sbin/scutil", ["--nwi"]).text
        let dns = ReadCommand.run("/usr/sbin/scutil", ["--dns"]).text
        return fingerprintData(Data((fingerprintData(proxyData) + network + dns).utf8))
    }
    private static func composeContext(settings: PreflightSettings, target: CheckTarget, directory: String?,
                                       environment: [String: String]?, network: String) -> String {
        return fingerprintData(Data((settings.fingerprint + target.rawValue + network +
            ClientInspection.fingerprint(target: target, directory: directory) +
            ClientInspection.environmentFingerprint(environment ?? [:])).utf8))
    }
    public static func inspect(target: CheckTarget, settings: PreflightSettings,
                               directory: String? = nil, environment: [String: String]? = nil,
                               batch: NetworkProbeBatch = NetworkProbeBatch()) -> PreflightReport {
        let started = Date()
        let networkBefore = networkFingerprint()
        let contextBefore = composeContext(settings: settings, target: target, directory: directory, environment: environment, network: networkBefore)
        var checks: [NetworkCheck] = []
        do { try settings.validate(); checks.append(.init("baseline", "固定出口基准", .passed, settings.expectedIP)) }
        catch { checks.append(.init("baseline", "固定出口基准", .failed, "请先填写并确认固定出口 IP。")) }
        let client = ClientInspection.inspect(target: target, directory: directory, environment: environment)
        checks.append(contentsOf: client.checks)
        let transports = target.hosts.map { host in client.transport ?? ProbeTransport.system(host: host) }
        let transportError = transports.compactMap(\.error).first
        checks.append(.init("transport", "探测网络路径", transportError == nil ? .passed : .unknown,
                            transportError ?? Array(Set(transports.map(\.label))).sorted().joined(separator: "；")))
        if target == .vscode {
            checks.append(.init("uniform-proxy", "Code 统一代理入口", transports.allSatisfy { $0 == transports.first } ? .passed : .failed,
                                "Code 使用统一 HTTP(S)_PROXY；多个目标必须选择同一入口。"))
        }
        // Independent origin probes run in parallel, keeping a whole preflight under the 30s lease.
        let collector = ObservationCollector(); let group = DispatchGroup()
        for (host, transport) in zip(target.hosts, transports) {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                let key = networkBefore + host + transport.label + settings.fingerprint
                collector.add(batch.observation(key: key) { probe(host: host, transport: transport, settings: settings) }); group.leave()
            }
        }
        group.wait()
        let observations = collector.values().sorted { $0.host < $1.host }
        checks.append(contentsOf: observations.map(\.check))
        let serviceHost = target == .desktop ? "claude.ai" : "api.anthropic.com"
        let serviceTransport = client.transport ?? ProbeTransport.system(host: serviceHost)
        checks.append(batch.service(key: networkBefore + serviceHost + serviceTransport.label) { service(host: serviceHost, transport: serviceTransport) })
        let unchanged = contextBefore == context(settings: settings, target: target, directory: directory, environment: environment)
        checks.append(.init("unchanged", "检查期间配置稳定", unchanged ? .passed : .failed,
                            unchanged ? "网络、代理及客户端配置指纹未变。" : "检查期间网络或配置变化，请重新检查。"))
        checks.append(.init("live-route", "实际连接与分流规则", .unknown, required: false,
                            "域名探测已单独核对；未取得当前客户端的实际连接链。进程分流可能与探测不同。"))
        checks.append(contentsOf: localDiagnostics())
        checks.append(.init("identity", "位置与住宅属性", .info, required: false,
                            "仅展示目标站点返回的国家代码；纽约、ASN、住宅属性尚未独立核验。"))
        checks.append(.init("enforcement", "故障断流", .info, required: false,
                            "此版本提供启动前检查与异常提醒；不修改 PF、路由或 IPv6，不切断已运行会话。"))
        return .init(target: target, startedAt: started, completedAt: Date(), context: contextBefore,
                     checks: checks, observations: observations)
    }
    static func localDiagnostics() -> [NetworkCheck] {
        let dns = ReadCommand.run("/usr/sbin/scutil", ["--dns"])
        let resolverCount = dns.text.components(separatedBy: "resolver #").count - 1
        let nameserverCount = dns.text.components(separatedBy: "nameserver[").count - 1
        var interfaces = Set<String>(); var pointer: UnsafeMutablePointer<ifaddrs>?
        if getifaddrs(&pointer) == 0 {
            var cursor = pointer
            while let item = cursor {
                defer { cursor = item.pointee.ifa_next }
                guard let address = item.pointee.ifa_addr, Int32(address.pointee.sa_family) == AF_INET6,
                      item.pointee.ifa_flags & UInt32(IFF_UP) != 0 else { continue }
                var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(address, socklen_t(address.pointee.sa_len), &host, socklen_t(host.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let text = String(cString: host)
                    if text != "::1" && !text.hasPrefix("fe80:") { interfaces.insert(String(cString: item.pointee.ifa_name)) }
                }
            }
            freeifaddrs(pointer)
        }
        return [
            .init("dns", "DNS 配置", dns.code == 0 ? .info : .unknown, required: false,
                  "系统当前报告 \(resolverCount) 个解析配置、\(nameserverCount) 个服务器条目。代理探测由上游解析目标；这不是 DNS 泄漏审计。"),
            .init("ipv6", "本机 IPv6", .info, required: false,
                  interfaces.isEmpty ? "未发现已启用的非链路本地 IPv6 地址；未修改 IPv6。代理的远端 IPv6 行为未独立验证。" : "存在非链路本地 IPv6 接口：\(interfaces.sorted().joined(separator: "、"))。当前探测不证明所有 IPv6 流量路径。")
        ]
    }
    static func service(host: String, transport: ProbeTransport) -> NetworkCheck {
        guard transport.error == nil else { return .init("service", "HTTPS 服务响应", .unknown, "网络路径未确定。") }
        let path = host == "api.anthropic.com" ? "/v1/messages" : "/"
        let response = ReadCommand.run("/usr/bin/curl", ["-q", "--silent", "--head", "--output", "/dev/null",
            "--max-time", "6", "--connect-timeout", "3", "--proto", "=https", "--noproxy", "", "--proxy", transport.proxy ?? "",
            "--write-out", "%{http_code}", "https://\(host)\(path)"], timeout: 7,
            environment: ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory()])
        guard response.code == 0, let status = Int(response.text), (200...499).contains(status), status != 429 else {
            let status = Int(response.text).map { "HTTP \($0)" } ?? "curl \(response.code)"
            return .init("service", "HTTPS 服务响应", .failed, "服务探测未通过（\(status)）；稍后重新检查。")
        }
        return .init("service", "HTTPS 服务响应", .passed,
                     "已收到 HTTPS 响应 \(status)。\([401,403].contains(status) ? "存在登录／访问验证；" : "")仅证明网络可达，不代表账号、登录或模型可用。")
    }
    public static func probe(host: String, transport: ProbeTransport, settings: PreflightSettings) -> DomainObservation {
        probeResult(host: host, transport: transport, settings: settings) { args in
            ReadCommand.run("/usr/bin/curl", args, timeout: 9, environment: ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory()])
        }
    }
    static func probeResult(host: String, transport: ProbeTransport, settings: PreflightSettings,
                            command: ([String]) -> CommandOutput) -> DomainObservation {
        let start = Date()
        func observation(_ result: CheckResult, _ detail: String, ip: String? = nil, country: String? = nil) -> DomainObservation {
            .init(host: host, ip: ip, country: country, transport: transport.label,
                  milliseconds: Int(Date().timeIntervalSince(start) * 1000),
                  check: .init("exit:" + host, host, result, detail))
        }
        guard transport.error == nil else { return observation(.unknown, "代理路径未确定，未发起探测。") }
        guard Set(CheckTarget.allCases.flatMap(\.hosts)).contains(host) else { return observation(.failed, "目标不在固定检查列表中。") }
        let args = ["-q", "--silent", "--show-error", "--connect-timeout", "4", "--max-time", "8",
                    "--max-filesize", "16384", "--proto", "=https", "--noproxy", "", "--proxy", transport.proxy ?? "",
                    "--write-out", "\n__STATUS__%{http_code}", "https://\(host)/cdn-cgi/trace"]
        // Neither .curlrc nor inherited proxy/auth/certificate overrides participate.
        let output = command(args)
        guard output.code == 0 else {
            let reason: String
            switch output.code { case 5, 6: reason = "解析失败"; case 7: reason = "连接失败"; case 28: reason = "探测超时"; case 35, 60: reason = "TLS 校验失败"; default: reason = "网络探测失败（\(output.code)）" }
            return observation(.failed, "\(host)：\(reason)。")
        }
        guard let split = output.text.range(of: "\n__STATUS__", options: .backwards),
              let status = Int(output.text[split.upperBound...]),
              let trace = TraceResponse.parse(String(output.text[..<split.lowerBound]), status: status) else {
            return observation(.unknown, "\(host)：未取得有效的站点出口回显，可能被访问验证拦截。")
        }
        let match = settings.matches(trace.ip)
        return observation(match ? .passed : .failed,
                           match ? "目标域名探测出口与确认基准一致；\(trace.country)。" : "\(host) 出口 \(trace.ip) 与确认基准不符。",
                           ip: trace.ip, country: trace.country)
    }
}
private final class ObservationCollector: @unchecked Sendable {
    private let lock = NSLock(); private var observations: [DomainObservation] = []
    func add(_ value: DomainObservation) { lock.lock(); observations.append(value); lock.unlock() }
    func values() -> [DomainObservation] { lock.lock(); defer { lock.unlock() }; return observations }
}
