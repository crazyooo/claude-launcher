import Foundation

public struct SelectedProxyConfiguration: Equatable, Sendable {
    public enum Kind: String, Sendable { case http, socks5 }
    public let id: UUID
    public let revision: UUID
    public let credentialReference: UUID?
    public let kind: Kind
    public let host: String
    public let port: Int
    public let expectedIP: String
    public init(id: UUID, revision: UUID, credentialReference: UUID?, kind: Kind,
                host: String, port: Int, expectedIP: String) {
        self.id = id; self.revision = revision; self.credentialReference = credentialReference
        self.kind = kind; self.host = host; self.port = port; self.expectedIP = expectedIP
    }
}

/// Only passed to a bounded worker's stdin; never part of a report, argv, file or environment.
public struct SelectedProxySecret: Sendable {
    public let username: String
    public let password: String
    public init(username: String, password: String) { self.username = username; self.password = password }
}
public struct SelectedProxyNetwork: Equatable, Sendable {
    public let fingerprint: String
    public let readable: Bool
    public init(fingerprint: String, readable: Bool) { self.fingerprint = fingerprint; self.readable = readable }
    public static func current() -> Self {
        let value = EnvironmentInspector.networkSnapshot()
        return .init(fingerprint: value.fingerprint, readable: value.readable)
    }
}
public struct SelectedProxyObservation: Sendable {
    public let host: String
    public let code: String
    public let ip: String?
    public let httpStatus: Int?
    public let proxyStatus: Int?
    public let settled: Bool
    /// `systemRoute` is the unchanged default probe. `physicalInterface` is an explicit comparison.
    public let scope: String
    public init(host: String, code: String, ip: String? = nil, httpStatus: Int? = nil,
                proxyStatus: Int? = nil, settled: Bool = true, scope: String = "systemRoute") {
        self.host = host; self.code = code; self.ip = ip; self.httpStatus = httpStatus
        self.proxyStatus = proxyStatus; self.settled = settled
        self.scope = scope == "physicalInterface" ? "physicalInterface" : "systemRoute"
    }
    public var result: CheckResult {
        if code == "exit_match", scope == "systemRoute" { return .passed }
        return ["proxy_auth_required", "proxy_request_rejected", "socks_negotiation_failed",
                "socks_method_rejected", "socks_auth_rejected", "socks_connect_rules_rejected", "socks_connect_failed", "dns_failed",
                "connect_failed", "probe_timeout", "tls_failed", "transport_failed", "exit_mismatch",
                "configuration_invalid", "credential_invalid", "interface_bind_unconfirmed"].contains(code) ? .failed : .unknown
    }
    public var detail: String {
        switch code {
        case "exit_match": return "此站点报告的出口与固定 IPv4 基准一致。"
        case "exit_mismatch": return "站点报告的出口与基准不一致；请核对 Webshare 入口和分配的静态出口。"
        case "proxy_auth_required": return "代理返回 407；请检查此线路的认证信息或 IP 白名单。"
        case "proxy_request_rejected": return "代理拒绝 CONNECT 请求（400）；请核对入口协议和端口。"
        case "socks_negotiation_failed": return "SOCKS 协商失败；可能涉及认证、白名单、目标拒绝或协议不符，不能仅据此判定密码错误。"
        case "socks_method_rejected": return "SOCKS 代理未接受本次认证方式，尚未进入目标连接阶段；请核对服务商的认证模式和访问要求。"
        case "socks_auth_rejected": return "SOCKS 代理拒绝本次用户名/密码认证；请在服务商后台核对凭据及权限，不能仅据此认定密码错误。"
        case "socks_connect_rules_rejected": return "代理报告按规则拒绝为该目标建立连接（SOCKS5 返回 2）；请核对服务商的目标访问和账户权限。"
        case "socks_connect_failed": return "已连接到 SOCKS 代理，但代理报告目标连接失败（SOCKS5 返回 1）；请核对服务商线路状态和目标访问限制。"
        case "tls_failed": return "TLS 握手或证书校验失败；请核对系统时间、线路和目标证书。未跳过证书验证。"
        case "dns_failed": return "未能解析代理或目标地址；SOCKS5 本次由代理解析目标域名。"
        case "connect_failed": return "无法连接代理入口；请核对地址、端口及网络。"
        case "probe_timeout": return "本轮检测超时，请检查线路后重新检测。"
        case "target_access_denied": return "目标站点返回 401/403，未取得出口；这不是代理认证结果，也不证明账号可用。"
        case "service_rate_limited": return "目标站点限流，请稍后手动重新检测。"
        case "baseline_missing": return "已取得站点报告的出口，但尚无可用的固定 IPv4 基准。"
        case "redirect_not_followed": return "目标返回重定向；未跟随，未取得出口依据。"
        case "credential_invalid": return "认证信息不符合协议限制：用户名不能含冒号；SOCKS5 用户名和密码各最多 255 个 UTF-8 字节。"
        case "configuration_invalid": return "线路配置无效，请检查协议、服务器地址、端口和出口基准。"
        case "process_unsettled": return "检测子进程退出尚未确认；停止重复检测，重新打开应用前请核对残留进程。"
        case "cancelled": return "本轮检测已取消，结果不作为当前依据。"
        case "proxy_path_unverified": return "代理协商元数据与配置协议不一致，本轮未验证出口。"
        case "interface_bind_unconfirmed": return "物理接口绑定未确认，已停止这次连接，没有改走未绑定的系统路由。"
        case "unavailable": return "物理接口对照没有建立本次转发，没有改走未绑定的系统路由。"
        case "physical_path_requires_ipv4": return "物理接口对照只接受 IPv4 数字入口，避免经由隧道解析域名。这次没有连接。"
        case "physical_exit_match": return "站点报告的出口与基准一致。这只是所选物理接口上的一次显式代理请求，不是 Desktop/CLI 通过，也不是实际分流验收。"
        default: return "尚未取得完整出口回应；目标可能不支持此检查，请保留为未测全。"
        }
    }
}
public final class SelectedProxyCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var requested = false
    public init() {}
    public func cancel() { lock.lock(); requested = true; lock.unlock() }
    public var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return requested }
}

public enum SelectedProxyDiagnostic {
    public static let hosts = ["claude.ai", "api.anthropic.com", "platform.claude.com"]
    struct Invocation { let arguments: [String]; let input: Data; let timeout: TimeInterval }
    enum Failure: Error { case invalidConfiguration, invalidCredential }

    private static func loopbackProxy(_ value: String, kind: SelectedProxyConfiguration.Kind) -> Bool {
        let prefix = (kind == .http ? "http://" : "socks5h://") + "127.0.0.1:"
        guard value.hasPrefix(prefix), let port = Int(value.dropFirst(prefix.count)),
              value == prefix + String(port), (1...65535).contains(port) else { return false }
        return true
    }
    private static func quoted(_ value: String) throws -> String {
        guard !value.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw Failure.invalidCredential
        }
        return "\"" + value.replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }
    static func invocation(_ config: SelectedProxyConfiguration, secret: SelectedProxySecret?,
                           host: String, timeout: TimeInterval, localProxy: String? = nil) throws -> Invocation {
        guard hosts.contains(host), (1...65535).contains(config.port), timeout.isFinite, timeout > 0,
              config.expectedIP.isEmpty || normalizedIPv4(config.expectedIP) != nil,
              !config.host.isEmpty, !config.host.contains(where: { "[]%/@?#".contains($0) }) else {
            throw Failure.invalidConfiguration
        }
        let address = config.host.contains(":") ? "[" + config.host + "]" : config.host
        let direct = (config.kind == .http ? "http://" : "socks5h://") + address + ":" + String(config.port)
        let proxy = localProxy ?? direct
        guard localProxy == nil || loopbackProxy(proxy, kind: config.kind),
              EnvironmentRoutes.validatedProxy(proxy).proxy == proxy,
              (config.credentialReference != nil) == (secret != nil) else { throw Failure.invalidConfiguration }
        var envelope = ""
        if let secret {
            let passwordLimit = config.kind == .socks5 ? 255 : 4096
            let usernameLimit = config.kind == .socks5 ? 255 : 1024
            guard !secret.username.isEmpty, !secret.password.isEmpty, !secret.username.contains(":"),
                  secret.username.utf8.count <= usernameLimit, secret.password.utf8.count <= passwordLimit else {
                throw Failure.invalidCredential
            }
            envelope = "proxy-user = " + (try quoted(secret.username + ":" + secret.password)) + "\n"
        }
        let input = Data(envelope.utf8)
        guard input.count <= 16_384 else { throw Failure.invalidCredential }
        var args = ["-q", "--config", "-", "--silent", "--proxy", proxy, "--noproxy", "",
                    "--proto", "=https", "--proto-redir", "=https", "--max-redirs", "0",
                    "--connect-timeout", String(min(4, timeout)), "--max-time", String(timeout),
                    "--max-filesize", "16000", "--write-out",
                    "\n__ROUTER_DIAG_ERROR__%{errormsg}\n__ROUTER_DIAG__%{http_code}:%{http_connect}"]
        if config.kind == .http { args.append("--proxy-basic") }
        else if secret != nil { args.append("--socks5-basic") }
        args.append("https://" + host + "/cdn-cgi/trace")
        return .init(arguments: args, input: input, timeout: timeout)
    }

    static func parse(_ response: BoundedProcess.Diagnostic, host: String,
                      config: SelectedProxyConfiguration) -> SelectedProxyObservation {
        func outcome(_ code: String, ip: String? = nil, http: Int? = nil, proxy: Int? = nil) -> SelectedProxyObservation {
            .init(host: host, code: code, ip: ip, httpStatus: http, proxyStatus: proxy, settled: response.settled)
        }
        guard response.settled else { return outcome("process_unsettled") }
        if response.cancelled { return outcome("cancelled") }
        if response.timedOut { return outcome("probe_timeout") }
        var body: String?, http: Int?, proxy: Int?
        var errorWasEmpty = false
        var socksFailure: String?
        if response.complete, response.data.count <= 16_384,
           let text = String(data: response.data, encoding: .utf8),
           let mark = text.range(of: "\n__ROUTER_DIAG__", options: .backwards),
           let errorMark = text[..<mark.lowerBound].range(of: "\n__ROUTER_DIAG_ERROR__", options: .backwards) {
            let values = text[mark.upperBound...].split(separator: ":", omittingEmptySubsequences: false)
            if values.count == 2, values.allSatisfy({ $0.count == 3 && $0.utf8.allSatisfy { (48...57).contains($0) } }),
               let h = Int(values[0]), let p = Int(values[1]), h == 0 || (100...599).contains(h),
               p == 0 || (100...599).contains(p) {
                let payload = text[..<errorMark.lowerBound]
                // Reserved metadata cannot also occur in the response body.
                if !payload.contains("__ROUTER_DIAG__"), !payload.contains("__ROUTER_DIAG_ERROR__") {
                    body = String(payload); http = h; proxy = p
                    let message = text[errorMark.upperBound..<mark.lowerBound]
                    errorWasEmpty = message.isEmpty
                    // Project only verified local curl templates. Raw error text never leaves this scope.
                    if payload.isEmpty, config.kind == .socks5, response.exitCode == 97,
                       h == 0, p == 0, hosts.contains(host) {
                        if message == "No authentication method was acceptable." {
                            socksFailure = "socks_method_rejected"
                        } else if message == "User was rejected by the SOCKS5 server (1 1)." {
                            socksFailure = "socks_auth_rejected"
                        } else if message == "Can't complete SOCKS5 connection to \(host). (2)" {
                            socksFailure = "socks_connect_rules_rejected"
                        } else if message == "Can't complete SOCKS5 connection to \(host). (1)" {
                            socksFailure = "socks_connect_failed"
                        }
                    }
                }
            }
        }
        if config.kind == .http, proxy == 407 { return outcome("proxy_auth_required", http: http, proxy: proxy) }
        if config.kind == .http, proxy == 400 { return outcome("proxy_request_rejected", http: http, proxy: proxy) }
        switch response.exitCode {
        case 0: break
        case 5, 6: return outcome("dns_failed")
        case 7: return outcome("connect_failed")
        case 28: return outcome("probe_timeout")
        case 35, 51, 58, 60, 77, 80, 82, 83, 90, 91: return outcome("tls_failed")
        case 97: return outcome(socksFailure ?? "socks_negotiation_failed")
        case .none: return outcome("process_failed")
        default: return outcome("transport_failed", http: http, proxy: proxy)
        }
        guard response.complete, errorWasEmpty, let body, let http else { return outcome("response_incomplete") }
        let expectedProxyStatus = config.kind == .http ? 200 : 0
        guard proxy == expectedProxyStatus else {
            return outcome("proxy_path_unverified", http: http, proxy: proxy)
        }
        if (300...399).contains(http) { return outcome("redirect_not_followed", http: http) }
        if http == 401 || http == 403 { return outcome("target_access_denied", http: http) }
        if http == 429 { return outcome("service_rate_limited", http: http) }
        guard let trace = TraceResponse.parse(body, status: http) else { return outcome("exit_unavailable", http: http) }
        guard let expected = normalizedIPv4(config.expectedIP) else {
            return outcome("baseline_missing", ip: trace.ip, http: http)
        }
        return outcome(normalizedIPv4(trace.ip) == expected ? "exit_match" : "exit_mismatch", ip: trace.ip, http: http)
    }

    public static func inspect(_ config: SelectedProxyConfiguration, secret: SelectedProxySecret?,
                               cancellation: SelectedProxyCancellation, until deadline: TimeInterval) async -> [SelectedProxyObservation] {
        await inspect(config, secret: secret, cancellation: cancellation, until: deadline,
                      run: { call, cancelled in
            BoundedProcess.diagnostic(arguments: call.arguments, timeout: call.timeout,
                                      input: call.input, cancelled: cancelled)
        }, uptime: { ProcessInfo.processInfo.systemUptime })
    }
    static func inspect(_ config: SelectedProxyConfiguration, secret: SelectedProxySecret?,
                        cancellation: SelectedProxyCancellation, until deadline: TimeInterval,
                        run: @escaping @Sendable (Invocation, () -> Bool) -> BoundedProcess.Diagnostic,
                        uptime: @escaping @Sendable () -> TimeInterval) async -> [SelectedProxyObservation] {
        let worker = Task.detached { () -> [SelectedProxyObservation] in
            let limit = min(deadline, uptime() + 24)
            var observations: [SelectedProxyObservation] = []
            for host in hosts {
                if cancellation.cancelled { break }
                let remaining = min(8, limit - uptime())
                guard limit.isFinite, remaining > 0 else { break }
                do {
                    let call = try invocation(config, secret: secret, host: host, timeout: remaining)
                    let response = run(call, { cancellation.cancelled })
                    guard uptime() < limit else {
                        observations.append(.init(host: host, code: "probe_timeout", settled: response.settled)); break
                    }
                    observations.append(parse(response, host: host, config: config))
                    if !response.settled || response.cancelled { break }
                } catch {
                    observations.append(.init(host: host, code: error as? Failure == .invalidCredential
                        ? "credential_invalid" : "configuration_invalid")); break
                }
            }
            return observations
        }
        return await withTaskCancellationHandler(operation: { await worker.value }, onCancel: { cancellation.cancel() })
    }

    /// Explicit physical-interface exit probe. A bind failure never becomes a system-route success.
    static func project(_ relay: String, _ parsed: SelectedProxyObservation) -> SelectedProxyObservation {
        if relay != "ok" {
            let code = ["interface_bind_unconfirmed", "connect_failed", "unavailable"].contains(relay) ? relay : "proxy_path_unverified"
            return .init(host: parsed.host, code: code, settled: parsed.settled, scope: "physicalInterface")
        }
        let code = parsed.code == "exit_match" ? "physical_exit_match" : parsed.code
        return .init(host: parsed.host, code: code, ip: parsed.ip, httpStatus: parsed.httpStatus,
                     proxyStatus: parsed.proxyStatus, settled: parsed.settled, scope: "physicalInterface")
    }
    public static func inspectBound(_ config: SelectedProxyConfiguration, secret: SelectedProxySecret?,
                                    interface name: String, index: UInt32, cancellation: SelectedProxyCancellation,
                                    until deadline: TimeInterval) async -> [SelectedProxyObservation] {
        await inspectBound(config, secret: secret, interface: name, index: index, cancellation: cancellation,
                           until: deadline, run: { call, cancelled in
            BoundedProcess.diagnostic(arguments: call.arguments, timeout: call.timeout, input: call.input, cancelled: cancelled)
        }, uptime: { ProcessInfo.processInfo.systemUptime })
    }
    static func inspectBound(_ config: SelectedProxyConfiguration, secret: SelectedProxySecret?,
                             interface name: String, index: UInt32, cancellation: SelectedProxyCancellation,
                             until deadline: TimeInterval,
                             run: @escaping @Sendable (Invocation, () -> Bool) -> BoundedProcess.Diagnostic,
                             uptime: @escaping @Sendable () -> TimeInterval) async -> [SelectedProxyObservation] {
        let worker = Task.detached { () -> [SelectedProxyObservation] in
            guard SelectedProxyPath.currentIndex(name) == index else {
                return hosts.map { .init(host: $0, code: "interface_bind_unconfirmed", scope: "physicalInterface") }
            }
            guard normalizedIPv4(config.host) != nil else {
                return [.init(host: hosts[0], code: "physical_path_requires_ipv4", scope: "physicalInterface")]
            }
            let limit = min(deadline, uptime() + 24)
            var observations: [SelectedProxyObservation] = []
            for host in hosts {
                if cancellation.cancelled { break }
                let remaining = min(8, limit - uptime())
                guard limit.isFinite, remaining > 0 else { break }
                guard SelectedProxyPath.currentIndex(name) == index else {
                    observations.append(.init(host: host, code: "interface_bind_unconfirmed", scope: "physicalInterface")); break
                }
                var response = BoundedProcess.Diagnostic(data: Data(), exitCode: nil, complete: false, settled: true, cancelled: false, timedOut: false)
                var failure: String?
                let relay = SelectedProxyPath.forward(index: index, name: name, proxyHost: config.host, proxyPort: config.port, timeout: remaining) { port in
                    let scheme = config.kind == .http ? "http://127.0.0.1:" : "socks5h://127.0.0.1:"
                    do {
                        let call = try invocation(config, secret: secret, host: host, timeout: remaining, localProxy: scheme + String(port))
                        if call.arguments.contains("--interface") { failure = "configuration_invalid"; return }
                        response = run(call, { cancellation.cancelled })
                    } catch {
                        failure = error as? Failure == .invalidCredential ? "credential_invalid" : "configuration_invalid"
                    }
                }
                let parsed = failure.map { SelectedProxyObservation(host: host, code: $0) } ?? parse(response, host: host, config: config)
                let projected = project(relay, parsed)
                guard uptime() < limit else {
                    observations.append(.init(host: host, code: "probe_timeout", settled: projected.settled, scope: "physicalInterface")); break
                }
                observations.append(projected)
                if !projected.settled || response.cancelled { break }
            }
            return observations
        }
        return await withTaskCancellationHandler(operation: { await worker.value }, onCancel: { cancellation.cancel() })
    }
}
