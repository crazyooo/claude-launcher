import Foundation
import CFNetwork

struct EnvironmentNetworkSnapshot {
    let fingerprint: String
    let readable: Bool
}

struct EnvironmentInspectionSource {
    var network: () -> EnvironmentNetworkSnapshot
    var systemRoute: (String) -> ProbeTransport
    var files: (String) -> [URL]
    var readConfiguration: (URL) throws -> [String: Any]
    var command: ([String]) -> CommandOutput
    var supplemental: () -> [NetworkCheck]
    static var live: Self {
        .init(network: EnvironmentInspector.networkSnapshot, systemRoute: ProbeTransport.system,
              files: EnvironmentRoutes.configurationURLs, readConfiguration: EnvironmentRoutes.readConfiguration,
              command: { ReadCommand.run("/usr/bin/curl", $0, timeout: 9,
                                         environment: ["PATH": "/usr/bin:/bin", "HOME": NSHomeDirectory()]) },
              supplemental: NetworkInspector.localDiagnostics)
    }
}

public enum EnvironmentInspector {
    public static func networkFingerprint() -> String { networkSnapshot().fingerprint }
    public static func configurationFingerprint(settings: EnvironmentSettings) -> String {
        // Notification preferences do not alter network evidence.
        fingerprintData(Data((settings.expectedIP + "\n" + settings.diagnosticProxy).utf8))
    }
    static func networkSnapshot() -> EnvironmentNetworkSnapshot {
        let proxy = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any]
        let bytes = proxy.flatMap { try? JSONSerialization.data(withJSONObject: $0, options: .sortedKeys) }
        let network = ReadCommand.run("/usr/sbin/scutil", ["--nwi"])
        let dns = ReadCommand.run("/usr/sbin/scutil", ["--dns"])
        return .init(fingerprint: fingerprintData(Data((fingerprintData(bytes ?? Data()) + String(network.code) + network.text + String(dns.code) + dns.text).utf8)),
                     readable: bytes != nil && network.code == 0 && dns.code == 0)
    }

    public static func inspect(target: EnvironmentTarget, settings: EnvironmentSettings,
                               directory: String? = nil, environment: [String: String]? = nil) -> EnvironmentReport {
        inspect(target: target, settings: settings, directory: directory, environment: environment, source: .live)
    }

    static func inspect(target: EnvironmentTarget, settings: EnvironmentSettings,
                        directory: String? = nil, environment: [String: String]? = nil,
                        source: EnvironmentInspectionSource) -> EnvironmentReport {
        let started = Date(), before = source.network()
        let configuration = configurationFingerprint(settings: settings)
        func cliContext() -> EnvironmentCLIContext {
            EnvironmentRoutes.cli(directory: directory, environment: environment,
                                  files: directory.map(source.files) ?? [], read: source.readConfiguration)
        }
        let cli = target == .cli ? cliContext() : nil
        func selectedRoutes() -> [String: EnvironmentRoute] {
            if let cli { return cli.routes }
            return Dictionary(uniqueKeysWithValues: target.hosts.map { host in
                if target == .diagnostic {
                    if settings.diagnosticProxy.isEmpty { return (host, .unresolved("diagnostic_proxy_missing")) }
                    let transport = EnvironmentRoutes.validatedProxy(settings.diagnosticProxy)
                    return (host, transport.error == nil ? .init(transport: transport, source: .explicitDiagnosticProxy, code: "route_ok") : .unresolved("proxy_invalid"))
                }
                let chosen = source.systemRoute(host)
                let transport = chosen.proxy.map(EnvironmentRoutes.validatedProxy) ?? chosen
                return (host, transport.error == nil ? .init(transport: transport, source: transport.proxy == nil ? .systemNetworkRoute : .systemProxySelection, code: "route_ok") : .unresolved("route_unresolved"))
            })
        }
        let routes = selectedRoutes()
        func routeDigest(_ values: [String: EnvironmentRoute]) -> String {
            fingerprintData(Data(values.keys.sorted().map { $0 + ":" + values[$0]!.transport.label + ":" + values[$0]!.source.rawValue }.joined(separator: "|").utf8))
        }
        let initialRoutes = routeDigest(routes)
        let context = fingerprintData(Data((configuration + before.fingerprint + target.rawValue + (cli?.fingerprint ?? initialRoutes)).utf8))
        var checks: [EnvironmentCheck] = []
        let configCode = cli?.code ?? "configuration_ok"
        checks.append(.init("configuration", "检测配置", configCode == "configuration_ok" ? .passed : .unknown, code: configCode,
                            configCode == "configuration_ok" ? "已确定本轮检测的配置来源；未修改客户端配置。" : EnvironmentGuidance.advice(for: configCode)))
        let baseline = normalizedIPv4(settings.expectedIP)
        checks.append(.init("baseline", "固定出口基准", settings.expectedIP.isEmpty ? .unknown : (baseline == nil ? .failed : .passed),
                            code: settings.expectedIP.isEmpty ? "baseline_missing" : (baseline == nil ? "baseline_invalid" : "baseline_ok"),
                            baseline == nil ? "尚无有效的固定出口基准。" : "使用预先确认的固定 IPv4 出口；不会自动接受新地址。"))
        checks.append(.init("network-configuration", "系统网络配置", before.readable ? .passed : .unknown,
                            code: before.readable ? "network_configuration_ok" : "configuration_unreadable",
                            before.readable ? "已读取当前系统网络和 DNS 配置。" : "未完整读取系统网络配置。"))
        for host in target.hosts {
            let route = routes[host]!
            checks.append(.init("route:" + host, host + " · 检测路径", route.transport.error == nil ? .passed : .unknown,
                                code: route.code, route.transport.error == nil ? route.source.title : EnvironmentGuidance.advice(for: route.code)))
        }
        let collector = EnvironmentProbeCollector(), group = DispatchGroup()
        for host in target.hosts {
            group.enter()
            DispatchQueue.global(qos: .utility).async {
                collector.append(probe(host: host, route: routes[host]!, baseline: baseline, command: source.command))
                group.leave()
            }
        }
        group.wait()
        let probes = collector.values().sorted { $0.observation.host < $1.observation.host }
        checks += probes.map(\.check)
        checks += service(host: target.serviceHost, route: routes[target.serviceHost]!, command: source.command)
        let after = source.network()
        let cliAfter = target == .cli ? cliContext() : nil
        let contextReadable = before.readable && after.readable
        let stable = before.fingerprint == after.fingerprint &&
            (cli?.fingerprint == cliAfter?.fingerprint) && initialRoutes == routeDigest(selectedRoutes())
        let stabilityCode = !contextReadable ? "configuration_unreadable" : (stable ? "context_stable" : "context_changed")
        checks.append(.init("context-stable", "检测期间环境稳定", !contextReadable ? .unknown : (stable ? .passed : .failed),
                            code: stabilityCode,
                            contextReadable && stable ? "检测期间网络与相关配置指纹未变。" : EnvironmentGuidance.advice(for: stabilityCode)))
        checks += source.supplemental().map { .init("supplemental:" + $0.id, $0.title, $0.result, required: false, code: "supplemental_information", $0.detail) }
        checks.append(.init("scope", "检测范围", .info, required: false, code: "scope_information",
                            "仅检查本轮 HTTPS 请求；DNS 和 IPv6 信息不等于泄漏审计。域名规则由现有代理客户端执行，未验证 Claude 实际流量或账号可用性。"))
        return .init(target: target, startedAt: started, completedAt: Date(), networkFingerprint: before.fingerprint,
                     configurationFingerprint: configuration, context: context, checks: checks, observations: probes.map(\.observation))
    }

    /// curl's own error text from the write-out tail; empty when the probe never
    /// reached write-out (killed process) or the caller passed a canned response.
    static func curlError(_ output: CommandOutput) -> String {
        guard let marker = output.text.range(of: "\n__CURL__", options: .backwards) else { return "" }
        let tail = output.text[marker.upperBound...]
        guard let split = tail.firstIndex(of: "|") else { return "" }
        return String(tail[tail.index(after: split)...]).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Transport attribution for a failed probe. Exit codes stay the fallback so
    /// persisted exports and canned sources keep working; curl's error text only
    /// splits classes that one code alone cannot (reset vs timeout vs certificate).
    static func transportOutcome(_ output: CommandOutput) -> String {
        let hint = curlError(output).lowercased()
        if hint.contains("certificate") { return "tls_certificate" }
        switch output.code {
        case 5, 6: return "dns_failed"
        case 7: return "connect_failed"
        case 28: return hint.contains("ssl") || hint.contains("tls") ? "tls_timeout" : "probe_timeout"
        case 35, 51, 58, 60, 77, 80, 82, 83, 90, 91:
            if hint.contains("syscall") || hint.contains("reset") || hint.contains("closed") { return "tls_reset" }
            if hint.contains("timeout") { return "tls_timeout" }
            return "tls_failed"
        default: return "transport_failed"
        }
    }

    /// One retry for failures that look like line jitter rather than stable
    /// blocking: a stalled or reset handshake often succeeds immediately after.
    /// Deterministic classes (certificate, rate limit, evidence shape) do not retry.
    static func transient(_ code: String) -> Bool {
        switch code {
        case "tls_reset", "tls_timeout", "probe_timeout", "connect_failed", "dns_failed", "transport_failed":
            return true
        default: return false
        }
    }

    private static func arguments(host: String, route: EnvironmentRoute, service: Bool) -> [String] {
        let path = service ? (host == "api.anthropic.com" ? "/v1/messages" : "/") : "/cdn-cgi/trace"
        var args = ["-q", "--silent", "--show-error", "--connect-timeout", "4", "--max-time", "8",
                    "--max-filesize", "16384", "--proto", "=https", "--noproxy", "", "--proxy", route.transport.proxy ?? ""]
        if service { args += ["--head", "--output", "/dev/null"] }
        return args + ["--write-out", "\n__STATUS__%{http_code}\n__CURL__%{exitcode}|%{errormsg}",
                       "https://" + host + path]
    }

    /// HTTP status from a write-out tail; plain responses without the marker
    /// (canned sources) still parse as before.
    private static func responseStatus(_ text: String) -> Int? {
        if let marker = text.range(of: "\n__STATUS__", options: .backwards) {
            return Int(text[marker.upperBound...].prefix(while: { $0.isNumber }))
        }
        return Int(text.trimmingCharacters(in: .whitespacesAndNewlines))
    }

    private static func probe(host: String, route: EnvironmentRoute, baseline: String?, command: ([String]) -> CommandOutput) -> EnvironmentProbe {
        var start = Date()
        func result(_ status: CheckResult, _ code: String, ip: String? = nil, country: String? = nil, detail: String? = nil) -> EnvironmentProbe {
            .init(check: .init("exit:" + host, host + " · 出口核对", status, code: code,
                               detail ?? (code == "exit_match" ? "站点返回的出口与确认基准一致。" : EnvironmentGuidance.advice(for: code))),
                  observation: .init(host: host, ip: ip, country: country, transport: route.transport.proxy ?? route.source.title,
                                     source: route.source, milliseconds: min(60_000, max(0, Int(Date().timeIntervalSince(start) * 1000)))))
        }
        guard route.transport.error == nil else { return result(.unknown, route.code) }
        var output = command(arguments(host: host, route: route, service: false))
        if output.code != 0, transient(transportOutcome(output)) {
            start = Date()
            output = command(arguments(host: host, route: route, service: false))
        }
        guard output.code == 0 else {
            let code = transportOutcome(output)
            let error = curlError(output)
            let advice = EnvironmentGuidance.advice(for: code)
            return result(.failed, code, detail: error.isEmpty ? advice : advice + "（curl：\(error.prefix(200))）")
        }
        guard output.text.utf8.count <= 16432,
              let split = output.text.range(of: "\n__STATUS__", options: .backwards),
              let status = Int(output.text[split.upperBound...].prefix(while: { $0.isNumber })) else { return result(.unknown, "exit_unavailable") }
        if status == 429 { return result(.failed, "service_rate_limited") }
        if (500...599).contains(status) { return result(.failed, "service_unavailable") }
        guard let trace = TraceResponse.parse(String(output.text[..<split.lowerBound]), status: status) else {
            return result(.unknown, "exit_unavailable")
        }
        guard let baseline else { return result(.unknown, "baseline_missing", ip: trace.ip, country: trace.country) }
        let match = normalizedIPv4(trace.ip) == baseline
        return result(match ? .passed : .failed, match ? "exit_match" : "exit_mismatch", ip: trace.ip, country: trace.country)
    }

    private static func service(host: String, route: EnvironmentRoute, command: ([String]) -> CommandOutput) -> [EnvironmentCheck] {
        func network(_ result: CheckResult, _ code: String, _ detail: String) -> EnvironmentCheck {
            .init("network:" + host, "HTTPS 网络连通", result, code: code, detail)
        }
        guard route.transport.error == nil else { return [network(.unknown, route.code, "路径未确认，未发送服务请求。")] }
        var output = command(arguments(host: host, route: route, service: true))
        if output.code != 0, transient(transportOutcome(output)) {
            output = command(arguments(host: host, route: route, service: true))
        }
        guard output.code == 0 else {
            let code = transportOutcome(output)
            return [network(.failed, code, EnvironmentGuidance.advice(for: code))]
        }
        guard let status = responseStatus(output.text), (200...599).contains(status) else {
            return [network(.unknown, "service_access_unconfirmed", "未取得可识别的 HTTPS 服务响应。")]
        }
        var result = [network(.passed, "network_ok", "收到通过 TLS 校验的 HTTPS 响应 HTTP \(status)；这不证明账号或模型可用。")]
        if status == 429 || (500...599).contains(status) {
            let code = status == 429 ? "service_rate_limited" : "service_unavailable"
            result.append(.init("service:" + host, "服务响应异常", .failed, code: code, EnvironmentGuidance.advice(for: code)))
        } else {
            result.append(.init("business:" + host, "业务访问未确认", .unknown, required: false, code: "service_access_unconfirmed",
                                "本工具没有登录或发送对话；HTTP \(status) 不能证明账号、模型或流式回复可用。"))
        }
        return result
    }
}

private struct EnvironmentProbe { let check: EnvironmentCheck; let observation: EnvironmentObservation }
private final class EnvironmentProbeCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var probes: [EnvironmentProbe] = []
    func append(_ value: EnvironmentProbe) { lock.lock(); defer { lock.unlock() }; probes.append(value) }
    func values() -> [EnvironmentProbe] { lock.lock(); defer { lock.unlock() }; return probes }
}
