import Foundation
import SwiftUI
import LauncherCore

/// One-screen product verdict after proxy probe + local Claude path detect.
enum ProductVerdictKind: String {
    case ready = "可用"
    case degraded = "线路受限"
    case attention = "异常"
    case mismatch = "代理声明不一致"
    case unknown = "未测全"
    case idle = "尚未检测"

    var symbol: String {
        switch self {
        case .ready: return "checkmark.circle.fill"
        case .degraded: return "exclamationmark.triangle.fill"
        case .attention, .mismatch: return "exclamationmark.circle.fill"
        case .unknown, .idle: return "questionmark.circle"
        }
    }
}

struct ProductProxyProbe: Equatable {
    let endpoint: String
    let listening: Bool
    let detail: String
}

/// Structured background-detect payload shown on the first screen.
struct ProductHostSample: Equatable, Identifiable {
    var id: String { "\(path)|\(host)" }
    let path: String
    let host: String
    let ip: String?
    let country: String?
    let milliseconds: Int
    let source: String
    /// Outcome code of this host's exit probe (`exit_match`, `tls_reset`, …).
    let exitCode: String

    var reachable: Bool { exitCode == "exit_match" || exitCode == "exit_mismatch" }
    var blocked: Bool { EnvironmentProbeFailure.isTransport(exitCode) }

    enum Tone { case good, warn, bad, muted }

    var statusLabel: String {
        if exitCode == "exit_match" { return "可访问" }
        return EnvironmentProbeFailure.shortLabel(for: exitCode) ?? "未确认"
    }

    var statusTone: Tone {
        switch exitCode {
        case "exit_match": return .good
        case "exit_mismatch", "service_rate_limited", "service_unavailable": return .warn
        case let code where EnvironmentProbeFailure.isTransport(code): return .bad
        default: return .muted
        }
    }
}

struct ProductDetectIssue: Equatable, Identifiable {
    var id: String { "\(target)|\(code)|\(title)" }
    let target: String
    let title: String
    let code: String
    let detail: String
}

struct ProductDetectData: Equatable {
    let collectedAt: Date
    let egressIPs: [String]
    let hosts: [ProductHostSample]
    let issues: [ProductDetectIssue]
    let proxy: ProductProxyProbe

    var summaryLine: String {
        let reachable = hosts.filter(\.reachable).count
        let blocked = hosts.filter(\.blocked).count
        var parts = ["采样 \(hosts.count) 站：可访问 \(reachable)"]
        if blocked > 0 { parts.append("线路不可达 \(blocked)") }
        parts.append(egressIPs.isEmpty ? "未采到出口 IP" : "出口 IP：" + egressIPs.joined(separator: " · "))
        return parts.joined(separator: " · ")
    }

    /// Hosts the current line cannot reach, deduplicated across paths.
    var blockedHosts: [String] {
        Array(Set(hosts.filter(\.blocked).map(\.host))).sorted()
    }

    var hasExitMismatch: Bool { hosts.contains { $0.exitCode == "exit_mismatch" } }
}

struct ProductVerdict: Equatable {
    let kind: ProductVerdictKind
    let headline: String
    let detail: String
    let nextStep: String
    let proxy: ProductProxyProbe?
    let desktop: EnvironmentRecommendation
    let cli: EnvironmentRecommendation
    let diagnostic: EnvironmentRecommendation
    let browserOpened: Bool
    let data: ProductDetectData?
}

@MainActor
final class ProductDetectSession: ObservableObject {
    @Published private(set) var busy = false
    @Published private(set) var verdict = ProductVerdict(
        kind: .idle,
        headline: "尚未一键检测",
        detail: "先拨「已开代理」，再点一键检测。检测在应用内后台完成，结果回填本页。",
        nextStep: "确认代理状态后开始检测。",
        proxy: nil,
        desktop: .unknown,
        cli: .unknown,
        diagnostic: .unknown,
        browserOpened: false,
        data: nil
    )

    /// Run local detect in-process; results land in `verdict.data`. Browser is opt-in.
    func run(model: EnvironmentModel, proxyAlreadyOn: Bool, openBrowser: Bool = false) {
        guard !busy, !model.busy else { return }
        busy = true
        let settings = model.settings
        Task {
            let proxy = Self.probeProxy(settings.diagnosticProxy)
            model.detect(manual: true)
            while model.busy {
                try? await Task.sleep(nanoseconds: 50_000_000)
            }
            if openBrowser {
                ProductDetectActions.openPrimaryBrowserSources()
            }
            ingest(model: model, proxyAlreadyOn: proxyAlreadyOn, proxy: proxy, browserOpened: openBrowser)
            busy = false
        }
    }

    /// Pull the latest EnvironmentModel reports into the product verdict (no new network).
    func ingest(
        model: EnvironmentModel,
        proxyAlreadyOn: Bool,
        proxy: ProductProxyProbe? = nil,
        browserOpened: Bool = false
    ) {
        let resolvedProxy = proxy ?? Self.probeProxy(model.settings.diagnosticProxy)
        let data = Self.extractData(
            reports: model.reports,
            proxy: resolvedProxy,
            at: model.now
        )
        verdict = Self.compose(
            proxyAlreadyOn: proxyAlreadyOn,
            proxy: resolvedProxy,
            desktop: model.recommendation(.desktop),
            cli: model.recommendation(.cli),
            diagnostic: model.recommendation(.diagnostic),
            browserOpened: browserOpened,
            data: data
        )
    }

    func refreshProxyOnly(settings: EnvironmentSettings, proxyAlreadyOn: Bool) {
        let proxy = Self.probeProxy(settings.diagnosticProxy)
        let kind: ProductVerdictKind
        let headline: String
        let detail: String
        let next: String
        if proxyAlreadyOn && !proxy.listening {
            kind = .mismatch
            headline = "你勾了已开代理，但入口不可达"
            detail = proxy.detail
            next = "打开代理客户端，或关掉「已开代理」后再检测。"
        } else if !proxyAlreadyOn && proxy.listening {
            kind = .mismatch
            headline = "入口在听，但你未勾已开代理"
            detail = proxy.detail
            next = "若浏览器走代理，请打开「已开代理」再一键检测。"
        } else if proxy.listening {
            kind = .unknown
            headline = "代理入口可达"
            detail = proxy.detail
            next = "点「一键检测」在应用内完成本机路径检查。"
        } else if settings.diagnosticProxy.isEmpty {
            kind = .unknown
            headline = "未配置诊断代理入口"
            detail = "在检测设置里填写如 http://127.0.0.1:1082"
            next = "配置入口后再检测。"
        } else {
            kind = .unknown
            headline = "代理入口当前不可达"
            detail = proxy.detail
            next = "直连检测可继续；若要用代理请先打开客户端。"
        }
        let previous = verdict.data.map {
            ProductDetectData(
                collectedAt: $0.collectedAt,
                egressIPs: $0.egressIPs,
                hosts: $0.hosts,
                issues: $0.issues,
                proxy: proxy
            )
        }
        verdict = ProductVerdict(
            kind: kind,
            headline: headline,
            detail: detail,
            nextStep: next,
            proxy: proxy,
            desktop: verdict.desktop,
            cli: verdict.cli,
            diagnostic: verdict.diagnostic,
            browserOpened: false,
            data: previous
        )
    }

    static func probeProxy(_ raw: String) -> ProductProxyProbe {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return .init(endpoint: "未配置", listening: false, detail: "诊断代理入口为空。")
        }
        let transport = ProbeTransport.explicit(trimmed)
        guard transport.error == nil, let proxy = transport.proxy,
              let parts = URLComponents(string: proxy), let host = parts.host, let port = parts.port else {
            return .init(endpoint: trimmed, listening: false, detail: transport.error ?? "代理地址无效。")
        }
        let cleanHost = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let status = CurrentPathPortrait.probeListener(cleanHost, port)
        let endpoint = "\(cleanHost):\(port)"
        switch status {
        case "listening":
            return .init(endpoint: endpoint, listening: true, detail: "本机 \(endpoint) 有进程在听。")
        case "refused":
            return .init(endpoint: endpoint, listening: false, detail: "本机 \(endpoint) 拒绝连接。")
        case "not_local":
            return .init(endpoint: endpoint, listening: false, detail: "入口不是本机回环地址，产品只验本地入口。")
        default:
            return .init(endpoint: endpoint, listening: false, detail: "未能确认 \(endpoint) 是否在听。")
        }
    }

    static func extractData(
        reports: [EnvironmentTarget: EnvironmentReport],
        proxy: ProductProxyProbe,
        at: Date
    ) -> ProductDetectData {
        var hosts: [ProductHostSample] = []
        var issues: [ProductDetectIssue] = []
        for target in EnvironmentTarget.allCases {
            guard let report = reports[target] else { continue }
            let exitCodes = Dictionary(uniqueKeysWithValues: report.checks.compactMap { check in
                check.id.hasPrefix("exit:") ? (String(check.id.dropFirst(5)), check.code) : nil
            })
            for obs in report.observations {
                hosts.append(ProductHostSample(
                    path: target.title,
                    host: obs.host,
                    ip: obs.ip,
                    country: obs.country,
                    milliseconds: obs.milliseconds,
                    source: obs.source.title,
                    exitCode: exitCodes[obs.host] ?? "exit_unavailable"
                ))
            }
            for check in report.checks where check.required && (check.result == .failed || check.result == .unknown) {
                // Exit rows and the service row already carry a per-host label in
                // the table; repeating them here only re-alarms.
                let rowVisible = check.id.hasPrefix("exit:") || check.id.hasPrefix("network:")
                if rowVisible, EnvironmentProbeFailure.shortLabel(for: check.code) != nil { continue }
                issues.append(ProductDetectIssue(
                    target: target.title,
                    title: check.title,
                    code: check.code,
                    detail: check.detail
                ))
            }
        }
        let ips = Array(Set(hosts.compactMap(\.ip).filter { !$0.isEmpty })).sorted()
        return ProductDetectData(
            collectedAt: at,
            egressIPs: ips,
            hosts: hosts,
            issues: issues,
            proxy: proxy
        )
    }

    static func compose(
        proxyAlreadyOn: Bool,
        proxy: ProductProxyProbe,
        desktop: EnvironmentRecommendation,
        cli: EnvironmentRecommendation,
        diagnostic: EnvironmentRecommendation,
        browserOpened: Bool,
        data: ProductDetectData?
    ) -> ProductVerdict {
        let egressNote = data.map { " \($0.summaryLine)" } ?? ""
        if proxyAlreadyOn && !proxy.listening {
            return .init(
                kind: .mismatch,
                headline: "代理声明与入口不一致",
                detail: "已开代理=开，但 \(proxy.detail)",
                nextStep: "打开代理或关闭开关后重新检测。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }
        if !proxyAlreadyOn && proxy.listening {
            return .init(
                kind: .mismatch,
                headline: "入口在听，声明却是未开代理",
                detail: proxy.detail + " 出口采样可能仍走代理。",
                nextStep: "打开「已开代理」后再测一次，避免误判直连出口。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }

        let paths = [desktop, cli, diagnostic]
        let rows = data?.hosts ?? []
        let blocked = data?.blockedHosts ?? []

        // A wrong exit IP is evidence on a working line; it outranks line degradation.
        if data?.hasExitMismatch == true {
            return .init(
                kind: .attention,
                headline: "出口与固定基准不符",
                detail: "部分站点经当前线路返回的出口 IP 与你确认的基准不同（见下表标「出口不符」的行）。\(proxy.detail)",
                nextStep: "在代理客户端核对节点与域名规则，确认后重新检测。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }

        if !blocked.isEmpty {
            let reachable = Array(Set(rows.filter(\.reachable).map(\.host))).sorted()
            let tlsClass = rows.filter(\.blocked).allSatisfy { $0.exitCode.hasPrefix("tls") }
            let reason = tlsClass ? "TLS 握手被中断或超时" : "连接失败或超时"
            let boundary = "这是线路对这些域名的阻断，不是本工具故障，也不能据此判断 Claude 服务或账号异常；Claude 走当前线路会遇到同样问题。"
            if reachable.isEmpty {
                return .init(
                    kind: .attention,
                    headline: "当前线路访问不了 Claude 域名",
                    detail: "代理入口可达，但 \(blocked.joined(separator: "、"))全部\(reason)，本轮未采到任何出口。\(boundary)",
                    nextStep: "在代理客户端换节点或线路，然后重新检测。",
                    proxy: proxy,
                    desktop: desktop,
                    cli: cli,
                    diagnostic: diagnostic,
                    browserOpened: browserOpened,
                    data: data
                )
            }
            return .init(
                kind: .degraded,
                headline: "线路对部分 Claude 域名不可用",
                detail: "同一条线路下 \(reachable.joined(separator: "、"))可访问；\(blocked.joined(separator: "、"))\(reason)。\(boundary)",
                nextStep: "换节点或线路后重新检测；可访问的域名也不代表 Claude 全部可用。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }

        if paths.contains(.attention) {
            return .init(
                kind: .attention,
                headline: "本机路径发现问题",
                detail: "桌面：\(desktop.title) · CLI：\(cli.title) · 诊断：\(diagnostic.title)。\(proxy.detail).\(egressNote)",
                nextStep: "查看下方检测数据或「检查详情」，处理后重新检测。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }
        if paths.contains(where: { $0 == .unknown || $0 == .stale }) {
            return .init(
                kind: .unknown,
                headline: "本机路径尚未测全",
                detail: "桌面：\(desktop.title) · CLI：\(cli.title) · 诊断：\(diagnostic.title)。\(proxy.detail).\(egressNote)",
                nextStep: "CLI 需在项目终端跑独立采样；其它项可再点一键检测。",
                proxy: proxy,
                desktop: desktop,
                cli: cli,
                diagnostic: diagnostic,
                browserOpened: browserOpened,
                data: data
            )
        }
        return .init(
            kind: .ready,
            headline: "本机检测通过",
            detail: "代理与路径本轮正常。\(proxy.detail).\(egressNote)",
            nextStep: "可自行打开 Claude；这不是账号或全部真实会话路径的证明。浏览器页仅可选人工补充。",
            proxy: proxy,
            desktop: desktop,
            cli: cli,
            diagnostic: diagnostic,
            browserOpened: browserOpened,
            data: data
        )
    }
}
