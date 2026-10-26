import SwiftUI
import AppKit
import LauncherCore

/// First-screen product surface: background local detect → structured data → optional protect.
struct ProductHomePanel: View {
    @ObservedObject var model: EnvironmentModel
    @ObservedObject var websiteResults: WebsiteResultsSession
    @StateObject private var session = ProductDetectSession()
    @AppStorage("detector.proxyAlreadyOn") private var proxyAlreadyOn = false
    var openProtect: () -> Void
    var openDetails: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 22) {
            header
            proxyCard
            actionRow
            verdictCard
            WebsiteResultsPanel(session: websiteResults)
            dataCard
            pathCard
            browserCard
            Text("本机与网站结果分别展示；网站结果不覆盖 Desktop / CLI 本机结论。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
        }
        .onAppear {
            session.refreshProxyOnly(settings: model.settings, proxyAlreadyOn: proxyAlreadyOn)
            if !model.busy, !model.reports.isEmpty {
                session.ingest(model: model, proxyAlreadyOn: proxyAlreadyOn)
            }
        }
        .onChange(of: proxyAlreadyOn) { _ in
            session.refreshProxyOnly(settings: model.settings, proxyAlreadyOn: proxyAlreadyOn)
        }
        .onChange(of: model.busy) { busy in
            // Toolbar / auto-detect also feed the first screen when a round finishes.
            if !busy, !session.busy {
                session.ingest(model: model, proxyAlreadyOn: proxyAlreadyOn)
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "waveform.path.ecg")
                .font(.system(size: 26))
                .foregroundStyle(DetectorStyle.green)
                .frame(width: 58, height: 58)
                .background(DetectorStyle.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
            VStack(alignment: .leading, spacing: 8) {
                Text("环境检测").font(.system(size: 30, weight: .semibold)).tracking(-0.5)
                Text("一键检测在后台核对代理入口与本机 Claude 路径，把出口 IP 与逐站结果回填到本页。默认不弹浏览器。可选再进「防直连」。")
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
            }
            Spacer(minLength: 12)
            if session.busy || model.busy {
                ProgressView().controlSize(.small).padding(.top, 10)
            } else {
                verdictBadge.padding(.top, 10)
            }
        }
    }

    private var verdictBadge: some View {
        Label(session.verdict.kind.rawValue, systemImage: session.verdict.kind.symbol)
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(verdictColor(session.verdict.kind))
    }

    private var proxyCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle(isOn: $proxyAlreadyOn) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("已开代理").font(.system(size: 15, weight: .semibold))
                    Text(proxyAlreadyOn
                         ? "声明：浏览器/Claude 走代理。将核对本地入口是否真的在听。"
                         : "声明：当前按直连理解。若入口实际在听，结论会提示你改开关。")
                        .font(.system(size: 12))
                        .foregroundStyle(DetectorStyle.muted)
                }
            }
            .toggleStyle(.switch)

            HStack(spacing: 10) {
                Circle()
                    .fill(session.verdict.proxy?.listening == true ? DetectorStyle.green : DetectorStyle.amber)
                    .frame(width: 8, height: 8)
                Text(session.verdict.proxy.map { "入口 \($0.endpoint) · \($0.listening ? "可达" : "不可达")" }
                     ?? "入口尚未探测")
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                Spacer()
                Button("再测入口") {
                    session.refreshProxyOnly(settings: model.settings, proxyAlreadyOn: proxyAlreadyOn)
                }
                .buttonStyle(.link)
                .disabled(session.busy || model.busy)
            }
            Text(model.settings.diagnosticProxy.isEmpty
                 ? "未配置诊断代理；可在检测设置填写 http://127.0.0.1:1082"
                 : model.settings.diagnosticProxy)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(DetectorStyle.muted)
                .textSelection(.enabled)
        }
        .padding(18)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private var actionRow: some View {
        HStack(spacing: 12) {
            Button {
                session.run(model: model, proxyAlreadyOn: proxyAlreadyOn, openBrowser: false)
            } label: {
                Label(session.busy || model.busy ? "检测中…" : "一键检测", systemImage: "bolt.horizontal.circle")
            }
            .buttonStyle(DetectorActionStyle(primary: true))
            .disabled(session.busy || model.busy)

            Button(action: openProtect) {
                Label("防直连", systemImage: "shield.lefthalf.filled")
            }
            .buttonStyle(DetectorActionStyle())

            Button(action: openDetails) {
                Label("检查详情", systemImage: "checklist")
            }
            .buttonStyle(DetectorActionStyle())

            Spacer(minLength: 0)
        }
    }

    private var verdictCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("检测结论").font(.system(size: 14, weight: .semibold))
            Text(session.verdict.headline)
                .font(.system(size: 20, weight: .semibold))
                .foregroundStyle(verdictColor(session.verdict.kind))
            Text(session.verdict.detail)
                .font(.system(size: 13))
                .foregroundStyle(DetectorStyle.ink)
            Text("下一步：\(session.verdict.nextStep)")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            if model.manualRequired && session.verdict.kind != .degraded {
                Label("已记录异常；处理完后再点「一键检测」。", systemImage: "exclamationmark.circle")
                    .font(.callout)
                    .foregroundStyle(DetectorStyle.amber)
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    @ViewBuilder
    private var dataCard: some View {
        if let data = session.verdict.data {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("后台检测数据").font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Text(Self.shortTime(data.collectedAt))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(DetectorStyle.muted)
                }
                Text(data.summaryLine)
                    .font(.system(size: 13, design: .monospaced))
                    .textSelection(.enabled)

                if !data.hosts.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        ForEach(data.hosts.prefix(8)) { sample in
                            HStack(alignment: .firstTextBaseline, spacing: 8) {
                                Text(sample.path)
                                    .font(.system(size: 11))
                                    .foregroundStyle(DetectorStyle.muted)
                                    .frame(width: 72, alignment: .leading)
                                Text(sample.host)
                                    .font(.system(size: 12, design: .monospaced))
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                Text(sample.statusLabel)
                                    .font(.system(size: 11, weight: .medium))
                                    .foregroundStyle(Self.tone(sample.statusTone))
                                    .frame(width: 62, alignment: .leading)
                                Text(sample.ip ?? "—")
                                    .font(.system(size: 12, design: .monospaced))
                                    .textSelection(.enabled)
                                    .frame(width: 116, alignment: .leading)
                                Text(sample.country ?? "—")
                                    .font(.system(size: 11))
                                    .foregroundStyle(DetectorStyle.muted)
                                    .frame(width: 36, alignment: .trailing)
                                Text("\(sample.milliseconds)ms")
                                    .font(.system(size: 11, design: .monospaced))
                                    .foregroundStyle(DetectorStyle.muted)
                                    .frame(width: 52, alignment: .trailing)
                            }
                        }
                        if data.hosts.count > 8 {
                            Text("另有 \(data.hosts.count - 8) 条，见检查详情。")
                                .font(.caption)
                                .foregroundStyle(DetectorStyle.muted)
                        }
                        Text("逐站结果只反映当前线路对这些域名的网络可达性；「可访问」不证明账号、订阅或对话可用，失败行也不代表 Claude 服务故障。")
                            .font(.system(size: 11))
                            .foregroundStyle(DetectorStyle.muted)
                    }
                }

                if !data.issues.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("其它待处理项").font(.system(size: 12, weight: .semibold))
                        ForEach(data.issues.prefix(5)) { issue in
                            Text("· \(issue.target)：\(issue.title)（\(issue.code)）")
                                .font(.system(size: 12))
                                .foregroundStyle(DetectorStyle.amber)
                        }
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
            .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
        }
    }

    private var pathCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("本机路径").font(.system(size: 14, weight: .semibold))
            HStack(alignment: .top, spacing: 18) {
                pathChip(.desktop, session.verdict.desktop)
                pathChip(.cli, session.verdict.cli)
                pathChip(.diagnostic, session.verdict.diagnostic)
            }
            Text(model.message)
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private func pathChip(_ target: EnvironmentTarget, _ state: EnvironmentRecommendation) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(target.title).font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            Label(state.title, systemImage: DetectorStyle.symbol(state))
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(DetectorStyle.color(state))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var browserCard: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("外部浏览器对照（可选）").font(.system(size: 14, weight: .semibold))
            Text("网站数据可在上方直接读取；需要与平时浏览器的结果对照时，再打开原网页。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            HStack(spacing: 12) {
                Button {
                    ProductDetectActions.openPrimaryBrowserSources()
                } label: {
                    Label("打开两页", systemImage: "safari")
                }
                .buttonStyle(DetectorActionStyle())
                ForEach(BrowserSupplementPage.allPages) { page in
                    Button {
                        ProductDetectActions.open(page.url)
                    } label: {
                        Label(page.title, systemImage: "arrow.up.right.square")
                            .font(.system(size: 13, weight: .medium))
                    }
                    .buttonStyle(.link)
                }
            }
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private func verdictColor(_ kind: ProductVerdictKind) -> Color {
        switch kind {
        case .ready: return DetectorStyle.green
        case .degraded, .attention, .mismatch: return DetectorStyle.amber
        case .unknown, .idle: return DetectorStyle.muted
        }
    }

    private static func tone(_ tone: ProductHostSample.Tone) -> Color {
        switch tone {
        case .good: return DetectorStyle.green
        case .warn: return DetectorStyle.amber
        case .bad: return DetectorStyle.clay
        case .muted: return DetectorStyle.muted
        }
    }

    private static func shortTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "zh_CN")
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}

enum ProductDetectActions {
    static func openPrimaryBrowserSources() {
        for (index, page) in BrowserSupplementPage.oneClickPages.enumerated() {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.35 * Double(index)) {
                open(page.url)
            }
        }
    }

    static func openIPSuperPrimary() { openPrimaryBrowserSources() }

    static func open(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }
}
