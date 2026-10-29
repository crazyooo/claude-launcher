import SwiftUI
import AppKit
import LauncherCore

/// First screen: proxy strip → hero verdict → one primary detect → collapsed detail.
struct ProductHomePanel: View {
    @ObservedObject var model: EnvironmentModel
    @ObservedObject var websiteResults: WebsiteResultsSession
    @StateObject private var session = ProductDetectSession()
    @AppStorage("detector.proxyAlreadyOn") private var proxyAlreadyOn = false
    @State private var showWebsite = false
    @State private var showData = false
    @State private var showPaths = false
    @State private var showBrowser = false
    var openProtect: () -> Void
    var openDetails: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: DetectorStyle.space * 2.5) {
            identityHeader
            proxyStrip
            verdictHero
            primaryActions
            detailStack
            Text("本机与网站结果分别展示；网站结果不覆盖 Desktop / CLI 本机结论。")
                .font(.system(size: 11))
                .foregroundStyle(DetectorStyle.muted)
        }
        .onAppear {
            session.refreshProxyOnly(settings: model.settings, proxyAlreadyOn: proxyAlreadyOn)
            if !model.busy, !model.reports.isEmpty {
                session.ingest(model: model, proxyAlreadyOn: proxyAlreadyOn)
            }
            if session.verdict.data != nil { showData = true }
        }
        .onChange(of: proxyAlreadyOn) { _ in
            session.refreshProxyOnly(settings: model.settings, proxyAlreadyOn: proxyAlreadyOn)
        }
        .onChange(of: model.busy) { busy in
            if !busy, !session.busy {
                session.ingest(model: model, proxyAlreadyOn: proxyAlreadyOn)
                if session.verdict.data != nil { showData = true }
            }
        }
    }

    private var identityHeader: some View {
        HStack(alignment: .center, spacing: 14) {
            Image(systemName: "waveform.path.ecg")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(DetectorStyle.pulse)
                .frame(width: 52, height: 52)
                .background(DetectorStyle.greenSoft, in: RoundedRectangle(cornerRadius: 14))

            VStack(alignment: .leading, spacing: 4) {
                Text("环境检测")
                    .font(.system(size: 26, weight: .semibold))
                    .tracking(-0.4)
                Text("看清代理链路 · 可选挡住静默直连")
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
            }
            Spacer(minLength: 8)
            if session.busy || model.busy {
                ProgressView().controlSize(.small)
            }
        }
    }

    private var proxyStrip: some View {
        VStack(alignment: .leading, spacing: 12) {
            Toggle(isOn: $proxyAlreadyOn) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("已开代理").font(.system(size: 14, weight: .semibold))
                    Text(proxyAlreadyOn ? "将核对本地入口是否在听" : "当前按直连理解；入口若在听会提示改开关")
                        .font(.system(size: 12))
                        .foregroundStyle(DetectorStyle.muted)
                }
            }
            .toggleStyle(.switch)

            HStack(spacing: 10) {
                Circle()
                    .fill(session.verdict.proxy?.listening == true ? DetectorStyle.green : DetectorStyle.pulse)
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
                 ? "未配置诊断代理 · 设置里可填 http://127.0.0.1:1082"
                 : model.settings.diagnosticProxy)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(DetectorStyle.muted)
                .textSelection(.enabled)
        }
        .detectorCard(.quiet)
    }

    private var verdictHero: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Text("检测结论")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(DetectorStyle.muted)
                Spacer()
                Label(session.verdict.kind.rawValue, systemImage: session.verdict.kind.symbol)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(verdictColor(session.verdict.kind))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 5)
                    .background(verdictColor(session.verdict.kind).opacity(0.12), in: Capsule())
            }
            Text(session.verdict.headline)
                .font(.system(size: 24, weight: .semibold))
                .foregroundStyle(verdictColor(session.verdict.kind))
                .fixedSize(horizontal: false, vertical: true)
            Text(session.verdict.detail)
                .font(.system(size: 13))
                .foregroundStyle(DetectorStyle.ink)
                .fixedSize(horizontal: false, vertical: true)
            Text("下一步：\(session.verdict.nextStep)")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            if model.manualRequired && session.verdict.kind != .degraded {
                Label("已记录异常；处理完后再点「一键检测」。", systemImage: "exclamationmark.circle")
                    .font(.system(size: 12))
                    .foregroundStyle(DetectorStyle.pulse)
            }
        }
        .detectorCard(.hero)
    }

    private var primaryActions: some View {
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

    private var detailStack: some View {
        VStack(alignment: .leading, spacing: 10) {
            disclosure("网站检测结果", isOn: $showWebsite, systemImage: "globe") {
                WebsiteResultsPanel(session: websiteResults, embedded: true)
            }
            if session.verdict.data != nil {
                disclosure("后台检测数据", isOn: $showData, systemImage: "tablecells") {
                    dataBody
                }
            }
            disclosure("本机路径", isOn: $showPaths, systemImage: "point.3.connected.trianglepath.dotted") {
                pathBody
            }
            disclosure("外部浏览器对照", isOn: $showBrowser, systemImage: "safari") {
                browserBody
            }
        }
    }

    private func disclosure<Content: View>(
        _ title: String,
        isOn: Binding<Bool>,
        systemImage: String,
        @ViewBuilder content: @escaping () -> Content
    ) -> some View {
        DisclosureGroup(isExpanded: isOn) {
            content()
                .padding(.top, 10)
        } label: {
            Label(title, systemImage: systemImage)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(DetectorStyle.ink)
        }
        .padding(14)
        .background(DetectorStyle.surfaceQuiet, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard))
        .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))
    }

    @ViewBuilder
    private var dataBody: some View {
        if let data = session.verdict.data {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Text(data.summaryLine)
                        .font(.system(size: 12, design: .monospaced))
                        .textSelection(.enabled)
                    Spacer()
                    Text(Self.shortTime(data.collectedAt))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(DetectorStyle.muted)
                }
                if !data.hosts.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
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
                        Text("逐站结果只反映当前线路可达性，不证明账号或对话可用。")
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
                                .foregroundStyle(DetectorStyle.pulse)
                        }
                    }
                }
            }
        }
    }

    private var pathBody: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 16) {
                pathChip(.desktop, session.verdict.desktop)
                pathChip(.cli, session.verdict.cli)
                pathChip(.diagnostic, session.verdict.diagnostic)
            }
            Text(model.message)
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
        }
    }

    private func pathChip(_ target: EnvironmentTarget, _ state: EnvironmentRecommendation) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(target.title).font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            Label(state.title, systemImage: DetectorStyle.symbol(state))
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(DetectorStyle.color(state))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(12)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusChip))
    }

    private var browserBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("需要与平时浏览器对照时，再打开原网页。")
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
    }

    private func verdictColor(_ kind: ProductVerdictKind) -> Color {
        switch kind {
        case .ready: return DetectorStyle.green
        case .degraded, .attention, .mismatch: return DetectorStyle.pulse
        case .unknown, .idle: return DetectorStyle.muted
        }
    }

    private static func tone(_ tone: ProductHostSample.Tone) -> Color {
        switch tone {
        case .good: return DetectorStyle.green
        case .warn: return DetectorStyle.pulse
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
