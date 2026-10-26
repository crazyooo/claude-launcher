import SwiftUI
import AppKit
import UserNotifications
import LauncherCore

private enum DetectorPage: String, CaseIterable, Identifiable {
    case home = "环境检测"
    case details = "检查详情"
    case protect = "防直连"
    case tools = "其他工具"
    case logs = "问题与日志"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .home: return "waveform.path.ecg"
        case .details: return "checklist"
        case .protect: return "shield.lefthalf.filled"
        case .tools: return "shippingbox"
        case .logs: return "doc.text.magnifyingglass"
        }
    }
}

private func detectorColor(_ value: EnvironmentRecommendation) -> Color {
    DetectorStyle.color(value)
}
func resultLabel(_ value: CheckResult) -> String {
    switch value { case .passed: return "通过"; case .failed: return "异常"; case .unknown: return "未确认"; case .info: return "补充观察" }
}
func copyDetectorText(_ value: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(value, forType: .string)
}

struct DetectorConsole: View {
    @ObservedObject var model: EnvironmentModel
    @StateObject private var websiteResults = WebsiteResultsSession()
    @StateObject private var protection = ClaudeProtectModel()
    @State private var page = DetectorPage.home
    @Environment(\.openWindow) private var openWindow
    @State private var exportMessage = ""
    private var overall: EnvironmentRecommendation { model.overallRecommendation }

    var body: some View {
        HStack(spacing: 0) {
            sidebar
            Rectangle().fill(DetectorStyle.border).frame(width: 1)
            VStack(alignment: .leading, spacing: 0) {
                HStack(spacing: 16) {
                    Text(page.rawValue).font(.system(size: 14, weight: .semibold))
                    Spacer()
                    Text("本机后台检测 · 浏览器可选").font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
                    Button { openWindow(id: "settings") } label: { Image(systemName: "slider.horizontal.3") }
                        .buttonStyle(DetectorActionStyle()).help("设置").accessibilityLabel("设置")
                    Button {
                        // In-app only; first screen ingests reports when busy clears. No auto browser.
                        model.detect()
                    } label: {
                        Label(
                            model.busy ? "检测中…" : (page == .home ? "一键检测" : "重新检测"),
                            systemImage: page == .home ? "bolt.horizontal.circle" : "arrow.clockwise"
                        )
                    }
                    .buttonStyle(DetectorActionStyle(primary: true))
                    .disabled(model.busy)
                }
                .padding(.horizontal, 30)
                .frame(height: 76)
                Rectangle().fill(DetectorStyle.border).frame(height: 1)
                ScrollView {
                    VStack(alignment: .leading, spacing: 24) {
                        switch page {
                        case .home:
                            ProductHomePanel(
                                model: model,
                                websiteResults: websiteResults,
                                openProtect: { page = .protect },
                                openDetails: { page = .details }
                            )
                        case .details:
                            details
                        case .protect:
                            ClaudeProtectPanel(model: protection)
                        case .tools:
                            ClaudeOpenSourceToolsPanel()
                        case .logs:
                            logPage
                        }
                    }
                    .padding(28)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                Rectangle().fill(DetectorStyle.border).frame(height: 1)
                HStack {
                    Circle()
                        .fill(model.busy ? DetectorStyle.blue : DetectorStyle.color(overall))
                        .frame(width: 6, height: 6)
                    Text(model.message).lineLimit(2)
                    Spacer()
                    Text("环境检测 · 可选防护 · 开源")
                }
                .font(.system(size: 11))
                .foregroundStyle(DetectorStyle.muted)
                .padding(.horizontal, 28)
                .frame(minHeight: 40)
            }
            .background(DetectorStyle.canvas)
        }
        .frame(minWidth: 1120, minHeight: 760)
        .foregroundStyle(DetectorStyle.ink)
        .tint(DetectorStyle.green)
        .onChange(of: model.generation) { _ in websiteResults.invalidate() }
        .onChange(of: model.now) { websiteResults.expire(at: $0) }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            Image(systemName: "network")
                .font(.system(size: 25, weight: .semibold))
                .foregroundStyle(DetectorStyle.green)
                .frame(width: 48, height: 48)
                .background(DetectorStyle.green.opacity(0.07), in: RoundedRectangle(cornerRadius: 14))
                .padding(.bottom, 20)
            Text("Claude\n环境检测")
                .font(.system(size: 25, weight: .semibold))
                .tracking(-0.7)
                .lineSpacing(2)
            Text("本机路径检测")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
                .padding(.top, 12)
                .padding(.bottom, 24)
            ForEach(DetectorPage.allCases) { item in
                Button { page = item } label: {
                    HStack(spacing: 12) {
                        Image(systemName: item.icon)
                            .font(.system(size: 17, weight: .medium))
                            .foregroundStyle(page == item ? DetectorStyle.blue : DetectorStyle.green)
                            .frame(width: 36, height: 36)
                            .background(
                                (page == item ? DetectorStyle.blue : DetectorStyle.green).opacity(0.07),
                                in: RoundedRectangle(cornerRadius: 10)
                            )
                        Text(item.rawValue)
                            .font(.system(size: 14, weight: page == item ? .semibold : .regular))
                        Spacer(minLength: 0)
                        if page == item {
                            RoundedRectangle(cornerRadius: 2)
                                .fill(DetectorStyle.blue)
                                .frame(width: 3, height: 16)
                        }
                    }
                    .padding(9)
                    .background(
                        page == item ? DetectorStyle.blue.opacity(0.08) : .clear,
                        in: RoundedRectangle(cornerRadius: 11)
                    )
                }
                .buttonStyle(.plain)
                .padding(.bottom, 7)
            }
            Spacer(minLength: 24)
            Rectangle().fill(DetectorStyle.border).frame(height: 1).padding(.bottom, 20)
            DetectorStateLabel(state: overall)
            Text(sidebarConclusionLine)
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
                .padding(.top, 9)
            Text(
                "环境检测 · v"
                    + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "开发版")
            )
            .font(.system(size: 11))
            .foregroundStyle(DetectorStyle.muted)
            .padding(.top, 7)
            HStack {
                Label("跟随系统外观", systemImage: "circle.lefthalf.filled").font(.system(size: 10))
                Spacer()
                Button { NSApp.terminate(nil) } label: {
                    Image(systemName: "power")
                }
                .buttonStyle(.plain)
                .help("退出检测器")
                .accessibilityLabel("退出检测器")
            }
            .foregroundStyle(DetectorStyle.muted)
            .padding(.top, 24)
        }
        .padding(.horizontal, 20)
        .padding(.top, 38)
        .padding(.bottom, 22)
        .frame(width: 218)
        .background(DetectorStyle.sidebar)
    }

    private var sidebarConclusionLine: String {
        if model.busy { return "正在后台检测…" }
        switch overall {
        case .ready: return "本轮环境检测可用"
        case .attention: return "本轮异常，打开检查详情"
        case .unknown, .stale: return "尚未测全，点一键检测"
        }
    }

    private var details: some View {
        ClaudeCodeDetailsPanel(model: model)
    }

    private var logPage: some View {
        VStack(alignment: .leading, spacing: 20) {
            DetectorSection("诊断日志", icon: "doc.text.magnifyingglass") {
                Text("日志保存在本机，最多 10 MiB。只保留时间、对象、结果和错误类别；不含凭据、对话、订阅原文。")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                Button("导出脱敏日志…") { exportLogs() }
                if !model.logProblem.isEmpty { Text(model.logProblem).foregroundStyle(.orange) }
                if !exportMessage.isEmpty { Text(exportMessage).font(.caption) }
                ForEach(Array(model.logs.reversed())) { entry in
                    DetectorLogRow(entry: entry)
                }
                if model.logs.isEmpty {
                    Text("暂无检测记录。").foregroundStyle(.secondary)
                }
            }
        }
    }

    private func exportLogs() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "claude-environment-diagnostics.json"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try model.records.export().write(to: url, options: .atomic)
            exportMessage = "脱敏日志已导出。"
        } catch {
            exportMessage = "日志导出失败；原记录已保留。"
        }
    }
}

private struct DetectorLogRow: View {
    let entry: DetectorLogEntry
    private var heading: String {
        entry.at.formatted() + " · " + entry.event.title + " · " + (entry.target?.title ?? "环境")
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(heading).font(.callout)
            if let result = entry.result {
                Text(resultLabel(result) + " · " + entry.problem.rawValue).font(.caption.monospaced())
            }
            Text(entry.problem.advice).font(.caption).foregroundStyle(.secondary)
        }
        .padding(.vertical, 6)
        Divider()
    }
}

struct DetectorSection<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content
    init(_ title: String, icon: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.icon = icon
        self.content = content()
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label(title, systemImage: icon).font(.headline)
            content
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }
}

struct CLIDetectionCommand: View {
    static var command: String {
        let tool = Bundle.main.bundleURL
            .appendingPathComponent("Contents/MacOS/launcher-tool").path
        return "'" + tool.replacingOccurrences(of: "'", with: "'\\''") + "' inspect cli"
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("在实际使用 Claude Code 的终端，先进入项目目录，再运行：").font(.caption)
            Text(Self.command).font(.caption.monospaced()).textSelection(.enabled)
            Button("复制 CLI 检测命令") { copyDetectorText(Self.command) }
        }
    }
}

struct DetectorSettings: View {
    @ObservedObject var model: EnvironmentModel
    @State var value: EnvironmentSettings
    @State private var error = ""
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("检测设置").font(.title2.bold())
            TextField("确认的固定出口 IPv4", text: $value.expectedIP)
            TextField("单独诊断的代理入口", text: $value.diagnosticProxy)
            Text("保存只改变检测基准；不修改系统代理或客户端线路。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Toggle("异常通知", isOn: $value.notifications)
            if !error.isEmpty { Text(error).foregroundStyle(.orange) }
            HStack {
                Button("取消") { dismiss() }
                Spacer()
                Button("保存并检测") {
                    do {
                        try model.save(value)
                        if value.notifications {
                            UNUserNotificationCenter.current()
                                .requestAuthorization(options: [.alert, .sound]) { _, _ in }
                        }
                        dismiss()
                    } catch {
                        self.error = error.localizedDescription
                    }
                }
                .disabled(!model.readable || model.busy)
            }
        }
        .padding(24)
        .frame(width: 520)
    }
}

private struct WebsiteSupplement: View {
    @ObservedObject var model: EnvironmentModel
    @State private var observed = Date()
    @State private var ip = ""
    @State private var result = WebsiteResult.uncertain
    @State private var message = ""
    var body: some View {
        DetectorSection("浏览器补充检查", icon: "globe") {
            Text("检测源仅两个 Claude 页。先确认是否已开代理，再打开；结果由你人工记录。")
                .font(.caption)
                .foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(BrowserSupplementPage.allPages) { page in
                    Link("打开 \(page.title)", destination: URL(string: page.url)!)
                }
            }
            Text("浏览器站点评分不参与本机 Desktop/CLI 结论。")
                .font(.caption)
                .foregroundStyle(.secondary)
            if let previous = model.website {
                Text(
                    (model.websiteRecent ? "近期人工记录" : "历史记录，需重新检测")
                        + " · " + previous.observedAt.formatted()
                )
                .font(.callout)
                Text(previous.observedIP + " · " + previous.result.rawValue).font(.caption)
            } else {
                Text("尚未记录网站检查").font(.caption).foregroundStyle(.secondary)
            }
            DatePicker("网站实际检测时间", selection: $observed, displayedComponents: [.date, .hourAndMinute])
            TextField("网站显示的出口 IP", text: $ip)
            Picker("人工结果", selection: $result) {
                ForEach(WebsiteResult.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }
            Button("保存补充记录") {
                do {
                    try model.saveWebsite(at: observed, ip: ip, result: result)
                    message = "已保存；本机检测结论保持独立。"
                } catch {
                    message = error.localizedDescription
                }
            }
            Text(message.isEmpty ? model.websiteProblem : message)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text("记录超过 10 分钟、网络或设置变化、应用重启后显示为历史。")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }
}

struct DetectorMenu: View {
    @ObservedObject var model: EnvironmentModel
    @ObservedObject private var preferences: MenuBarPreferences
    @AppStorage("detector.proxyAlreadyOn") private var proxyAlreadyOn = false
    @Environment(\.openWindow) private var openWindow
    init(model: EnvironmentModel) {
        self.model = model
        self.preferences = model.preferences
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Claude 环境检测", systemImage: "network").font(.headline)
            Text(model.headline)
                .font(.title2.bold())
                .foregroundStyle(detectorColor(model.overallRecommendation))
            Text(menuConclusionLine)
                .font(.caption)
                .foregroundStyle(.secondary)
            Toggle("已开代理", isOn: $proxyAlreadyOn)
            Toggle("后台自动检测", isOn: $preferences.automaticChecks)
            Text(preferences.automaticChecks
                 ? "每 " + MenuBarPreferences.intervalTitle(preferences.interval) + "自动检测本机路径"
                 : (model.busy ? "自动检测已暂停，当前一轮完成后停止" : "自动检测已暂停，可随时手动检测"))
                .font(.caption).foregroundStyle(.secondary)
            Text(
                "环境检测 · v"
                    + (Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "开发版")
            )
            .font(.caption2)
            .foregroundStyle(.secondary)
            Text("固定出口：" + (model.settings.expectedIP.isEmpty ? "未设置" : model.settings.expectedIP))
                .font(.caption.monospaced())
            HStack {
                Button(checkButtonTitle, action: check)
                .disabled(checkDisabled)
                Button("打开控制台") {
                    openConsole(open: { openWindow(id: $0) },
                                activate: { NSApp.activate(ignoringOtherApps: true) })
                }
            }
            Divider()
            HStack {
                Button("设置…") {
                    openSettings(open: { openWindow(id: $0) },
                                 activate: { NSApp.activate(ignoringOtherApps: true) })
                }
                Spacer()
                Button("退出检测器") { NSApp.terminate(nil) }
            }
        }
        .padding(20)
        .frame(width: 360)
    }

    // These are also exercised by menu regression tests; buttons use the same
    // actions so tests do not duplicate the manual-check or window-routing rules.
    var checkButtonTitle: String { model.busy ? "检测中…" : "一键检测" }
    var checkDisabled: Bool { model.busy }
    func check() { model.detect(manual: true) }

    func openConsole(open: (String) -> Void, activate: () -> Void) {
        open("main")
        activate()
    }

    func openSettings(open: (String) -> Void, activate: () -> Void) {
        open("settings")
        activate()
    }

    var menuConclusionLine: String {
        if model.busy { return "正在后台检测…" }
        switch model.overallRecommendation {
        case .ready: return "本轮环境检测可用"
        case .attention: return "本轮异常，打开控制台查看"
        case .unknown, .stale: return "尚未测全，点一键检测"
        }
    }
}
