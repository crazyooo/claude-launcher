import SwiftUI
import ServiceManagement

enum DetectorMenuIcon: String, CaseIterable, Identifiable {
    case network, pulse, magnifier
    var id: String { rawValue }
    var title: String {
        switch self {
        case .network: return "网络"
        case .pulse: return "脉冲"
        case .magnifier: return "检测镜"
        }
    }
    var symbol: String {
        switch self {
        case .network: return "network"
        case .pulse: return "waveform.path.ecg"
        case .magnifier: return "magnifyingglass"
        }
    }
}

/// App presentation and scheduling preferences, separate from network evidence.
@MainActor final class MenuBarPreferences: ObservableObject {
    static let intervals = [30, 60, 120, 300]
    private let defaults: UserDefaults

    @Published var icon: DetectorMenuIcon {
        didSet { defaults.set(icon.rawValue, forKey: "detector.menu.icon") }
    }
    @Published var showStatusText: Bool {
        didSet { defaults.set(showStatusText, forKey: "detector.menu.showStatusText") }
    }
    @Published var automaticChecks: Bool {
        didSet { defaults.set(automaticChecks, forKey: "detector.menu.automaticChecks") }
    }
    @Published var interval: Int {
        didSet {
            if !Self.intervals.contains(interval) { interval = 30 }
            defaults.set(interval, forKey: "detector.menu.interval")
        }
    }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        icon = DetectorMenuIcon(rawValue: defaults.string(forKey: "detector.menu.icon") ?? "") ?? .network
        showStatusText = defaults.object(forKey: "detector.menu.showStatusText") as? Bool ?? false
        automaticChecks = defaults.object(forKey: "detector.menu.automaticChecks") as? Bool ?? true
        let savedInterval = defaults.integer(forKey: "detector.menu.interval")
        interval = Self.intervals.contains(savedInterval) ? savedInterval : 30
    }

    static func intervalTitle(_ seconds: Int) -> String {
        seconds < 60 ? "\(seconds) 秒" : "\(seconds / 60) 分钟"
    }
}

struct LoginItemEffects {
    var status: () -> SMAppService.Status = { SMAppService.mainApp.status }
    var register: () throws -> Void = { try SMAppService.mainApp.register() }
    var unregister: () throws -> Void = { try SMAppService.mainApp.unregister() }
}

/// Read the OS registration state; a saved toggle alone cannot prove registration.
@MainActor final class DetectorLoginItem: ObservableObject {
    @Published private(set) var status: SMAppService.Status
    @Published private(set) var error = ""
    private let effects: LoginItemEffects

    init(effects: LoginItemEffects = LoginItemEffects()) {
        self.effects = effects
        status = effects.status()
    }

    var requested: Bool { status == .enabled || status == .requiresApproval }
    var detail: String {
        switch status {
        case .enabled: return "已开启，下次登录 Mac 时启动检测器。"
        case .requiresApproval: return "等待系统允许，请在系统登录项中开启。"
        case .notRegistered: return "未开启；需要时手动打开应用。"
        case .notFound: return "系统未找到应用，请从安装位置重新打开后再试。"
        @unknown default: return "系统状态未知，请查看系统登录项。"
        }
    }

    func refresh() { status = effects.status() }
    func setEnabled(_ enabled: Bool) {
        refresh()
        guard enabled != requested else { return }
        error = ""
        do {
            if enabled { try effects.register() }
            else { try effects.unregister() }
        } catch {
            self.error = "登录启动设置未完成：" + error.localizedDescription
        }
        refresh()
    }
}

struct DetectorMenuBarLabel: View {
    @ObservedObject var model: EnvironmentModel
    @ObservedObject var preferences: MenuBarPreferences

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: preferences.icon.symbol)
            if preferences.showStatusText { Text(model.headline) }
        }
        .accessibilityLabel("Claude 环境检测 · " + model.headline)
        .help("Claude 环境检测 · " + model.headline)
    }
}

struct DetectorAppSettings: View {
    @ObservedObject var model: EnvironmentModel
    var body: some View {
        TabView {
            DetectorMenuSettings(preferences: model.preferences)
                .tabItem { Label("菜单栏与后台", systemImage: "menubar.rectangle") }
            DetectorSettings(model: model, value: model.settings)
                .tabItem { Label("检测", systemImage: "slider.horizontal.3") }
        }
        .padding(16)
        .frame(width: 580, height: 540)
    }
}

private struct DetectorMenuSettings: View {
    @ObservedObject var preferences: MenuBarPreferences
    @StateObject private var loginItem = DetectorLoginItem()

    var body: some View {
        Form {
            Section("菜单栏") {
                Picker("图标", selection: $preferences.icon) {
                    ForEach(DetectorMenuIcon.allCases) { icon in
                        Label(icon.title, systemImage: icon.symbol).tag(icon)
                    }
                }
                Toggle("在图标旁显示检测状态", isOn: $preferences.showStatusText)
            }
            Section("后台检测") {
                Toggle("自动检测本机网络", isOn: $preferences.automaticChecks)
                Picker("检测间隔", selection: $preferences.interval) {
                    ForEach(MenuBarPreferences.intervals, id: \.self) { interval in
                        Text(MenuBarPreferences.intervalTitle(interval)).tag(interval)
                    }
                }
                .disabled(!preferences.automaticChecks)
                Text("关闭后仍可手动检测，正在进行的一轮会完成。结果超过 5 分钟或网络变化后失效；网站结果仍需手动读取。")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Section("启动") {
                Toggle("登录 Mac 时启动", isOn: Binding(
                    get: { loginItem.requested }, set: { loginItem.setEnabled($0) }
                ))
                Text(loginItem.detail).font(.caption).foregroundStyle(.secondary)
                if !loginItem.error.isEmpty {
                    Text(loginItem.error).font(.caption).foregroundStyle(.orange)
                }
                Button("打开系统登录项…") { SMAppService.openSystemSettingsLoginItems() }
            }
            Section {
                Text("本页更改立即保存。关闭主窗口后仍驻留菜单栏，可从菜单退出检测器。退出不会关闭独立运行的防直连防护。")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .formStyle(.grouped)
        .onAppear { loginItem.refresh() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            loginItem.refresh()
        }
    }
}
