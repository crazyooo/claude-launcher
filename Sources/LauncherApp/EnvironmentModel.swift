import SwiftUI
import AppKit
import Network
import UserNotifications
import LauncherCore

struct DetectorEffects {
    var settings: () throws -> EnvironmentSettings = { try EnvironmentSettings.read() }
    var save: (EnvironmentSettings) throws -> Void = { try $0.save() }
    var network: () async -> String = { await Task.detached { EnvironmentInspector.networkFingerprint() }.value }
    var inspect: (EnvironmentTarget, EnvironmentSettings) async -> EnvironmentReport = { target, settings in
        await Task.detached { EnvironmentInspector.inspect(target: target, settings: settings) }.value
    }
    var cli: () throws -> EnvironmentReport? = { try EnvironmentReportStore.latestCLI() }
    var now: () -> Date = { Date() }
    var notify: (String) -> Void = { text in
        let center = UNUserNotificationCenter.current()
        center.getNotificationSettings { settings in
            guard settings.authorizationStatus == .authorized else { return }
            let content = UNMutableNotificationContent(); content.title = "Claude 环境检测"; content.body = text
            center.add(.init(identifier: "environment-issue", content: content, trigger: nil))
        }
    }
}

/// Observation only: no old recovery model, launch action, PF journal or gateway control.
@MainActor final class EnvironmentModel: ObservableObject {
    @Published private(set) var settings = EnvironmentSettings()
    @Published private(set) var readable = true
    @Published private(set) var reports: [EnvironmentTarget: EnvironmentReport] = [:]
    @Published private(set) var busy = false
    @Published private(set) var generation = 0
    @Published private(set) var currentNetwork = ""
    @Published private(set) var now = Date()
    @Published private(set) var message = "等待检测当前环境。"
    @Published private(set) var logs: [DetectorLogEntry] = []
    @Published private(set) var logProblem = ""
    @Published private(set) var website: WebsiteObservation?
    @Published private(set) var websiteProblem = ""
    @Published private(set) var manualRequired = false
    let session = UUID()
    let records: DetectorRecords
    let preferences: MenuBarPreferences
    private let effects: DetectorEffects
    private let monitor = NWPathMonitor()
    private var timer: Timer?
    private var observers: [NSObjectProtocol] = []
    private var contextBusy = false
    private var sleeping = false
    private var rescan = false
    private var lastScan = Date.distantPast
    private var lastNetworkCheck = Date.distantPast
    private var lastNotified: [EnvironmentTarget: EnvironmentRecommendation] = [:]
    private var websiteInvalidated = true
    private var environmentSince: Date
    private var pendingContext = false
    private var lastCLI: UUID?
    private let logQueue = DispatchQueue(label: "claude.detector.records", qos: .utility)

    init(effects: DetectorEffects = DetectorEffects(), records: DetectorRecords = DetectorRecords(),
         startMonitoring: Bool = true, preferences: MenuBarPreferences? = nil) {
        self.preferences = preferences ?? MenuBarPreferences()
        self.effects = effects; self.records = records; now = effects.now(); environmentSince = effects.now()
        do { settings = try effects.settings() }
        catch { readable = false; message = "检测设置不可读，原文件已保留；修复文件后重新检测。" }
        do { logs = Array(try records.logs().suffix(200)) }
        catch { logProblem = "历史日志不可读，原文件已保留。" }
        do { website = try records.website() }
        catch { websiteProblem = "网站记录不可读，原文件已保留。" }
        guard startMonitoring else { return }
        monitor.pathUpdateHandler = { [weak self] _ in Task { @MainActor in self?.pathChanged() } }
        monitor.start(queue: DispatchQueue(label: "claude.detector.network"))
        for event in [NSWorkspace.willSleepNotification, NSWorkspace.didWakeNotification] {
            observers.append(NSWorkspace.shared.notificationCenter.addObserver(forName: event, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.sleepChanged(event == NSWorkspace.willSleepNotification) }
            })
        }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.tick() }
        }
    }
    deinit {
        monitor.cancel(); timer?.invalidate()
        for observer in observers { NSWorkspace.shared.notificationCenter.removeObserver(observer) }
    }
    var overallRecommendation: EnvironmentRecommendation {
        DetectorPresentation.overall(EnvironmentTarget.allCases.map { recommendation($0) })
    }
    var headline: String { busy ? "正在检测" : overallRecommendation.title }
    func recommendation(_ target: EnvironmentTarget) -> EnvironmentRecommendation {
        guard readable else { return .unknown }
        return reports[target]?.recommendation(settings: settings, currentNetwork: currentNetwork, now: now) ?? .unknown
    }
    var websiteRecent: Bool {
        readable && !websiteInvalidated && (website?.observedAt ?? .distantPast) >= environmentSince && website?.isRecent(network: currentNetwork, settings: EnvironmentInspector.configurationFingerprint(settings: settings),
                          session: session, now: now) == true
    }
    func tick() {
        now = effects.now()
        guard !sleeping else { return }
        reloadCLI()
        if now.timeIntervalSince(lastNetworkCheck) >= 2 { refreshContext() }
        if now.timeIntervalSince(lastScan) >= Double(preferences.interval), !busy { detect(manual: false) }
    }
    func pathChanged() {
        if !currentNetwork.isEmpty { invalidate(.networkChanged) }
        refreshContext(force: true)
    }
    func sleepChanged(_ sleeping: Bool) {
        self.sleeping = sleeping; invalidate(.sleepWake)
        if !sleeping { refreshContext(force: true) }
    }
    private func refreshContext(force: Bool = false) {
        guard !sleeping else { return }
        if contextBusy { pendingContext = pendingContext || force; return }
        contextBusy = true; lastNetworkCheck = effects.now()
        let previous = currentNetwork, ticket = generation
        Task {
            let current = await effects.network()
            contextBusy = false
            guard !sleeping else { return }
            guard ticket == generation else { pendingContext = false; refreshContext(force: true); return }
            if !previous.isEmpty, current != currentNetwork { invalidate(.networkChanged) }
            currentNetwork = current
            do {
                let latest = try effects.settings()
                if latest != settings || !readable {
                    settings = latest; readable = true; invalidate(.settingsChanged)
                }
            } catch {
                if readable { invalidate(.settingsChanged) }
                readable = false; message = "检测设置不可读；已保留文件，旧结论失效。"
            }
            if force || previous.isEmpty || previous != current ||
                (reports[.desktop] == nil && effects.now().timeIntervalSince(lastScan) >= Double(preferences.interval)) {
                detect(manual: false)
            }
            if pendingContext { pendingContext = false; refreshContext(force: true) }
        }
    }
    func invalidate(_ reason: DetectorEvent) {
        generation += 1; reports = [:]; now = effects.now(); currentNetwork = ""; websiteInvalidated = true
        environmentSince = now
        message = reason.title
        record(.init(event: reason, at: now))
        if busy { rescan = true }
    }
    func detect(manual: Bool = true) {
        guard manual || preferences.automaticChecks else { return }
        guard !busy, !sleeping else { return }
        do {
            let latest = try effects.settings()
            if latest != settings { settings = latest; invalidate(.settingsChanged) }
            readable = true
        } catch {
            readable = false; reports = [:]; message = "检测设置不可读；请修复后重新检测。"; return
        }
        if manual { manualRequired = false }
        busy = true; rescan = false; lastScan = effects.now()
        let ticket = generation, captured = settings
        Task {
            let initialNetwork = await effects.network()
            if currentNetwork.isEmpty, ticket == generation, !sleeping { currentNetwork = initialNetwork }
            let desktop = await effects.inspect(.desktop, captured)
            let diagnostic = await effects.inspect(.diagnostic, captured)
            let finalNetwork = await effects.network()
            now = effects.now()
            let latest = try? effects.settings()
            let same = ticket == generation && latest == captured && initialNetwork == finalNetwork && !sleeping
            if same {
                currentNetwork = finalNetwork
                // Background sampling observes recovery, but an explicit recheck clears the alert.
                for report in [desktop, diagnostic] {
                    let outcome = report.recommendation(settings: captured, currentNetwork: finalNetwork, now: now)
                    if manual || !manualRequired || outcome != .ready { reports[report.target] = report }
                    log(report)
                    if outcome == .attention, lastNotified[report.target] != outcome, settings.notifications {
                        effects.notify(report.target.title + "发现网络异常，请查看检查详情，处理后重新检测。")
                    }
                    lastNotified[report.target] = outcome
                }
                reloadCLI()
                let outcome = desktop.recommendation(settings: captured, currentNetwork: finalNetwork, now: now)
                if outcome == .attention {
                    manualRequired = true
                }
                message = manualRequired ? "已记录异常；处理完成后点击“重新检测”。" : "本轮检测完成。Claude 由你自行打开。"
            } else {
                reports = [:]; generation += 1; currentNetwork = ""
                record(.init(event: .discarded, at: now)); message = "检查期间环境变化，已忽略旧结果。"
                rescan = !sleeping && latest != nil
            }
            busy = false
            if rescan { rescan = false; detect(manual: false) }
        }
    }
    private func reloadCLI() {
        do {
            if let sample = try effects.cli(), sample.target == .cli {
                reports[.cli] = sample
                if sample.id != lastCLI {
                    lastCLI = sample.id; log(sample)
                    if sample.recommendation(settings: settings, currentNetwork: currentNetwork, now: now) == .attention,
                       settings.notifications { effects.notify("独立 CLI 检测发现异常，请查看检查详情。") }
                }
            }
            else { reports[.cli] = nil }
        } catch { reports[.cli] = nil }
    }
    func save(_ value: EnvironmentSettings) throws {
        guard readable else { throw LauncherError.message("已有设置不可读，未覆盖。") }
        try effects.save(value); settings = try effects.settings(); invalidate(.settingsChanged)
        detect()
    }
    func saveWebsite(at: Date, ip: String, result: WebsiteResult) throws {
        guard readable else { throw LauncherError.message("检测设置不可读；请修复后记录网站检查。") }
        let value = try WebsiteObservation(observedAt: at, observedIP: ip, result: result,
            network: currentNetwork, settings: EnvironmentInspector.configurationFingerprint(settings: settings), session: session, now: effects.now())
        try records.saveWebsite(value); website = value; websiteProblem = ""; websiteInvalidated = false
    }
    private func record(_ entry: DetectorLogEntry) {
        record([entry])
    }
    private func record(_ entries: [DetectorLogEntry]) {
        let records = self.records
        logQueue.async { [weak self] in
            let result = Result { try records.append(entries); return Array(try records.logs().suffix(200)) }
            Task { @MainActor [weak self] in
                switch result {
                case .success(let entries): self?.logs = entries; self?.logProblem = ""
                case .failure: self?.logProblem = "日志无法写入；已有记录保留，当前检测继续。"
                }
            }
        }
    }
    private func log(_ report: EnvironmentReport) {
        let problems = report.checks.filter { $0.required && ($0.result == .failed || $0.result == .unknown) }
        if problems.isEmpty { record(.init(event: .checked, target: report.target, result: .passed, at: report.completedAt)) }
        else {
            record(problems.map { .init(event: .checked, target: report.target, result: $0.result,
                                       problem: .classify($0.code), at: report.completedAt) })
        }
    }
}
