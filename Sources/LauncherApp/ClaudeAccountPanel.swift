import SwiftUI

/// Desktop A–D switching. First-run is one CTA; afterwards a 2×2 account grid.
struct ClaudeAccountPanel: View {
    @ObservedObject var model: ClaudeAccountModel
    @State private var confirmSwitchTo: String?
    @State private var confirmSaveCurrent = false
    @State private var showGuide = false

    /// Logged-in Desktop data exists, but no slot is registered yet.
    private var needsFirstSave: Bool { model.current == nil && model.liveExists }

    var body: some View {
        VStack(alignment: .leading, spacing: DetectorStyle.space * 2.5) {
            header
            if needsFirstSave {
                firstSaveCard
            } else {
                readyBody
            }

            DisclosureGroup(isExpanded: $showGuide) {
                guideBody.padding(.top, 10)
            } label: {
                Label("说明", systemImage: "text.alignleft")
                    .font(.system(size: 13, weight: .semibold))
            }
            .padding(14)
            .background(DetectorStyle.surfaceQuiet, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard))
            .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))

            if model.busy {
                HStack {
                    ProgressView().controlSize(.small)
                    Text(model.operationTitle)
                }
                .font(.system(size: 12))
            }
            if !model.message.isEmpty {
                Text(model.message)
                    .font(.system(size: 12))
                    .foregroundStyle(DetectorStyle.muted)
            }
        }
        .onAppear { model.refresh() }
        .alert("保存当前登录为账号 A？", isPresented: $confirmSaveCurrent) {
            Button("取消", role: .cancel) {}
            Button("保存") { model.adoptCurrent(as: "A") }
        } message: {
            Text(model.desktopRunning
                 ? "会先退出 Claude Desktop，把你现在的登录存成账号 A。之后还有 B / C / D 三个空位。"
                 : "把你现在的登录存成账号 A。之后还有 B / C / D 三个空位。")
        }
        .alert(switchTitle, isPresented: Binding(
            get: { confirmSwitchTo != nil },
            set: { if !$0 { confirmSwitchTo = nil } }
        )) {
            Button("取消", role: .cancel) { confirmSwitchTo = nil }
            Button(switchConfirmLabel, role: .destructive) {
                if let slot = confirmSwitchTo { model.switchTo(slot) }
                confirmSwitchTo = nil
            }
        } message: {
            Text(switchMessage)
        }
    }

    private var switchTitle: String {
        guard let slot = confirmSwitchTo else { return "切换账号？" }
        if model.slots.first(where: { $0.name == slot })?.hasArchive == true {
            return "切换到账号 \(slot)？"
        }
        return "开始账号 \(slot)？"
    }

    private var switchConfirmLabel: String {
        guard let slot = confirmSwitchTo,
              model.slots.first(where: { $0.name == slot })?.hasArchive == true else {
            return "开始"
        }
        return "切换"
    }

    private var switchMessage: String {
        guard let slot = confirmSwitchTo else { return "" }
        let hasArchive = model.slots.first(where: { $0.name == slot })?.hasArchive == true
        var lines: [String] = []
        if hasArchive {
            lines.append("会退出 Claude Desktop，换到账号 \(slot) 的登录。")
        } else {
            lines.append("会先保存当前登录，再换成空白桌面。打开 Claude 后登录新账号即可。")
        }
        if model.openAfterSwitch {
            lines.append("切换后会尝试打开 Claude。")
        } else {
            lines.append("切换后请自己打开 Claude。")
        }
        return lines.joined(separator: "\n")
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "person.2.crop.square.stack")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(DetectorStyle.green)
                .frame(width: 48, height: 48)
                .background(DetectorStyle.greenSoft, in: RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 6) {
                Text("Desktop 账号")
                    .font(.system(size: 26, weight: .semibold))
                    .tracking(-0.3)
                Text("最多四个登录来回切，不用反复登出登入。")
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
            }
            Spacer()
            Button {
                model.refresh()
            } label: {
                Label(model.refreshing ? "刷新中…" : "刷新", systemImage: "arrow.clockwise")
            }
            .buttonStyle(DetectorActionStyle())
            .disabled(model.refreshing || model.busy)
        }
    }

    /// One-step onboarding when Desktop already has a login.
    private var firstSaveCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("检测到 Claude Desktop 已登录")
                .font(.system(size: 16, weight: .semibold))
            if model.liveIdentity.hasDisplay {
                identityBlock(model.liveIdentity, emphasize: true)
            }
            Text(model.desktopRunning
                 ? "先把它存成账号 A，之后还能再加 B / C / D。保存时会短暂退出 Desktop。"
                 : "先把它存成账号 A，之后还能再加 B / C / D。")
                .font(.system(size: 13))
                .foregroundStyle(DetectorStyle.muted)
            Button {
                confirmSaveCurrent = true
            } label: {
                Text("把当前登录存为账号 A")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(DetectorActionStyle(primary: true))
            .disabled(model.busy)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard))
        .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))
    }

    private var readyBody: some View {
        VStack(alignment: .leading, spacing: DetectorStyle.space * 2) {
            HStack(alignment: .firstTextBaseline) {
                Text(statusLine)
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
                Spacer()
                Button {
                    model.refreshUsage()
                } label: {
                    Label("刷新额度", systemImage: "chart.bar")
                }
                .buttonStyle(DetectorActionStyle())
                .disabled(model.busy || model.current == nil)
                .help("读取当前账号的订阅类型与用量；免费账号也可刷新。首次可能要求钥匙串授权。")
            }

            LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                ForEach(model.slots) { slot in
                    slotCard(slot)
                }
            }

            Toggle("切换后打开 Claude", isOn: $model.openAfterSwitch)
                .toggleStyle(.switch)
                .font(.system(size: 13))
            Text("额度来自 Anthropic 接口；未升级 Pro 也会显示 Free。本地没有令牌时，请先打开 Claude 并退出一次后再刷新。")
                .font(.system(size: 11))
                .foregroundStyle(DetectorStyle.muted)
        }
    }

    private var statusLine: String {
        if let current = model.current {
            let running = model.desktopRunning ? "· Desktop 运行中" : ""
            if let label = model.slots.first(where: { $0.name == current })?.identity.label
                ?? model.liveIdentity.label {
                return "正在用账号 \(current)（\(label)） \(running)".trimmingCharacters(in: .whitespaces)
            }
            return "正在用账号 \(current) \(running)".trimmingCharacters(in: .whitespaces)
        }
        if model.liveExists {
            return "本机有登录，但还没存档。"
        }
        return "还没有 Desktop 登录。打开 Claude 登录一次后再回来。"
    }

    private func slotCard(_ slot: ClaudeAccountSlot) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text("账号 \(slot.name)")
                    .font(.system(size: 18, weight: .bold))
                Spacer()
                Text(slotLabel(slot))
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(slot.isCurrent ? Color.white.opacity(0.9) : DetectorStyle.muted)
            }
            if slot.identity.hasDisplay {
                identityBlock(slot.identity, emphasize: slot.isCurrent)
            } else if slot.hasArchive || slot.isCurrent {
                Text("已保存登录，暂未读到邮箱/名称")
                    .font(.system(size: 12))
                    .foregroundStyle(slot.isCurrent ? Color.white.opacity(0.8) : DetectorStyle.muted)
            } else {
                Text("空位")
                    .font(.system(size: 12))
                    .foregroundStyle(DetectorStyle.muted)
            }
            if slot.usage.hasDisplay {
                usageBlock(slot.usage, emphasize: slot.isCurrent)
            } else if slot.hasArchive || slot.isCurrent {
                Text("订阅/额度未刷新")
                    .font(.system(size: 11))
                    .foregroundStyle(slot.isCurrent ? Color.white.opacity(0.7) : DetectorStyle.muted)
            }
            Spacer(minLength: 0)
            if slot.isCurrent {
                Text("当前使用中")
                    .font(.system(size: 13, weight: .semibold))
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 10)
            } else {
                Button {
                    confirmSwitchTo = slot.name
                } label: {
                    Text(slot.hasArchive ? "切换到这个" : "登录新账号")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(DetectorActionStyle(primary: true))
                .disabled(model.busy)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .leading)
        .background(
            slot.isCurrent ? DetectorStyle.green : DetectorStyle.surface,
            in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard)
        )
        .foregroundStyle(slot.isCurrent ? Color.white : DetectorStyle.ink)
        .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))
    }

    @ViewBuilder
    private func identityBlock(_ identity: ClaudeAccountIdentity, emphasize: Bool) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            if let label = identity.label, !label.isEmpty {
                Text(label)
                    .font(.system(size: 14, weight: .semibold))
            }
            if let email = identity.email, !email.isEmpty {
                Text(email)
                    .font(.system(size: 12))
                    .foregroundStyle(emphasize ? Color.white.opacity(0.85) : DetectorStyle.muted)
                    .lineLimit(1)
            }
            if let organization = identity.organization, !organization.isEmpty {
                Text(organization)
                    .font(.system(size: 11))
                    .foregroundStyle(emphasize ? Color.white.opacity(0.75) : DetectorStyle.muted)
                    .lineLimit(2)
            }
        }
    }

    @ViewBuilder
    private func usageBlock(_ usage: ClaudeAccountUsage, emphasize: Bool) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("订阅 \(usage.planLabel)")
                .font(.system(size: 12, weight: .semibold))
            if let session = usage.sessionPercent {
                Text(String(format: "会话 %.0f%%", session)
                    + (usage.sessionResets.map { " · 重置 \($0)" } ?? ""))
                    .font(.system(size: 11))
                    .foregroundStyle(emphasize ? Color.white.opacity(0.8) : DetectorStyle.muted)
                    .lineLimit(1)
            }
            if let week = usage.weekPercent {
                Text(String(format: "本周 %.0f%%", week)
                    + (usage.weekResets.map { " · 重置 \($0)" } ?? ""))
                    .font(.system(size: 11))
                    .foregroundStyle(emphasize ? Color.white.opacity(0.8) : DetectorStyle.muted)
                    .lineLimit(1)
            }
        }
        .padding(.top, 2)
    }

    private func slotLabel(_ slot: ClaudeAccountSlot) -> String {
        if slot.isCurrent { return "当前" }
        if slot.hasArchive { return "已保存" }
        return "空位"
    }

    private var guideBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("1. 把现在的登录存成 A")
            Text("2. 点空位「登录新账号」，打开 Claude 登录另一个（最多 A–D）")
            Text("3. 点「刷新额度」查看订阅与用量（Free / Pro 都可以）")
            Text("切换前会退出 Desktop；默认不自动打开。")
        }
        .font(.system(size: 12))
        .foregroundStyle(DetectorStyle.muted)
    }
}
