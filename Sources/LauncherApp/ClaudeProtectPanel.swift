import SwiftUI
import AppKit
import LauncherCore

/// Optional Claude fail-closed controls: two primary actions, quieter docs below.
struct ClaudeProtectPanel: View {
    @ObservedObject var model: ClaudeProtectModel
    @State private var confirmEnableBlock = false
    @State private var confirmDisableBlock = false
    @State private var confirmKillCheck = false
    @State private var showGuide = false
    @State private var showAdvanced = false

    var body: some View {
        VStack(alignment: .leading, spacing: DetectorStyle.space * 2.5) {
            header
            statusRow
            blockControl
            watchControl
            DisclosureGroup(isExpanded: $showGuide) {
                guideBody.padding(.top, 10)
            } label: {
                Label("说明与建议", systemImage: "text.alignleft")
                    .font(.system(size: 13, weight: .semibold))
            }
            .padding(14)
            .background(DetectorStyle.surfaceQuiet, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard))
            .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))

            DisclosureGroup(isExpanded: $showAdvanced) {
                advancedBody.padding(.top, 10)
            } label: {
                Label("高级 · 钉死代理地址", systemImage: "doc.badge.gearshape")
                    .font(.system(size: 13, weight: .semibold))
            }
            .padding(14)
            .background(DetectorStyle.surfaceQuiet, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusCard))
            .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusCard).stroke(DetectorStyle.border))

            if model.busy {
                HStack { ProgressView().controlSize(.small); Text(model.operationTitle) }
                    .font(.system(size: 12))
            }
            if !model.refreshMessage.isEmpty {
                Text(model.refreshMessage).font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            }
            if !model.message.isEmpty {
                Text(model.message)
                    .font(.system(size: 12))
                    .foregroundStyle(DetectorStyle.muted)
            }
        }
        .onAppear { model.refresh() }
        .alert("开启「禁止直连」？", isPresented: $confirmEnableBlock) {
            Button("取消", role: .cancel) {}
            Button("开启", role: .destructive) { model.enableL3() }
        } message: {
            Text("通过 macOS 管理员授权后开启。会初始化系统防火墙并加载本工具规则，在物理网卡上拦截 Anthropic 直连；代理客户端保持原样。")
        }
        .alert("关闭「禁止直连」？", isPresented: $confirmDisableBlock) {
            Button("取消", role: .cancel) {}
            Button("关闭", role: .destructive) { model.disableL3() }
        } message: {
            Text("通过 macOS 管理员授权后清除本工具装上的拦截规则。之后 Claude 是否直连，由系统和代理客户端决定。")
        }
        .alert("代理异常时关掉 Claude？", isPresented: $confirmKillCheck) {
            Button("取消", role: .cancel) {}
            Button("检查并执行", role: .destructive) { model.runL4Check(dryRun: false) }
        } message: {
            Text("先看本地代理入口是否健康。若不健康，会尝试关掉当前可见的 Claude Desktop / CLI，并可能弹出通知。不会动其它 App。")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(DetectorStyle.pulse)
                .frame(width: 48, height: 48)
                .background(DetectorStyle.pulseSoft, in: RoundedRectangle(cornerRadius: 14))
            VStack(alignment: .leading, spacing: 6) {
                Text("防 Claude 直连")
                    .font(.system(size: 26, weight: .semibold))
                    .tracking(-0.3)
                Text("可选保险：代理异常时，尽量别让 Claude 悄悄改走直连。")
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
            .disabled(model.refreshing)
        }
    }

    private var statusRow: some View {
        HStack(spacing: 12) {
            statusChip(
                title: "本地代理入口",
                ok: model.l4Healthy,
                text: model.l4Healthy == true ? "正常" : (model.l4Healthy == false ? "异常" : "未知")
            )
            statusChip(
                title: "禁止直连",
                ok: model.l3Armed,
                text: model.l3Armed == true ? "已开启" : (model.l3Armed == false ? "未开启" : "未知")
            )
        }
    }

    private var blockControl: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("禁止直连")
                    .font(.system(size: 15, weight: .semibold))
                Spacer()
                Text("推荐")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(DetectorStyle.pulse)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 4)
                    .background(DetectorStyle.pulseSoft, in: Capsule())
            }
            Text(model.pfSummary)
                .font(.system(size: 13))
            Text("在物理网卡上拦住 Anthropic 直连；本机回环代理入口通常不受影响。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            HStack(spacing: 10) {
                Button("先检查规则") { model.previewL3() }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy)
                Button("开启") { confirmEnableBlock = true }
                    .buttonStyle(DetectorActionStyle(primary: true, emphasis: .protect))
                    .disabled(model.busy || model.mutationOutcomeUnknown)
                Button("关闭") { confirmDisableBlock = true }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy || model.mutationOutcomeUnknown || model.l3Armed != true)
            }
            Text("开关需 macOS 管理员授权；刷新状态免密。")
                .font(.caption)
                .foregroundStyle(DetectorStyle.muted)
            if !model.previewNote.isEmpty {
                Text(model.previewNote)
                    .font(.caption)
                    .foregroundStyle(DetectorStyle.muted)
                    .textSelection(.enabled)
            }
        }
        .detectorCard(.hero)
    }

    private var watchControl: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("代理异常时关掉 Claude")
                .font(.system(size: 15, weight: .semibold))
            Text(model.guardSummary)
                .font(.system(size: 13))
            Text("入口不健康时尝试停 Claude Desktop / CLI，避免裸奔；不动其它 App。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            HStack(spacing: 10) {
                Button("只看一眼（不关进程）") { model.runL4Check(dryRun: true) }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy)
                Button("检查并执行") { confirmKillCheck = true }
                    .buttonStyle(DetectorActionStyle(primary: true, emphasis: .protect))
                    .disabled(model.busy)
            }
        }
        .detectorCard(.regular)
    }

    private var guideBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("1. 先保证自己的代理客户端已开，入口显示正常。")
            Text("2. 需要时开启「禁止直连」，按系统提示授权。")
            Text("3. 可选：代理挂了再执行「关掉 Claude」。")
            Text("会动：Claude 相关进程与 Anthropic 直连拦截。")
            Text("不动：其它 App、代理客户端、整机断网。")
            Text("开启 ≠ 已验证防护成功；上网结论仍以环境检测页为准。")
        }
        .font(.system(size: 12))
        .foregroundStyle(DetectorStyle.muted)
    }

    private var advancedBody: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("把 Claude Desktop / CLI 写死到本地代理入口需改配置，本页不代改。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            Button("复制说明文档路径") {
                copy("docs/claude-protect-l2.md")
            }
            .buttonStyle(.link)
        }
    }

    private func statusChip(title: String, ok: Bool?, text: String) -> some View {
        let symbol: String
        let color: Color
        if ok == true {
            symbol = "checkmark.circle.fill"
            color = DetectorStyle.green
        } else if ok == false {
            symbol = "xmark.circle"
            color = DetectorStyle.pulse
        } else {
            symbol = "questionmark.circle"
            color = DetectorStyle.muted
        }
        return VStack(alignment: .leading, spacing: 6) {
            Text(title).font(.system(size: 12)).foregroundStyle(DetectorStyle.muted)
            Label(text, systemImage: symbol)
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(color)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusChip))
        .overlay(RoundedRectangle(cornerRadius: DetectorStyle.radiusChip).stroke(DetectorStyle.border))
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
