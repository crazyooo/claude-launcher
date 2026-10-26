import SwiftUI
import AppKit
import LauncherCore

/// Optional Claude fail-closed controls, explained in plain product language.
struct ClaudeProtectPanel: View {
    @ObservedObject var model: ClaudeProtectModel
    @State private var confirmEnableBlock = false
    @State private var confirmDisableBlock = false
    @State private var confirmKillCheck = false

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header
            purposeCard
            statusRow
            recommendCard
            blockSection
            watchSection
            pinSection
            limitsCard

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
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "shield.lefthalf.filled")
                .font(.system(size: 26))
                .foregroundStyle(DetectorStyle.green)
                .frame(width: 58, height: 58)
                .background(DetectorStyle.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
            VStack(alignment: .leading, spacing: 8) {
                Text("防 Claude 直连").font(.system(size: 28, weight: .semibold)).tracking(-0.4)
                Text("可选功能：代理挂了时，尽量别让 Claude 悄悄改走直连。先弄清「它干什么」，再动手。")
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
            }
            Spacer()
            Button {
                model.refresh()
            } label: {
                Label(model.refreshing ? "刷新中…" : "刷新", systemImage: "arrow.clockwise")
            }
            .buttonStyle(DetectorActionStyle(primary: true))
            .disabled(model.refreshing)
        }
    }

    private var purposeCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("它解决什么问题").font(.system(size: 14, weight: .semibold))
            Text("你平时用自己的代理客户端上 Claude。一旦代理断了，Claude 有时会自己直连官方——账号风险、地区暴露都可能变。本页只给 Claude 加两道可选保险，不接管整机网络。")
                .font(.system(size: 13))
                .foregroundStyle(DetectorStyle.ink)
            VStack(alignment: .leading, spacing: 6) {
                Label("会动：Claude 相关进程、以及通往 Anthropic 的直连拦截", systemImage: "checkmark.circle")
                Label("不动：其它 App、你的代理客户端/系统分流、整机断网", systemImage: "xmark.circle")
            }
            .font(.system(size: 12))
            .foregroundStyle(DetectorStyle.muted)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
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

    private var recommendCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("建议怎么用").font(.system(size: 14, weight: .semibold))
            Text("1. 先保证你自己的代理客户端已开，本地入口正常（上面「本地代理入口」为正常）。")
            Text("2. 需要时开启「禁止直连」，按 macOS 提示进行管理员授权。")
            Text("3. 可选：点「代理异常时关掉 Claude」做一次检查；代理挂了就先停 Claude，避免裸奔。")
            Text("4. 「钉死代理地址」仍是高级手动项，本页不代你改配置文件。")
        }
        .font(.system(size: 13))
        .foregroundStyle(DetectorStyle.ink)
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private var blockSection: some View {
        DetectorSection("禁止直连（推荐）", icon: "firewall") {
            Text(model.pfSummary)
                .font(.callout)
            Text("含义：在 Wi‑Fi / 有线等物理网卡上，拦住通往 Anthropic 网段的直连。走本机回环代理入口（如 127.0.0.1:端口）一般不受影响。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            VStack(alignment: .leading, spacing: 10) {
                Button("先检查规则") { model.previewL3() }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy)
                HStack(alignment: .top, spacing: 10) {
                    Button("开启禁止直连") { confirmEnableBlock = true }
                        .buttonStyle(DetectorActionStyle(primary: true))
                        .disabled(model.busy || model.mutationOutcomeUnknown)
                    Button("关闭禁止直连") { confirmDisableBlock = true }
                        .buttonStyle(DetectorActionStyle())
                        .disabled(model.busy || model.mutationOutcomeUnknown || model.l3Armed != true)
                }
            }
            Text("开关防护使用 macOS 管理员授权，当前可能需要输入密码；刷新状态无需密码。")
                .font(.caption).foregroundStyle(.secondary)
            if !model.previewNote.isEmpty {
                Text(model.previewNote)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    private var watchSection: some View {
        DetectorSection("代理异常时关掉 Claude（可选）", icon: "antenna.radiowaves.left.and.right") {
            Text(model.guardSummary)
                .font(.callout)
            Text("含义：看本地代理入口还在不在。不在了，就尝试停掉当前 Claude，避免它改走直连。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            VStack(alignment: .leading, spacing: 10) {
                Button("只看一眼（不关进程）") { model.runL4Check(dryRun: true) }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy)
                Button("检查并执行（代理异常时关 Claude）") { confirmKillCheck = true }
                    .buttonStyle(DetectorActionStyle())
                    .disabled(model.busy)
            }
        }
    }

    private var pinSection: some View {
        DetectorSection("钉死代理地址（高级 · 手动）", icon: "doc.badge.gearshape") {
            Text("把 Claude Desktop / CLI 写死到你的本地代理入口，需要改配置文件，本页不代改。")
                .font(.callout)
            Button("复制说明文档路径") {
                copy("docs/claude-protect-l2.md")
            }
            .buttonStyle(.link)
        }
    }

    private var limitsCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("请把期望放对").font(.system(size: 14, weight: .semibold))
            Text("· 这不是「整机断网」，也不是替你开/关任何代理客户端。")
            Text("· 开启后也不能保证 100% 防护；界面不会显示「已验证防护成功」。")
            Text("· 真正上网是否正常，仍以「环境检测」页结论为准。")
        }
        .font(.system(size: 12))
        .foregroundStyle(DetectorStyle.muted)
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private func statusChip(title: String, ok: Bool?, text: String) -> some View {
        let symbol: String
        let color: Color
        if ok == true {
            symbol = "checkmark.circle.fill"
            color = DetectorStyle.green
        } else if ok == false {
            symbol = "xmark.circle"
            color = DetectorStyle.amber
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
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(DetectorStyle.border))
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

