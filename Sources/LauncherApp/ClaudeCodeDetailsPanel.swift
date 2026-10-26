import SwiftUI
import AppKit
import LauncherCore

/// 「检查详情」主内容：围绕 Net.Coffee Claude Code 稳定使用指南，供对照自查。
struct ClaudeCodeDetailsPanel: View {
    @ObservedObject var model: EnvironmentModel
    @State private var selected = EnvironmentTarget.desktop

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            header
            summaryCard
            ForEach(Self.checklist) { item in
                checklistRow(item)
            }
            relatedLinks
            localProbeSection
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 16) {
            Image(systemName: "checklist")
                .font(.system(size: 26))
                .foregroundStyle(DetectorStyle.green)
                .frame(width: 58, height: 58)
                .background(DetectorStyle.green.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
            VStack(alignment: .leading, spacing: 8) {
                Text("检查详情").font(.system(size: 28, weight: .semibold)).tracking(-0.4)
                Text("对照 Claude Code 稳定使用要点自查。完整原文在 Net.Coffee；本页是摘要清单，不替代原文，也不等于本机检测已通过。")
                    .font(.system(size: 13))
                    .foregroundStyle(DetectorStyle.muted)
            }
            Spacer(minLength: 12)
            Button {
                open(NetCoffeeDetection.claudeCodeGuide.url)
            } label: {
                Label("打开原文", systemImage: "safari")
            }
            .buttonStyle(DetectorActionStyle(primary: true))
        }
    }

    private var summaryCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("一句话").font(.system(size: 14, weight: .semibold))
            Text("网络看起来越像普通家庭用户，Claude Code 通常越稳。优先管好：出口 IP、DNS、IPv6、固定分流、路径别绕。")
                .font(.system(size: 13))
            Text("来源：\(NetCoffeeDetection.claudeCodeGuide.rawValue)")
                .font(.system(size: 11))
                .foregroundStyle(DetectorStyle.muted)
            Text(NetCoffeeDetection.claudeCodeGuide.url)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(DetectorStyle.muted)
                .textSelection(.enabled)
        }
        .padding(18)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(DetectorStyle.surface, in: RoundedRectangle(cornerRadius: 14))
        .overlay(RoundedRectangle(cornerRadius: 14).stroke(DetectorStyle.border))
    }

    private func checklistRow(_ item: GuideItem) -> some View {
        DetectorSection("\(item.index). \(item.title)", icon: item.icon) {
            Text(item.body)
                .font(.system(size: 13))
            if let tip = item.tip {
                Text(tip)
                    .font(.system(size: 12))
                    .foregroundStyle(DetectorStyle.muted)
            }
            if let link = item.link {
                Button(link.label) { open(link.url) }
                    .buttonStyle(.link)
            }
        }
    }

    private var relatedLinks: some View {
        DetectorSection("相关在线检查（可选）", icon: "link") {
            Text("需要时打开站点自测；结果由你判断，不自动写回本机结论。")
                .font(.caption)
                .foregroundStyle(.secondary)
            Button("Net.Coffee · Claude 环境检测") {
                open(NetCoffeeDetection.claude.url)
            }
            .buttonStyle(.link)
            Button("IPSuper · Claude 环境检测") {
                open(IPSuperDetection.claude.url)
            }
            .buttonStyle(.link)
        }
    }

    private var localProbeSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("本机探针（次要）")
                .font(.system(size: 16, weight: .semibold))
            Text("下面是本工具对 Desktop / CLI / 诊断路径的 HTTPS 采样，供对照；已知部分域名可能 tls_failed，详见检测债备注。主内容仍是上方稳定使用清单。")
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)

            Picker("检测对象", selection: $selected) {
                ForEach(EnvironmentTarget.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)

            Text(model.recommendation(selected).detail)
                .font(.callout)
                .foregroundStyle(.secondary)

            if selected == .cli { CLIDetectionCommand() }

            if let report = model.reports[selected] {
                ForEach(report.checks.filter { $0.required && ($0.result == .failed || $0.result == .unknown) }.prefix(8)) { check in
                    DetectorSection(check.title, icon: "exclamationmark.circle") {
                        Text(resultLabel(check.result) + " · " + check.code)
                            .font(.caption.monospaced())
                        Text(check.detail)
                        Text(EnvironmentGuidance.advice(for: check.code))
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
                if report.checks.filter({ $0.required && ($0.result == .failed || $0.result == .unknown) }).isEmpty {
                    Text("本对象本轮必查项无失败/未知记录（或尚未测全）。")
                        .foregroundStyle(.secondary)
                }
            } else {
                Text("尚未取得该对象的本机检查记录；可先回「环境检测」点一键检测。")
                    .foregroundStyle(.secondary)
            }
        }
    }

    private func open(_ urlString: String) {
        guard let url = URL(string: urlString) else { return }
        NSWorkspace.shared.open(url)
    }
}

private struct GuideItem: Identifiable {
    let id: Int
    var index: Int { id }
    let title: String
    let icon: String
    let body: String
    let tip: String?
    let link: (label: String, url: String)?
}

private extension ClaudeCodeDetailsPanel {
    /// 摘要自 Net.Coffee Claude Code 稳定使用指南；非原文照抄。
    static let checklist: [GuideItem] = [
        .init(
            id: 1,
            title: "出口 IP（最核心）",
            icon: "globe",
            body: "优先家宽 / 干净原生 IP；尽量避开脏数据中心段和大量共享出口。IP 质量往往比「能不能连上」更决定稳定性。",
            tip: "不确定就用站点做一次 Claude IP / 环境检测。",
            link: (label: "打开 Net.Coffee Claude 检测", url: NetCoffeeDetection.claude.url)
        ),
        .init(
            id: 2,
            title: "IP 稳定性要符合类型",
            icon: "arrow.triangle.2.circlepath",
            body: "家宽动态换 IP 通常正常；机房 / 数据中心出口应尽量固定，频繁切换更容易被当成异常。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 3,
            title: "强制 TCP，少依赖 UDP",
            icon: "cable.connector",
            body: "Claude Code 本质是 HTTPS/TCP。UDP（含 QUIC）更容易不稳或绕过规则，也要当心 WebRTC 等泄露。",
            tip: "代理里可强制 network=tcp 一类设置（以你的客户端为准）。",
            link: nil
        ),
        .init(
            id: 4,
            title: "TLS 指纹尽量像浏览器",
            icon: "lock.shield",
            body: "部分代理默认握手不像浏览器，可能被当成非正常客户端。有条件时模拟常见浏览器指纹。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 5,
            title: "DNS 必须走代理",
            icon: "server.rack",
            body: "出口在海外、DNS 却打本地，地域不一致容易触发风控。优先代理内 DoH / 加密 DNS。",
            tip: "可另做 DNS 泄露自测。",
            link: nil
        ),
        .init(
            id: 6,
            title: "禁用 IPv6（代理场景）",
            icon: "network",
            body: "代理环境下 IPv6 常导致分流失效、泄露或抖动。客户端侧尽量关 IPv6 / 只用 IPv4。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 7,
            title: "Claude 单独分流",
            icon: "arrow.branch",
            body: "为 api.anthropic.com、claude.ai 等单独建规则；Code 运行时还有 CDN/认证等域名，漏一条都可能偏航。",
            tip: "配完用分流测试核对是否走指定出口。",
            link: nil
        ),
        .init(
            id: 8,
            title: "不要靠笼统智能分流顶上",
            icon: "exclamationmark.triangle",
            body: "通配海外规则可能把 Claude 分到不同节点甚至直连。Claude 规则优先级应高于通用规则。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 9,
            title: "保持连接复用",
            icon: "link",
            body: "频繁短连接更像机器行为，也更慢。代理侧尽量 keep-alive / 连接复用，少反复断开重连。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 10,
            title: "控制并发",
            icon: "square.stack.3d.up",
            body: "同一出口上堆太多并行任务，更容易限速。单 IP 并发建议压低；要更高吞吐再考虑多出口。",
            tip: nil,
            link: nil
        ),
        .init(
            id: 11,
            title: "路径短且干净",
            icon: "point.topleft.down.to.point.bottomright.curvepath",
            body: "亚洲→亚洲或合理直达北美通常更好；大绕路（例如亚洲→欧洲→北美）更易抖。",
            tip: "原文总结：IP + DNS + 路径 + 一致性。",
            link: (label: "打开完整指南", url: NetCoffeeDetection.claudeCodeGuide.url)
        ),
    ]
}
