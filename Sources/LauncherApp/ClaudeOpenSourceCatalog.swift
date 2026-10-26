import SwiftUI
import AppKit
import LauncherCore

/// Curated third-party Claude-related open source projects for the Tools page.
struct ClaudeOpenSourceProject: Identifiable, Sendable {
    let id: String
    let name: String
    let summary: String
    let category: String
    let url: String
}

enum ClaudeOpenSourceCatalog {
    static let projects: [ClaudeOpenSourceProject] = [
        .init(
            id: "macos-claude-failclosed",
            name: "macos-claude-failclosed",
            summary: "macOS 上 Claude 断网 / fail-closed 分层思路参考。",
            category: "断网防护",
            url: "https://github.com/ggllzz04/macos-claude-failclosed"
        ),
        .init(
            id: "claude-desktop-killswitch",
            name: "claude-desktop-killswitch",
            summary: "代理挂掉时防止 Claude Desktop 直连 Anthropic（Windows 防火墙 kill-switch）。",
            category: "断网防护",
            url: "https://github.com/yoruuuchan/claude-desktop-killswitch"
        ),
        .init(
            id: "lid-awake",
            name: "lid-awake",
            summary: "Claude Code 工作时保持 Mac 醒着（含合盖）；会话结束后再允许睡眠。",
            category: "长时间任务",
            url: "https://github.com/LeonMelamud/lid-awake"
        ),
        .init(
            id: "StayAwake",
            name: "StayAwake",
            summary: "菜单栏应用：Claude Code / Codex / Cursor 长跑时保持醒着，可选合盖不睡。",
            category: "长时间任务",
            url: "https://github.com/TY-teo/StayAwake"
        ),
        .init(
            id: "nemuri",
            name: "Nemuri",
            summary: "菜单栏：Claude Code / Codex 工作时醒着，结束后自动恢复睡眠。",
            category: "长时间任务",
            url: "https://github.com/syfssb/nemuri"
        ),
        .init(
            id: "claude-code",
            name: "claude-code",
            summary: "Anthropic 官方 Claude Code（CLI）仓库与议题跟踪。",
            category: "官方与文档",
            url: "https://github.com/anthropics/claude-code"
        ),
        .init(
            id: "claude-code-network",
            name: "Claude Code 网络配置说明",
            summary: "官方网络 / 代理相关文档，便于对照本机检测结论。",
            category: "官方与文档",
            url: "https://code.claude.com/docs/en/network-config"
        ),
    ]

    static var categories: [String] {
        var seen: [String] = []
        for project in projects where !seen.contains(project.category) {
            seen.append(project.category)
        }
        return seen
    }
}

struct ClaudeOpenSourceToolsPanel: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack(alignment: .top, spacing: 16) {
                Image(systemName: "shippingbox")
                    .font(.system(size: 26))
                    .foregroundStyle(DetectorStyle.blue)
                    .frame(width: 58, height: 58)
                    .background(DetectorStyle.blue.opacity(0.08), in: RoundedRectangle(cornerRadius: 16))
                VStack(alignment: .leading, spacing: 8) {
                    Text("Claude 相关开源").font(.system(size: 28, weight: .semibold)).tracking(-0.4)
                    Text("别人的开源项目目录，方便对照学习。不参与本机检测结论，也不由本工具代为安装或运行。")
                        .font(.system(size: 13))
                        .foregroundStyle(DetectorStyle.muted)
                }
            }

            ForEach(ClaudeOpenSourceCatalog.categories, id: \.self) { category in
                DetectorSection(category, icon: icon(for: category)) {
                    ForEach(ClaudeOpenSourceCatalog.projects.filter { $0.category == category }) { project in
                        projectRow(project)
                    }
                }
            }

            Text("可继续往这个列表加项目；保持外链可点、说明诚实即可。")
                .font(.caption)
                .foregroundStyle(DetectorStyle.muted)
        }
    }

    private func icon(for category: String) -> String {
        switch category {
        case "断网防护": return "shield.lefthalf.filled"
        case "长时间任务": return "moon.zzz"
        case "官方与文档": return "doc.text"
        default: return "link"
        }
    }

    private func projectRow(_ project: ClaudeOpenSourceProject) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(project.name).font(.system(size: 14, weight: .semibold))
                Spacer(minLength: 8)
                Button("打开") {
                    guard let url = URL(string: project.url) else { return }
                    NSWorkspace.shared.open(url)
                }
                .buttonStyle(.link)
                Button("复制链接") {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(project.url, forType: .string)
                }
                .buttonStyle(.link)
            }
            Text(project.summary)
                .font(.system(size: 12))
                .foregroundStyle(DetectorStyle.muted)
            Text(project.url)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(DetectorStyle.muted)
                .textSelection(.enabled)
        }
        .padding(.vertical, 4)
    }
}
