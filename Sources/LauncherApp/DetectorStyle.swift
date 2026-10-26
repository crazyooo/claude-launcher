import SwiftUI
import AppKit
import LauncherCore

/// Shared native palette; follows the Mac appearance without changing system settings.
enum DetectorStyle {
    private static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        func color(_ hex: UInt32) -> NSColor {
            NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
                    green: CGFloat((hex >> 8) & 255) / 255, blue: CGFloat(hex & 255) / 255, alpha: 1)
        }
        return Color(nsColor: NSColor(name: nil) { appearance in
            color(appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light)
        })
    }
    static let canvas = adaptive(0xF2F6F4, 0x171F1C)
    static let sidebar = adaptive(0xE8EFEC, 0x1C2823)
    static let surface = adaptive(0xFCFEFD, 0x202D27)
    static let ink = adaptive(0x273C33, 0xE0EBE5)
    static let muted = adaptive(0x62776D, 0x9DB3A6)
    static let border = adaptive(0xD7E2DC, 0x3A5045)
    static let green = adaptive(0x28664F, 0x89C9A9)
    static let blue = adaptive(0x486F9F, 0x9AB9E0)
    static let amber = adaptive(0x996825, 0xDCB477)
    static let clay = adaptive(0xAC7661, 0xD9AB93)
    static func color(_ state: EnvironmentRecommendation) -> Color {
        switch state { case .ready: return green; case .attention: return amber; case .unknown, .stale: return muted }
    }
    static func symbol(_ state: EnvironmentRecommendation) -> String {
        switch state {
        case .ready: return "checkmark.circle.fill"
        case .attention: return "exclamationmark.circle.fill"
        case .unknown: return "questionmark.circle"
        case .stale: return "clock.arrow.circlepath"
        }
    }
}

struct DetectorActionStyle: ButtonStyle {
    var primary = false
    func makeBody(configuration: ButtonStyleConfiguration) -> some View {
        configuration.label
            .font(.system(size: 13, weight: .semibold))
            .lineLimit(2)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 15).padding(.vertical, 10)
            .foregroundStyle(primary ? Color.white : DetectorStyle.ink)
            .background(primary ? Color(red: 0.16, green: 0.40, blue: 0.31) : DetectorStyle.surface,
                        in: RoundedRectangle(cornerRadius: 8))
            .overlay(RoundedRectangle(cornerRadius: 8).stroke(primary ? Color.clear : DetectorStyle.border))
            .opacity(configuration.isPressed ? 0.72 : 1)
    }
}

struct DetectorStateLabel: View {
    let state: EnvironmentRecommendation
    var body: some View {
        Label(state == .stale ? "记录已失效" : state.title, systemImage: DetectorStyle.symbol(state))
            .font(.system(size: 12, weight: .medium)).foregroundStyle(DetectorStyle.color(state))
    }
}

/// Presentation aggregation only. A successful proxy probe never covers an absent CLI sample.
enum DetectorPresentation {
    static func overall(_ states: [EnvironmentRecommendation]) -> EnvironmentRecommendation {
        if states.contains(.attention) { return .attention }
        if states.isEmpty || states.contains(where: { $0 != .ready }) { return .unknown }
        return .ready
    }
    static func hostState(report: EnvironmentReport?, host: String,
                          recommendation: EnvironmentRecommendation) -> EnvironmentRecommendation {
        guard recommendation != .stale, recommendation != .unknown, let report else { return .unknown }
        let checks = report.checks.filter { $0.id == "route:" + host || $0.id == "exit:" + host || $0.id == "network:" + host }
        guard checks.contains(where: { $0.id == "route:" + host }), checks.contains(where: { $0.id == "exit:" + host }) else { return .unknown }
        if checks.contains(where: { $0.result == .failed }) { return .attention }
        return checks.allSatisfy { $0.result == .passed } ? .ready : .unknown
    }
}
