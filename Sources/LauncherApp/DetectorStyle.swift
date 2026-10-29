import SwiftUI
import AppKit
import LauncherCore

/// Brand-aligned palette from the app icon: forest green, cream type, pulse coral.
/// Follows Mac appearance; does not change system settings.
enum DetectorStyle {
    private static func adaptive(_ light: UInt32, _ dark: UInt32) -> Color {
        func color(_ hex: UInt32) -> NSColor {
            NSColor(srgbRed: CGFloat((hex >> 16) & 255) / 255,
                    green: CGFloat((hex >> 8) & 255) / 255,
                    blue: CGFloat(hex & 255) / 255,
                    alpha: 1)
        }
        return Color(nsColor: NSColor(name: nil) { appearance in
            color(appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light)
        })
    }

    // Surfaces — light: mint-cream paper; dark: deep forest.
    static let canvas = adaptive(0xF4F7F4, 0x0E1C16)
    static let sidebar = adaptive(0xE7EFE9, 0x13241C)
    static let surface = adaptive(0xFBFCFB, 0x183028)
    static let surfaceQuiet = adaptive(0xF0F4F1, 0x14271F)
    static let ink = adaptive(0x1A2E24, 0xF0EBE3)
    static let muted = adaptive(0x5F7468, 0x8FA898)
    static let border = adaptive(0xD2DED6, 0x2B5343)
    static let borderStrong = adaptive(0xB7C9BD, 0x3A6B56)

    // Accents — one health green + one protect/warn pulse (icon waveform).
    static let green = adaptive(0x1F5C42, 0x7EC8A3)
    static let greenSoft = adaptive(0xE6F1EB, 0x1C4032)
    static let pulse = adaptive(0xC56A3E, 0xE8A070)
    static let pulseSoft = adaptive(0xF6E8DF, 0x3A2A22)
    static let amber = pulse
    static let clay = adaptive(0xA85B48, 0xD9AB93)
    static let blue = green // legacy call sites; single accent family

    static let radiusHero: CGFloat = 18
    static let radiusCard: CGFloat = 14
    static let radiusChip: CGFloat = 10
    static let space: CGFloat = 8

    static func color(_ state: EnvironmentRecommendation) -> Color {
        switch state {
        case .ready: return green
        case .attention: return pulse
        case .unknown, .stale: return muted
        }
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
    var emphasis: Emphasis = .neutral

    enum Emphasis { case neutral, protect }

    func makeBody(configuration: ButtonStyleConfiguration) -> some View {
        let fill: Color = {
            if !primary { return DetectorStyle.surface }
            return emphasis == .protect ? DetectorStyle.pulse : DetectorStyle.green
        }()
        let foreground: Color = primary ? Color.white : DetectorStyle.ink
        return configuration.label
            .font(.system(size: 13, weight: .semibold))
            .lineLimit(2)
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: true, vertical: false)
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
            .foregroundStyle(foreground)
            .background(fill, in: RoundedRectangle(cornerRadius: DetectorStyle.radiusChip))
            .overlay(
                RoundedRectangle(cornerRadius: DetectorStyle.radiusChip)
                    .stroke(primary ? Color.clear : DetectorStyle.border)
            )
            .opacity(configuration.isPressed ? 0.78 : 1)
    }
}

struct DetectorStateLabel: View {
    let state: EnvironmentRecommendation
    var body: some View {
        Label(state == .stale ? "记录已失效" : state.title, systemImage: DetectorStyle.symbol(state))
            .font(.system(size: 12, weight: .medium))
            .foregroundStyle(DetectorStyle.color(state))
    }
}

/// Shared chrome: hero = elevated verdict; quiet = secondary blocks.
struct DetectorCardModifier: ViewModifier {
    enum Rank { case hero, regular, quiet }
    var rank: Rank = .regular

    func body(content: Content) -> some View {
        let radius = rank == .hero ? DetectorStyle.radiusHero : DetectorStyle.radiusCard
        let fill = rank == .quiet ? DetectorStyle.surfaceQuiet : DetectorStyle.surface
        let stroke = rank == .hero ? DetectorStyle.borderStrong : DetectorStyle.border
        return content
            .padding(rank == .hero ? 22 : 16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(fill, in: RoundedRectangle(cornerRadius: radius))
            .overlay(RoundedRectangle(cornerRadius: radius).stroke(stroke, lineWidth: rank == .hero ? 1.2 : 1))
    }
}

extension View {
    func detectorCard(_ rank: DetectorCardModifier.Rank = .regular) -> some View {
        modifier(DetectorCardModifier(rank: rank))
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
