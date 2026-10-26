import Foundation

/// Client-side fail-closed gate before GUI→helper hit-correlation IPC.
/// Never authorizes accepted promotion or TUN mutation.
public enum RouterHitCorrelationGate {
    public enum Decision: Equatable, Sendable {
        case allow(instance: UUID)
        case refuse(String)
    }

    public static func decide(arming: RouterHitCorrelationEntry.Arming?,
                              mode: RouterHitCorrelationEntry.Mode,
                              systemPhase: String?,
                              systemInstance: UUID?,
                              refuseOwnTun: Bool?,
                              now: Date = Date()) -> Decision {
        guard let arming else {
            return .refuse("hit_correlation_disarmed")
        }
        guard arming.mode == mode, arming.isValid(now: now) else {
            return .refuse(arming.mode == mode ? "hit_correlation_arming_expired" : "hit_correlation_mode_mismatch")
        }
        if refuseOwnTun == true {
            return .refuse("refuseOwnTun_blocks_live_hit_correlation")
        }
        guard systemPhase == "active", let instance = systemInstance else {
            return .refuse("no_active_system_instance")
        }
        return .allow(instance: instance)
    }
}
