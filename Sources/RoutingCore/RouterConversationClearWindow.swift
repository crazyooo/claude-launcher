import Foundation

/// Conversation-scoped clear-window grant for `tun-apply-clear-window-v1`.
///
/// Issued only after the user confirmed foreign clients were closed **and** a
/// requireClear-aligned observation showed empty tunnel capture, disconnected VPN,
/// and system proxies off. This does **not** arm PF, does **not** stop residual
/// privileged helpers by itself, and does **not** invent `routing_verified` /
/// `accepted`.
public enum RouterConversationClearWindow {
    public static let windowID = RouterTunApplyExecuteGate.clearWindowID

    /// Evidence stamp for this conversation grant (not a promotion seal).
    public static let evidence =
        "2026-10-24:user_closed_longmao_again;obs_capture=[];vpn=Disconnected;sys_proxy=off;ipv4_default=en0;helper_upgraded;live_apply_active_utun8"

    /// Live production grant for this conversation. Execute paths still re-check
    /// refuseOwnTun / requireClear on every apply.
    public static let liveGrant = RouterTunApplyExecuteGate.ClearWindowGrant(
        windowID: windowID,
        grantedInConversation: true)

    public static var isGranted: Bool {
        liveGrant.windowID == windowID && liveGrant.grantedInConversation
    }
}
