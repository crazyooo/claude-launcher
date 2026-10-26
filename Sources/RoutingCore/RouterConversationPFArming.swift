import Foundation

/// Conversation-scoped grant for `pf-arming-user-confirm-v1`.
///
/// Issued only after the user explicitly confirmed PF arming in this conversation.
/// This does **not** load packet-filter rules by itself: `RouterPFArmingExecuteGate`
/// may pass while PF side-effects remain unwired (`armed=false` ·
/// `networkModified=false`). Never invents `routing_verified` / `accepted`.
public enum RouterConversationPFArming {
    public static let windowID = RouterPFArmingExecuteGate.confirmationWindowID

    /// Evidence stamp for this conversation grant (not a promotion seal, not a load proof).
    public static let evidence =
        "2026-10-24:user_confirmed_pf-arming-user-confirm-v1;ack_anchor_default_deny;ack_no_auto_stop_longmao;post_exit_reobservation_required"

    /// Live production grant for this conversation.
    public static let liveGrant = RouterPFArmingExecuteGate.ConversationGrant(
        windowID: windowID,
        grantedInConversation: true)

    public static var isGranted: Bool {
        liveGrant.windowID == windowID && liveGrant.grantedInConversation
    }
}
