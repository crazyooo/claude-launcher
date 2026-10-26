import Foundation

/// Production TUN **apply** gate: sealed takeover preview → guarded arming →
/// explicit UI confirm → post-confirm re-observation.
///
/// Refuses when a foreign tunnel / `refuseOwnTun` / `requireClear` failure is present,
/// or when the conversation clear-window grant (`tun-apply-clear-window-v1`) is absent.
/// On `.allow`, optional `SideEffects.enableOwnTun` may run; without it the gate still
/// passes but `tunEffectsWired=false` and no network mutation occurs.
/// Never stops 你的代理客户端/小火箭/system VPN from this gate. Never invents
/// `routing_verified` / `accepted` / `canPromoteAccepted`.
public enum RouterTunApplyExecuteGate {
    public static let policyVersion = 2
    public static let clearWindowID = "tun-apply-clear-window-v1"

    /// Injectable TUN enable hook. Production live UI passes `nil` until clear is proven
    /// and a conversation grant is set; tests inject a recorder.
    public struct SideEffects: Sendable {
        public struct Outcome: Equatable, Sendable {
            public let networkModified: Bool
            public let tunEnabled: Bool
            public let foreignComponentsStopped: Bool
            public let journalMutated: Bool
            public let detail: String

            public init(networkModified: Bool, tunEnabled: Bool,
                        foreignComponentsStopped: Bool = false,
                        journalMutated: Bool = false, detail: String) {
                self.networkModified = networkModified
                self.tunEnabled = tunEnabled
                self.foreignComponentsStopped = foreignComponentsStopped
                self.journalMutated = journalMutated
                self.detail = detail
            }
        }

        public var enableOwnTun: (@Sendable (Preview) throws -> Outcome)?

        public init(enableOwnTun: (@Sendable (Preview) throws -> Outcome)? = nil) {
            self.enableOwnTun = enableOwnTun
        }

        public static let unwired = SideEffects(enableOwnTun: nil)
    }

    public struct Dimension: Equatable, Sendable {
        public let name: String
        public let status: String
        public let detail: String
    }

    public struct Preview: Equatable, Sendable {
        public let id: UUID
        public let planDigest: String
        public let manifestDigest: String
        public let bullets: [String]
        public let issuedAt: Date
        public let expiresAt: Date
        public let dimensions: [Dimension]
        public let routingVerified: Bool
        public let accepted: Bool
        public let wouldEnableTunIfApplied: Bool
        public let summary: String

        public func isFresh(now: Date = Date()) -> Bool {
            now >= issuedAt && now < expiresAt
        }
    }

    public struct Arming: Equatable, Sendable {
        public enum Kind: Equatable, Sendable {
            case productionPreviewOnly
            case productionGuardedApply
        }

        public let id: UUID
        public let kind: Kind
        public let previewID: UUID
        public let issuedAt: Date
        public let expiresAt: Date

        public func isValid(now: Date = Date()) -> Bool {
            now >= issuedAt && now < expiresAt
        }
    }

    public struct Confirmation: Equatable, Sendable {
        public let previewID: UUID
        public let confirmedAt: Date
        public let explicitUIConfirm: Bool

        public init(previewID: UUID, confirmedAt: Date = Date(), explicitUIConfirm: Bool) {
            self.previewID = previewID
            self.confirmedAt = confirmedAt
            self.explicitUIConfirm = explicitUIConfirm
        }
    }

    public struct Observation: Equatable, Sendable {
        public let refuseOwnTun: Bool?
        public let requireClearWouldPass: Bool?
        public let foreignTunnelPresent: Bool?
        public let systemPhase: String?
        public let observedAt: Date
        public let fingerprint: String?

        public init(refuseOwnTun: Bool?, requireClearWouldPass: Bool?,
                    foreignTunnelPresent: Bool? = nil, systemPhase: String?,
                    observedAt: Date = Date(), fingerprint: String? = nil) {
            self.refuseOwnTun = refuseOwnTun
            self.requireClearWouldPass = requireClearWouldPass
            self.foreignTunnelPresent = foreignTunnelPresent
            self.systemPhase = systemPhase
            self.observedAt = observedAt
            self.fingerprint = fingerprint
        }

        public var foreignTunnelLikely: Bool {
            if foreignTunnelPresent == true { return true }
            return refuseOwnTun == true || requireClearWouldPass == false
        }
    }

    /// Conversation-scoped clear-window grant. Not issued in this product session.
    public struct ClearWindowGrant: Equatable, Sendable {
        public let windowID: String
        public let grantedInConversation: Bool

        public init(windowID: String = RouterTunApplyExecuteGate.clearWindowID,
                    grantedInConversation: Bool) {
            self.windowID = windowID
            self.grantedInConversation = grantedInConversation
        }

        public static let none = ClearWindowGrant(grantedInConversation: false)
    }

    public enum Decision: Equatable, Sendable {
        case allow
        case refuse(String)
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let previewID: UUID
        public let decision: Decision
        public let executed: Bool
        public let networkModified: Bool
        public let tunEnabled: Bool
        public let tunEffectsWired: Bool
        public let foreignComponentsStopped: Bool
        public let journalMutated: Bool
        public let routingVerified: Bool
        public let accepted: Bool
        public let canPromoteAccepted: Bool
        public let dimensions: [Dimension]
        public let reason: String
        public let summary: String
    }

    public enum Failure: Error, Equatable {
        case stalePreview
        case invalidPlanDigest
    }

    /// Build a fresh apply preview bound to the takeover change manifest.
    public static func preview(plan: RouterPlan, profile: RouterSystemProfile,
                               now: Date = Date(), ttl: TimeInterval = 120) throws -> Preview {
        let planDigest = try RouterSystemCompiler.digest(plan: plan, profile: profile)
        guard planDigest.count == 64 else { throw Failure.invalidPlanDigest }
        let manifest = RouterTakeoverChangeManifest.make(plan: plan, profile: profile, digest: planDigest)
        let manifestDigest = manifest.digest
        let dimensions = [
            Dimension(name: "tunEnable", status: "preview_only",
                      detail: "预览描述将创建自有 TUN；本包执行不会真正启用。"),
            Dimension(name: "routesDns", status: "preview_only",
                      detail: "预览描述路由与 DNS 拦截；未改系统网络。"),
            Dimension(name: "foreignProxies", status: "never_auto_stop",
                      detail: "不会自动停止你的代理客户端/小火箭/系统 VPN；须你确认清场。"),
            Dimension(name: "trafficAcceptance", status: "required_after_real_apply",
                      detail: "routing_verified/accepted 保持 false；不能本预览提升。")
        ]
        return .init(
            id: UUID(),
            planDigest: planDigest,
            manifestDigest: manifestDigest,
            bullets: manifest.bullets,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(ttl),
            dimensions: dimensions,
            routingVerified: false,
            accepted: false,
            wouldEnableTunIfApplied: true,
            summary: "TUN apply 密封预览已生成（digest \(planDigest.prefix(12))…）。须武装+显式确认+复验；外隧道/requireClear 失败则拒绝；清场窗口 \(clearWindowID) 未确认前不启用 TUN。routing_verified=false · accepted=false。")
    }

    public static func arm(preview: Preview, kind: Arming.Kind,
                           now: Date = Date(), ttl: TimeInterval = 90) throws -> Arming {
        guard preview.isFresh(now: now) else { throw Failure.stalePreview }
        return .init(id: UUID(), kind: kind, previewID: preview.id,
                     issuedAt: now, expiresAt: now.addingTimeInterval(ttl))
    }

    public static func decide(preview: Preview,
                              arming: Arming?,
                              confirmation: Confirmation?,
                              before: Observation,
                              after: Observation,
                              clearWindow: ClearWindowGrant = .none,
                              now: Date = Date()) -> Decision {
        guard preview.isFresh(now: now) else {
            return .refuse("stale_preview")
        }
        guard preview.routingVerified == false, preview.accepted == false else {
            return .refuse("preview_must_not_claim_accepted")
        }
        guard let arming, arming.isValid(now: now), arming.previewID == preview.id else {
            return .refuse("apply_disarmed")
        }
        guard arming.kind == .productionGuardedApply else {
            return .refuse("arming_kind_not_guarded_apply")
        }
        guard let confirmation, confirmation.explicitUIConfirm,
              confirmation.previewID == preview.id,
              confirmation.confirmedAt >= preview.issuedAt,
              confirmation.confirmedAt <= now else {
            return .refuse("explicit_ui_confirm_required")
        }
        guard after.observedAt >= confirmation.confirmedAt else {
            return .refuse("reobservation_before_confirm")
        }
        if before.foreignTunnelLikely || after.foreignTunnelLikely {
            return .refuse("foreign_tunnel_or_refuseOwnTun")
        }
        if before.requireClearWouldPass == false || after.requireClearWouldPass == false {
            return .refuse("requireClear_would_fail")
        }
        if before.refuseOwnTun == true || after.refuseOwnTun == true {
            return .refuse("refuseOwnTun_blocks_tun_apply")
        }
        if let a = before.fingerprint, let b = after.fingerprint, a != b {
            return .refuse("reobservation_fingerprint_changed")
        }
        guard clearWindow.windowID == clearWindowID, clearWindow.grantedInConversation else {
            return .refuse("clear_window_not_confirmed_in_conversation")
        }
        guard after.requireClearWouldPass == true, after.refuseOwnTun != true else {
            return .refuse("clear_window_not_proven")
        }
        return .allow
    }

    /// Production execute entry. Runs `sideEffects` only after `.allow`.
    /// Without `enableOwnTun`, allow means gate-passed-unwired (no mutation).
    public static func execute(preview: Preview,
                               arming: Arming?,
                               confirmation: Confirmation?,
                               before: Observation,
                               after: Observation,
                               clearWindow: ClearWindowGrant = .none,
                               sideEffects: SideEffects = .unwired,
                               now: Date = Date()) throws -> Report {
        guard preview.isFresh(now: now) else { throw Failure.stalePreview }
        let decision = decide(preview: preview, arming: arming, confirmation: confirmation,
                              before: before, after: after, clearWindow: clearWindow, now: now)
        switch decision {
        case .refuse(let reason):
            let dimensions = preview.dimensions.map {
                Dimension(name: $0.name, status: "refused",
                          detail: "\($0.detail) · gate=\(reason)")
            }
            return .init(
                policyVersion: policyVersion, previewID: preview.id, decision: decision,
                executed: false, networkModified: false, tunEnabled: false,
                tunEffectsWired: false, foreignComponentsStopped: false, journalMutated: false,
                routingVerified: false, accepted: false, canPromoteAccepted: false,
                dimensions: dimensions, reason: reason,
                summary: "TUN apply 拒绝（\(reason)）。未启用 TUN、未改网络、未停你的代理客户端/小火箭/系统 VPN；routing_verified=false · accepted=false。")
        case .allow:
            guard let enable = sideEffects.enableOwnTun else {
                let dimensions = [
                    Dimension(name: "tunEnable", status: "gate_passed_unwired",
                              detail: "门禁通过；未注入 enableOwnTun；不创建/启用 TUN。"),
                    Dimension(name: "routesDns", status: "gate_passed_no_mutation",
                              detail: "门禁通过且清场已证明；仍不改路由/DNS/PF。"),
                    Dimension(name: "foreignProxies", status: "untouched",
                              detail: "未停止你的代理客户端/小火箭/系统 VPN。"),
                    Dimension(name: "trafficAcceptance", status: "required",
                              detail: "须真实 apply 后新流量验收；不提升 accepted。")
                ]
                return .init(
                    policyVersion: policyVersion, previewID: preview.id, decision: .allow,
                    executed: false, networkModified: false, tunEnabled: false,
                    tunEffectsWired: false, foreignComponentsStopped: false, journalMutated: false,
                    routingVerified: false, accepted: false, canPromoteAccepted: false,
                    dimensions: dimensions, reason: "gates_passed_tun_effects_unwired",
                    summary: "TUN apply 门禁已通过（密封预览+显式确认+复验+清场授予）。TUN 副作用未接线；networkModified=false · tunEnabled=false；未写 accepted。")
            }
            let outcome = try enable(preview)
            // Effects must not invent promotion seals; gate always keeps these false.
            let dimensions = [
                Dimension(name: "tunEnable",
                          status: outcome.tunEnabled ? "effects_reported_tun_enabled" : "effects_ran_tun_not_enabled",
                          detail: outcome.detail),
                Dimension(name: "routesDns",
                          status: outcome.networkModified ? "effects_reported_network_modified" : "effects_ran_no_network_claim",
                          detail: "副作用已执行；networkModified=\(outcome.networkModified)。"),
                Dimension(name: "foreignProxies",
                          status: outcome.foreignComponentsStopped ? "effects_claimed_foreign_stop" : "untouched",
                          detail: outcome.foreignComponentsStopped
                            ? "副作用声称停止了外部组件——须独立核验，本门禁不替你关你的代理客户端。"
                            : "未停止你的代理客户端/小火箭/系统 VPN。"),
                Dimension(name: "trafficAcceptance", status: "required",
                          detail: "须新流量验收；routing_verified/accepted 仍 false；不提升 canPromoteAccepted。")
            ]
            return .init(
                policyVersion: policyVersion, previewID: preview.id, decision: .allow,
                executed: true,
                networkModified: outcome.networkModified,
                tunEnabled: outcome.tunEnabled,
                tunEffectsWired: true,
                foreignComponentsStopped: outcome.foreignComponentsStopped,
                journalMutated: outcome.journalMutated,
                routingVerified: false, accepted: false, canPromoteAccepted: false,
                dimensions: dimensions, reason: "gates_passed_tun_effects_invoked",
                summary: "TUN apply 门禁通过且副作用已调用（tunEffectsWired=true · networkModified=\(outcome.networkModified) · tunEnabled=\(outcome.tunEnabled)）。未写 accepted；routing_verified=false。")
        }
    }
}
