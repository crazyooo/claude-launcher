import Foundation

/// Production packet-filter **arming** gate: sealed preview → guarded arming →
/// explicit UI confirm → post-confirm re-observation.
///
/// Refuses when conversation grant `pf-arming-user-confirm-v1` is absent, when
/// preview/arming/confirm/reobservation invariants fail, or when a foreign tunnel /
/// `refuseOwnTun` observation is present. On `.allow`, optional `SideEffects.loadFailClosed`
/// may run; without it the gate still passes but `pfEffectsWired=false` and no `pfctl`
/// mutation occurs. Never stops 你的代理客户端/小火箭. Never invents `routing_verified` / `accepted`.
public enum RouterPFArmingExecuteGate {
    public static let policyVersion = 2
    public static let confirmationWindowID = RouterPFArmingPreview.confirmationWindowID

    /// Injectable PF load hook. Production live UI passes `.unwired` until a reviewed
    /// loader is connected; tests inject a recorder; scripts live under
    /// `tools/router_pf_failclosed.py`.
    public struct SideEffects: Sendable {
        public struct Outcome: Equatable, Sendable {
            public let networkModified: Bool
            public let pfRulesLoaded: Bool
            public let armed: Bool
            public let foreignComponentsStopped: Bool
            public let journalMutated: Bool
            public let detail: String

            public init(networkModified: Bool, pfRulesLoaded: Bool, armed: Bool,
                        foreignComponentsStopped: Bool = false,
                        journalMutated: Bool = false, detail: String) {
                self.networkModified = networkModified
                self.pfRulesLoaded = pfRulesLoaded
                self.armed = armed
                self.foreignComponentsStopped = foreignComponentsStopped
                self.journalMutated = journalMutated
                self.detail = detail
            }
        }

        public var loadFailClosed: (@Sendable (Preview) throws -> Outcome)?

        public init(loadFailClosed: (@Sendable (Preview) throws -> Outcome)? = nil) {
            self.loadFailClosed = loadFailClosed
        }

        public static let unwired = SideEffects(loadFailClosed: nil)
    }

    public struct Dimension: Equatable, Sendable {
        public let name: String
        public let status: String
        public let detail: String
    }

    public struct Preview: Equatable, Sendable {
        public let id: UUID
        public let planDigest: String
        public let designedLayer: RouterCoreExitFailClosed.SystemLayerKind
        public let subjectCount: Int
        public let bullets: [String]
        public let issuedAt: Date
        public let expiresAt: Date
        public let dimensions: [Dimension]
        public let routingVerified: Bool
        public let accepted: Bool
        public let wouldMutateNetworkIfArmed: Bool
        public let confirmationWindowID: String
        /// Structural applicability of the PF ruleset for this exact plan. Address fill
        /// (empty table) is checked by the loader, not here.
        public let rulesetApplicable: Bool
        public let rulesetBlockers: [String]
        public let summary: String

        public func isFresh(now: Date = Date()) -> Bool {
            now >= issuedAt && now < expiresAt
        }
    }

    public struct Arming: Equatable, Sendable {
        public enum Kind: Equatable, Sendable {
            case productionPreviewOnly
            case productionGuardedArm
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
        public let foreignTunnelPresent: Bool?
        public let systemPhase: String?
        public let observedAt: Date
        public let fingerprint: String?

        public init(refuseOwnTun: Bool?, foreignTunnelPresent: Bool? = nil,
                    systemPhase: String?, observedAt: Date = Date(),
                    fingerprint: String? = nil) {
            self.refuseOwnTun = refuseOwnTun
            self.foreignTunnelPresent = foreignTunnelPresent
            self.systemPhase = systemPhase
            self.observedAt = observedAt
            self.fingerprint = fingerprint
        }

        public var foreignTunnelLikely: Bool {
            foreignTunnelPresent == true || refuseOwnTun == true
        }
    }

    /// Conversation-scoped PF arming grant. Issued via `RouterConversationPFArming` after
    /// explicit user confirm in this chat; gate allow still leaves PF effects unwired.
    public struct ConversationGrant: Equatable, Sendable {
        public let windowID: String
        public let grantedInConversation: Bool

        public init(windowID: String = RouterPFArmingExecuteGate.confirmationWindowID,
                    grantedInConversation: Bool) {
            self.windowID = windowID
            self.grantedInConversation = grantedInConversation
        }

        public static let none = ConversationGrant(grantedInConversation: false)
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
        public let pfRulesLoaded: Bool
        public let armed: Bool
        public let pfEffectsWired: Bool
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

    public static func preview(plan: RouterPlan, profile: RouterSystemProfile = .init(resolver: .cloudflare),
                               now: Date = Date(), ttl: TimeInterval = 120) throws -> Preview {
        let planDigest = try RouterSystemCompiler.digest(plan: plan, profile: profile)
        guard planDigest.count == 64 else { throw Failure.invalidPlanDigest }
        let recipe = RouterCoreExitFailClosed.recipe(from: plan)
        let ruleset = RouterPFArmingRuleset.generate(
            recipe: recipe, planDigest: planDigest,
            transportExclusions: plan.proxies.map(\.host))
        let legacy = RouterPFArmingPreview.preview(plan: plan)
        let dimensions = [
            Dimension(name: "pfAnchor", status: "preview_only",
                      detail: "预览设计独立 anchor default-deny；本包不加载 PF 规则。"),
            Dimension(name: "defaultDeny", status: "preview_only",
                      detail: "subjects=\(recipe.subjects.count)；未安装 packet-filter。"),
            Dimension(name: "foreignProxies", status: "never_auto_stop",
                      detail: "不会自动停止你的代理客户端/小火箭/系统 VPN。"),
            Dimension(name: "postExitReobservation", status: "required_after_real_arm",
                      detail: "内核退出后断流须武装后再验；REJECT≠证明。")
        ]
        let bullets = legacy.requiredConfirmations.map { "须确认：\($0)" }
            + [
                "设计层 \(recipe.designedLayer.rawValue)；subjects=\(recipe.subjects.count)。",
                "窗口 \(confirmationWindowID) 未授予前不武装 PF。",
                "routing_verified=false · accepted=false。"
            ]
        return .init(
            id: UUID(),
            planDigest: planDigest,
            designedLayer: recipe.designedLayer,
            subjectCount: recipe.subjects.count,
            bullets: bullets,
            issuedAt: now,
            expiresAt: now.addingTimeInterval(ttl),
            dimensions: dimensions,
            routingVerified: false,
            accepted: false,
            wouldMutateNetworkIfArmed: true,
            confirmationWindowID: confirmationWindowID,
            rulesetApplicable: ruleset.applicable,
            rulesetBlockers: ruleset.blockers,
            summary: "PF 武装密封预览已生成（digest \(planDigest.prefix(12))…）。须武装+显式确认+复验；窗口 \(confirmationWindowID) 未确认前不安装 PF。routing_verified=false · accepted=false。")
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
                              grant: ConversationGrant = .none,
                              now: Date = Date()) -> Decision {
        guard preview.isFresh(now: now) else {
            return .refuse("stale_preview")
        }
        guard preview.routingVerified == false, preview.accepted == false else {
            return .refuse("preview_must_not_claim_accepted")
        }
        // Never hand a plan the PF layer cannot honestly cover to a wired loader.
        guard preview.rulesetApplicable else {
            return .refuse("pf_ruleset_not_applicable")
        }
        guard let arming, arming.isValid(now: now), arming.previewID == preview.id else {
            return .refuse("arm_disarmed")
        }
        guard arming.kind == .productionGuardedArm else {
            return .refuse("arming_kind_not_guarded_arm")
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
        if let a = before.fingerprint, let b = after.fingerprint, a != b {
            return .refuse("reobservation_fingerprint_changed")
        }
        guard grant.windowID == confirmationWindowID, grant.grantedInConversation else {
            return .refuse("pf_arming_not_confirmed_in_conversation")
        }
        return .allow
    }

    /// Production execute entry. Runs `sideEffects` only after `.allow`.
    /// Without `loadFailClosed`, allow means gate-passed-unwired (no `pfctl` mutation).
    public static func execute(preview: Preview,
                               arming: Arming?,
                               confirmation: Confirmation?,
                               before: Observation,
                               after: Observation,
                               grant: ConversationGrant = .none,
                               sideEffects: SideEffects = .unwired,
                               now: Date = Date()) throws -> Report {
        guard preview.isFresh(now: now) else { throw Failure.stalePreview }
        let decision = decide(preview: preview, arming: arming, confirmation: confirmation,
                              before: before, after: after, grant: grant, now: now)
        switch decision {
        case .refuse(let reason):
            let dimensions = preview.dimensions.map {
                Dimension(name: $0.name, status: "refused",
                          detail: "\($0.detail) · gate=\(reason)")
            }
            return .init(
                policyVersion: policyVersion, previewID: preview.id, decision: decision,
                executed: false, networkModified: false, pfRulesLoaded: false, armed: false,
                pfEffectsWired: false, foreignComponentsStopped: false, journalMutated: false,
                routingVerified: false, accepted: false, canPromoteAccepted: false,
                dimensions: dimensions, reason: reason,
                summary: "PF 武装拒绝（\(reason)）。未加载 PF 规则、未改网络、未停你的代理客户端/小火箭；routing_verified=false · accepted=false。")
        case .allow:
            guard let load = sideEffects.loadFailClosed else {
                let dimensions = [
                    Dimension(name: "pfAnchor", status: "gate_passed_unwired",
                              detail: "门禁通过；未注入 loadFailClosed；不创建/加载 PF anchor。"),
                    Dimension(name: "defaultDeny", status: "gate_passed_no_mutation",
                              detail: "门禁通过；仍不安装 default-deny。"),
                    Dimension(name: "foreignProxies", status: "untouched",
                              detail: "未停止你的代理客户端/小火箭/系统 VPN。"),
                    Dimension(name: "postExitReobservation", status: "required",
                              detail: "须真实武装后内核退出复验；不提升 accepted。")
                ]
                return .init(
                    policyVersion: policyVersion, previewID: preview.id, decision: .allow,
                    executed: false, networkModified: false, pfRulesLoaded: false, armed: false,
                    pfEffectsWired: false, foreignComponentsStopped: false, journalMutated: false,
                    routingVerified: false, accepted: false, canPromoteAccepted: false,
                    dimensions: dimensions, reason: "gates_passed_pf_effects_unwired",
                    summary: "PF 武装门禁已通过（密封预览+显式确认+复验+对话授予）。PF 副作用未接线；networkModified=false · pfRulesLoaded=false · armed=false；未写 accepted。")
            }
            let outcome = try load(preview)
            let dimensions = [
                Dimension(name: "pfAnchor",
                          status: outcome.pfRulesLoaded ? "effects_reported_rules_loaded" : "effects_ran_rules_not_loaded",
                          detail: outcome.detail),
                Dimension(name: "defaultDeny",
                          status: outcome.armed ? "effects_reported_armed" : "effects_ran_not_armed",
                          detail: "副作用已执行；armed=\(outcome.armed) · networkModified=\(outcome.networkModified)。"),
                Dimension(name: "foreignProxies",
                          status: outcome.foreignComponentsStopped ? "effects_claimed_foreign_stop" : "untouched",
                          detail: outcome.foreignComponentsStopped
                            ? "副作用声称停止了外部组件——须独立核验；本门禁不替你关你的代理客户端。"
                            : "未停止你的代理客户端/小火箭/系统 VPN。"),
                Dimension(name: "postExitReobservation", status: "required",
                          detail: "即便规则已加载，内核退出后断流仍须复验；REJECT≠证明；不提升 accepted。")
            ]
            return .init(
                policyVersion: policyVersion, previewID: preview.id, decision: .allow,
                executed: true,
                networkModified: outcome.networkModified,
                pfRulesLoaded: outcome.pfRulesLoaded,
                armed: outcome.armed,
                pfEffectsWired: true,
                foreignComponentsStopped: outcome.foreignComponentsStopped,
                journalMutated: outcome.journalMutated,
                routingVerified: false, accepted: false, canPromoteAccepted: false,
                dimensions: dimensions, reason: "gates_passed_pf_effects_invoked",
                summary: "PF 武装门禁通过且副作用已调用（pfEffectsWired=true · networkModified=\(outcome.networkModified) · pfRulesLoaded=\(outcome.pfRulesLoaded) · armed=\(outcome.armed)）。未写 accepted；routing_verified=false。")
        }
    }
}
