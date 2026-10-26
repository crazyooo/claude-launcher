import Foundation

/// Independent fail-closed capability for traffic that must stay blocked after the owned
/// routing core exits. Mihomo/internal REJECT rules, probe success, and detection alone
/// are never proof. This package designs and evaluates the gate; it does not install PF,
/// change routes, or touch 你的代理客户端/小火箭/system IPv6.
public enum RouterCoreExitFailClosed {
    public static let policyVersion = 1

    /// System-layer mechanisms that could eventually prove fail-closed. Only an armed and
    /// post-exit verified independent layer counts; internal core rules do not.
    public enum SystemLayerKind: String, Equatable, Sendable {
        case packetFilterAnchorDefaultDeny
        case routeDiscardWithInterfaceHold
        case networkExtensionPacketFilter
    }

    /// Claims that must never upgrade verification by themselves.
    public enum InsufficientProof: String, Equatable, Sendable, CaseIterable {
        case mihomoInternalRejectRules
        case compiledRejectRulePresence
        case probeOrDetectionSuccess
        case systemProxyToggle
        case acceptedJournalPointer
        case routingVerifiedFlag
    }

    public struct ProtectedSubject: Equatable, Sendable {
        public enum Kind: String, Equatable, Sendable { case domainExact, domainSuffix, processPath, defaultBlock }
        public let kind: Kind
        public let value: String
        public let ruleID: UUID?
    }

    /// Offline recipe of what an independent layer would need to cover. Not an apply permit.
    public struct Recipe: Equatable, Sendable {
        public let policyVersion: Int
        public let designedLayer: SystemLayerKind
        public let subjects: [ProtectedSubject]
        public let allowFailoverOnFault: Bool
        public let notes: [String]

        public var requiresIndependentLayer: Bool { !subjects.isEmpty }
    }

    public struct IndependentLayerClaim: Equatable, Sendable {
        public enum Authentication: Equatable, Sendable {
            case productionUnverified
            /// Unit-test-only harness. Must never be built from IPC, UI, or REJECT inspection.
            case unitTestSealedAfterCoreExit
        }

        public let authentication: Authentication
        public let layerKind: SystemLayerKind?
        public let layerArmed: Bool
        public let verifiedAfterCoreExit: Bool
        public let offeredProofs: [InsufficientProof]
        public let evidenceDigest: String?

        public static var productionGap: Self {
            .init(authentication: .productionUnverified, layerKind: nil, layerArmed: false,
                  verifiedAfterCoreExit: false, offeredProofs: [], evidenceDigest: nil)
        }

        public static func unitTestVerified(layer: SystemLayerKind, evidenceDigest: String) -> Self {
            .init(authentication: .unitTestSealedAfterCoreExit, layerKind: layer, layerArmed: true,
                  verifiedAfterCoreExit: true, offeredProofs: [], evidenceDigest: evidenceDigest)
        }
    }

    public struct Assessment: Equatable, Sendable {
        public let status: String
        public let verified: Bool
        public let capabilityGap: Bool
        public let blockers: [String]
        public let rejectRulesAreNotProof: Bool
        public let recipeSubjectCount: Int
        public let summary: String
    }

    /// Derive protected subjects from the plan. Block destinations and proxied selectors that
    /// must not leak on core death are included. Direct-only plans yield an empty recipe.
    public static func recipe(from plan: RouterPlan,
                              designedLayer: SystemLayerKind = .packetFilterAnchorDefaultDeny,
                              allowFailoverOnFault: Bool = false) -> Recipe {
        var subjects: [ProtectedSubject] = []
        for rule in plan.rules {
            switch rule.destination.kind {
            case .direct: continue
            case .block, .proxy:
                if let domain = rule.selector.domain {
                    subjects.append(.init(kind: domain.kind == .exact ? .domainExact : .domainSuffix,
                                          value: domain.value, ruleID: rule.id))
                }
                if let path = rule.selector.processPath {
                    subjects.append(.init(kind: .processPath, value: path, ruleID: rule.id))
                }
                if rule.selector.domain == nil, rule.selector.processPath == nil {
                    subjects.append(.init(kind: .defaultBlock, value: "rule:\(rule.id.uuidString)",
                                          ruleID: rule.id))
                }
            }
        }
        switch plan.defaultDestination.kind {
        case .direct: break
        case .block, .proxy:
            subjects.append(.init(kind: .defaultBlock, value: "plan.defaultDestination", ruleID: nil))
        }
        let notes = [
            "Independent system-layer arming is not performed by this recipe.",
            "Internal Mihomo REJECT / UDP REJECT compilation is insufficient proof.",
            "Arming or verifying fail-closed must not silently alter 你的代理客户端, 小火箭, or system IPv6.",
            allowFailoverOnFault
                ? "Failover on fault is explicitly enabled in this recipe preview only."
                : "Failover on fault remains disabled unless explicitly configured."
        ]
        return .init(policyVersion: policyVersion, designedLayer: designedLayer, subjects: subjects,
                     allowFailoverOnFault: allowFailoverOnFault, notes: notes)
    }

    public static func assess(recipe: Recipe, claim: IndependentLayerClaim) -> Assessment {
        var blockers: [String] = []
        if recipe.requiresIndependentLayer {
            blockers.append("independent_layer_required_for_protected_subjects")
        } else {
            blockers.append("no_protected_subjects_fail_closed_not_applicable")
        }
        for proof in claim.offeredProofs {
            blockers.append("insufficient_proof:\(proof.rawValue)")
        }
        if claim.offeredProofs.contains(.mihomoInternalRejectRules)
            || claim.offeredProofs.contains(.compiledRejectRulePresence) {
            blockers.append("reject_rules_are_not_core_exit_proof")
        }
        let sealed = claim.authentication == .unitTestSealedAfterCoreExit
            && claim.layerArmed
            && claim.verifiedAfterCoreExit
            && claim.layerKind == recipe.designedLayer
            && recipe.requiresIndependentLayer
            && (claim.evidenceDigest.map(RouterSystemProvider.validDigest) ?? false)
            && claim.offeredProofs.isEmpty
        if sealed {
            return .init(status: "verified_after_core_exit_fixture",
                         verified: true, capabilityGap: false,
                         blockers: [], rejectRulesAreNotProof: true,
                         recipeSubjectCount: recipe.subjects.count,
                         summary: "单元测试密封夹具证明评估路径；不代表本机已武装独立断流层。")
        }
        if claim.layerArmed && !claim.verifiedAfterCoreExit {
            blockers.append("layer_armed_but_not_verified_after_core_exit")
        }
        if claim.authentication == .productionUnverified {
            blockers.append("production_independent_layer_unimplemented")
        }
        let unique = Array(Set(blockers)).sorted()
        return .init(status: "capability_gap",
                     verified: false, capabilityGap: true,
                     blockers: unique, rejectRulesAreNotProof: true,
                     recipeSubjectCount: recipe.subjects.count,
                     summary: "内核退出后的严格断流尚未验证；内部 REJECT 规则不能代替独立系统层证明。")
    }

    /// Production UI/default status. Never claims verification.
    public static func productionGap(for plan: RouterPlan) -> Assessment {
        assess(recipe: recipe(from: plan), claim: .productionGap)
    }
}
