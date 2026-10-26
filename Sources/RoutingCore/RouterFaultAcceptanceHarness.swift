import Foundation

/// Enumerates remaining product faults for delivery. Never claims verified without evidence.
/// `canClaimProductComplete` stays false until every fault is verified (not in this package).
public enum RouterFaultAcceptanceHarness {
    public static let policyVersion = 2

    public enum FaultCode: String, Equatable, Sendable, CaseIterable {
        case appTrafficMatrixUnauthenticated
        case realTunApplyMissing
        case pfArmingUnconfirmed
        case pfPostExitUnproven
        case rollbackRestoreUnwired
        case tunRestoreClearWindowUnconfirmed
        case acceptedLiveSealMissing
        case finalFaultAcceptanceIncomplete
    }

    public enum Verification: String, Equatable, Sendable {
        case verified
        case unverified
        case blockedOnUserConfirm
    }

    public struct Fault: Equatable, Sendable, Identifiable {
        public var id: String { code.rawValue }
        public let code: FaultCode
        public let title: String
        public let verification: Verification
        public let evidence: String
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let faults: [Fault]
        public let verifiedCount: Int
        public let unverifiedCount: Int
        public let blockedOnUserConfirmCount: Int
        public let routingVerified: Bool
        public let accepted: Bool
        public let canClaimProductComplete: Bool
        public let summary: String
    }

    public static func report(liveMatrix: RouterTrafficMatrixLiveRunner.Report? = nil,
                              rollbackRestore: RouterAcceptedRollbackRestore.Report? = nil,
                              tunApply: RouterTunApplyExecuteGate.Report? = nil,
                              pfArming: RouterPFArmingExecuteGate.Report? = nil,
                              failClosedProof: RouterCoreExitFailClosedProofHarness.Report? = nil,
                              appTrafficAttestation: RouterAppTrafficMatrixAttestation.Report? = nil,
                              pfArmed: Bool = false) -> Report {
        let matrixEvidence: String
        let matrixVerification: Verification
        if let appTrafficAttestation {
            if appTrafficAttestation.livePassedCount > 0 {
                matrixEvidence = appTrafficAttestation.summary
                matrixVerification = .unverified // scaffolding pass ≠ full matrix complete
            } else {
                matrixEvidence = appTrafficAttestation.summary
                matrixVerification = .blockedOnUserConfirm
            }
        } else if let liveMatrix, liveMatrix.livePassedCount > 0,
           liveMatrix.cells.contains(where: {
               $0.kind == .applicationTraffic && $0.outcome == .livePassed
           }) {
            matrixEvidence = liveMatrix.summary
            matrixVerification = .unverified // still not full matrix complete
        } else if let liveMatrix {
            matrixEvidence = "loopback/控制面可能已取证；应用格仍非 livePassed。\(liveMatrix.summary)"
            matrixVerification = .blockedOnUserConfirm
        } else {
            matrixEvidence = "尚未运行可证明应用路径的矩阵填格；须 \(RouterAppTrafficMatrixAttestation.clearWindowID)"
            matrixVerification = .unverified
        }

        let restoreEvidence: String
        let restoreVerification: Verification
        if let rollbackRestore {
            let extras = " ours=\(rollbackRestore.previousAcceptedIsOurs)"
                + " clearGrant=\(rollbackRestore.clearWindowGranted)"
                + " tunEffectsWired=\(rollbackRestore.tunEffectsWired)"
                + " canAttempt=\(rollbackRestore.canAttemptTunRestore)"
                + " networkModified=\(rollbackRestore.networkModified)"
            if rollbackRestore.networkModified {
                restoreEvidence = rollbackRestore.summary + extras
                restoreVerification = .unverified // mutation without full traffic reaccept ≠ done
            } else if rollbackRestore.gateAllowed {
                restoreEvidence = rollbackRestore.summary + extras
                // Structured / unwired — enumerated but not product-complete.
                restoreVerification = .unverified
            } else {
                restoreEvidence = rollbackRestore.summary + extras
                restoreVerification = .blockedOnUserConfirm
            }
        } else {
            restoreEvidence = "恢复副作用分项未运行；须 previousAccepted 自有+清场+\(RouterAcceptedRollbackRestore.clearWindowID)+userConfirmedNetworkRestore；未注入 restoreOwnTun 时 tunEffectsWired=false"
            restoreVerification = .unverified
        }

        let tunRestoreClearEvidence: String
        let tunRestoreClearVerification: Verification
        if let rollbackRestore {
            if rollbackRestore.clearWindowGranted {
                if rollbackRestore.tunEffectsWired {
                    tunRestoreClearEvidence = "清场已授予且 restoreOwnTun 已调用（tunEffectsWired=true · networkModified=\(rollbackRestore.networkModified)）；仍须流量复验；不得把旧 digest 当新成功；\(rollbackRestore.reason)"
                    tunRestoreClearVerification = rollbackRestore.networkModified ? .unverified : .unverified
                } else {
                    tunRestoreClearEvidence = "清场已授予但未注入/未调用 restoreOwnTun（tunEffectsWired=false）；不得声称恢复完成；reason=\(rollbackRestore.reason)"
                    tunRestoreClearVerification = .unverified
                }
            } else {
                tunRestoreClearEvidence = "窗口 \(RouterAcceptedRollbackRestore.clearWindowID) 未在本对话确认；restore reason=\(rollbackRestore.reason)；tunEffectsWired=false · networkModified=false"
                tunRestoreClearVerification = .blockedOnUserConfirm
            }
        } else {
            tunRestoreClearEvidence = "须 \(RouterAcceptedRollbackRestore.clearWindowID) 对话确认后才可谈 TUN 恢复接线；门禁拒绝路径已接线；不静默停你的代理客户端"
            tunRestoreClearVerification = .blockedOnUserConfirm
        }

        let tunEvidence: String
        if let tunApply {
            tunEvidence = "\(tunApply.summary) networkModified=\(tunApply.networkModified) tunEnabled=\(tunApply.tunEnabled) tunEffectsWired=\(tunApply.tunEffectsWired)"
        } else {
            tunEvidence = "须 requireClear 清场与 \(RouterTunApplyExecuteGate.clearWindowID) 对话确认；门禁拒绝路径已接线；副作用可注入但活路径默认 unwired；不静默停你的代理客户端/小火箭"
        }

        let faults: [Fault] = [
            .init(code: .appTrafficMatrixUnauthenticated, title: "应用流量矩阵未认证",
                  verification: matrixVerification, evidence: matrixEvidence),
            .init(code: .realTunApplyMissing, title: "真实 TUN apply 未完成",
                  verification: .blockedOnUserConfirm,
                  evidence: tunEvidence),
            .init(code: .pfArmingUnconfirmed, title: "PF 武装未确认",
                  verification: Self.pfArmingVerification(pfArmed: pfArmed, pfArming: pfArming),
                  evidence: Self.pfArmingEvidence(pfArmed: pfArmed, pfArming: pfArming)),
            .init(code: .pfPostExitUnproven, title: "内核退出后断流未证明",
                  verification: Self.failClosedVerification(failClosedProof),
                  evidence: failClosedProof.map {
                      "\($0.summary) canClaim=\($0.canClaimFailClosedProven)"
                  } ?? "REJECT/探测≠证明；须独立 PF 武装后故障验收；证明 harness 可枚举拒绝/未验证"),
            .init(code: .rollbackRestoreUnwired, title: "回退恢复副作用未接线",
                  verification: restoreVerification, evidence: restoreEvidence),
            .init(code: .tunRestoreClearWindowUnconfirmed, title: "TUN 恢复清场窗口未确认",
                  verification: tunRestoreClearVerification, evidence: tunRestoreClearEvidence),
            .init(code: .acceptedLiveSealMissing, title: "accepted live seal 缺失",
                  verification: .unverified,
                  evidence: "生产采集器未认证前不写 accepted；canPromoteAccepted 恒受门禁约束"),
            .init(code: .finalFaultAcceptanceIncomplete, title: "最终故障验收未完成",
                  verification: .unverified,
                  evidence: "本 harness 只枚举缺口；不能宣称产品完成")
        ]
        let verified = faults.filter { $0.verification == .verified }.count
        let unverified = faults.filter { $0.verification == .unverified }.count
        let blocked = faults.filter { $0.verification == .blockedOnUserConfirm }.count
        return .init(policyVersion: policyVersion, faults: faults,
                     verifiedCount: verified, unverifiedCount: unverified,
                     blockedOnUserConfirmCount: blocked,
                     routingVerified: false, accepted: false, canClaimProductComplete: false,
                     summary: "故障验收：verified=\(verified) unverified=\(unverified) blockedOnConfirm=\(blocked)；routing_verified=false · accepted=false · complete=false。")
    }

    private static func pfArmingVerification(pfArmed: Bool,
                                             pfArming: RouterPFArmingExecuteGate.Report?) -> Verification {
        if pfArmed { return .unverified }
        if let pfArming, case .allow = pfArming.decision, pfArming.armed {
            return .unverified
        }
        return .blockedOnUserConfirm
    }

    private static func pfArmingEvidence(pfArmed: Bool,
                                         pfArming: RouterPFArmingExecuteGate.Report?) -> String {
        if let pfArming {
            return "\(pfArming.summary) networkModified=\(pfArming.networkModified) pfRulesLoaded=\(pfArming.pfRulesLoaded) armed=\(pfArming.armed)"
        }
        if pfArmed {
            return "armed 声明存在但仍须退出后复验"
        }
        return "窗口 \(RouterPFArmingExecuteGate.confirmationWindowID) 未在本对话确认；门禁拒绝路径已接线；不加载 PF"
    }

    private static func failClosedVerification(
        _ proof: RouterCoreExitFailClosedProofHarness.Report?
    ) -> Verification {
        guard let proof else { return .unverified }
        // fixture / differential / live verified flags still do not complete the product.
        if proof.verified || proof.postExitDifferentiallyObserved { return .unverified }
        return proof.outcome == .refused ? .blockedOnUserConfirm : .unverified
    }
}
