import Foundation

/// Honest delivery checklist for remaining router capabilities. Never marks live
/// TUN/PF/accepted completion without evidence.
public enum RouterDeliveryChecklist {
    public static let policyVersion = 1

    public enum Status: String, Equatable, Sendable {
        case done
        case partial
        case gap
    }

    public struct Item: Equatable, Sendable, Identifiable {
        public var id: String { code }
        public let code: String
        public let title: String
        public let status: Status
        public let evidence: String
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let items: [Item]
        public let routingVerified: Bool
        public let accepted: Bool
        public let canClaimProductComplete: Bool
        public let summary: String
    }

    public static func report(plan: RouterPlan = .init(proxies: [], rules: [], defaultDestination: .direct),
                              profile: RouterSystemProfile = .init(resolver: .cloudflare),
                              liveMatrix: RouterTrafficMatrixLiveRunner.Report? = nil,
                              rollbackRestore: RouterAcceptedRollbackRestore.Report? = nil,
                              tunApply: RouterTunApplyExecuteGate.Report? = nil,
                              pfArming: RouterPFArmingExecuteGate.Report? = nil,
                              failClosedProof: RouterCoreExitFailClosedProofHarness.Report? = nil,
                              appTrafficAttestation: RouterAppTrafficMatrixAttestation.Report? = nil) -> Report {
        let failClosed = RouterCoreExitFailClosed.productionGap(for: plan)
        let matrix = (try? RouterTrafficMatrix.report(plan: plan, profile: profile))
        let pfPreview = RouterPFArmingPreview.preview(plan: plan)
        let faults = RouterFaultAcceptanceHarness.report(
            liveMatrix: liveMatrix, rollbackRestore: rollbackRestore,
            tunApply: tunApply, pfArming: pfArming, failClosedProof: failClosedProof,
            appTrafficAttestation: appTrafficAttestation, pfArmed: pfPreview.armed)
        let liveFillStatus: Status
        let liveFillEvidence: String
        if let liveMatrix {
            if liveMatrix.livePassedCount > 0 && liveMatrix.canClaimMatrixComplete {
                liveFillStatus = .done
                liveFillEvidence = liveMatrix.summary
            } else if liveMatrix.refusedCount + liveMatrix.blockedCount + liveMatrix.untestedCount > 0 {
                liveFillStatus = .partial
                liveFillEvidence = liveMatrix.summary
            } else {
                liveFillStatus = .gap
                liveFillEvidence = liveMatrix.summary
            }
        } else {
            liveFillStatus = .gap
            liveFillEvidence = "尚未运行 live runner；inventory livePassed=0"
        }
        let items: [Item] = [
            .init(code: "path_portrait", title: "当前走线识别", status: .done,
                  evidence: "只读采样；不提升 accepted"),
            .init(code: "coexistence_prepare_gate", title: "共存拒绝预览与 prepare 闸门", status: .done,
                  evidence: "refuseOwnTun 挡 prepare；requireClear 仍为服务端门禁"),
            .init(code: "takeover_manifest", title: "接管明确变更清单", status: .done,
                  evidence: "预览/确认框绑定；不伪造验收"),
            .init(code: "accepted_seal", title: "accepted 证据门禁", status: .partial,
                  evidence: "拒假填；live 采集未认证前不写入"),
            .init(code: "fail_closed", title: "内核退出 fail-closed",
                  status: failClosedProof.map {
                      $0.canClaimFailClosedProven ? .done : .partial
                  } ?? .partial,
                  evidence: failClosedProof.map {
                      "\($0.summary) outcome=\($0.outcome.rawValue) differential=\($0.postExitDifferentiallyObserved)"
                  } ?? "脚本路径已做差分复验（见 web-notes/pf-failclosed-post-exit-2026-10-24.json）；\(failClosed.summary)"),
            .init(code: "traffic_matrix", title: "流量矩阵 harness",
                  status: (matrix?.canClaimMatrixComplete == true) ? .done : .partial,
                  evidence: matrix?.summary ?? "规划无法生成矩阵"),
            .init(code: "app_traffic_attestation", title: "应用流量取证脚手架",
                  status: appTrafficAttestation.map {
                      $0.canClaimAppTrafficComplete ? .done : .partial
                  } ?? .partial,
                  evidence: appTrafficAttestation.map {
                      "\($0.summary) canPromoteAccepted=\($0.canPromoteAccepted) window=\($0.clearWindowID)"
                  } ?? "应用/已有连接格在 \(RouterAppTrafficMatrixAttestation.clearWindowID) 未授予前精确 blocked；livePassed 仅认证证据；canPromoteAccepted=false"),
            .init(code: "hit_correlation", title: "受控命中关联入口", status: .partial,
                  evidence: "武装+闸门+GUI→active hitCorrelation IPC；无实例/refuseOwnTun/远端 fail-closed；仍不写 accepted"),
            .init(code: "rollback_preview", title: "sealed 回退执行门禁+TUN 恢复结构化", status: .partial,
                  evidence: rollbackRestore.map {
                      "\($0.summary) networkModified=\($0.networkModified) tunEffectsWired=\($0.tunEffectsWired) clearGrant=\($0.clearWindowGranted) ours=\($0.previousAcceptedIsOurs) canAttempt=\($0.canAttemptTunRestore)"
                  } ?? "预览+确认+复验+refuseOwnTun；TUN 恢复挂 ExecuteGate；外隧道/未清场/\(RouterAcceptedRollbackRestore.clearWindowID) 未确认 → 诚实拒绝；可注入 restoreOwnTun；未注入则 tunEffectsWired=false；旧 digest≠新成功"),
            .init(code: "routing_event_log", title: "路由事件日志", status: .partial,
                  evidence: "脱敏持久日志已接线本包；非完整故障验收"),
            .init(code: "live_tun_apply", title: "真实 TUN 接管", status: .partial,
                  evidence: tunApply.map {
                      "门禁已接线；\($0.summary) networkModified=\($0.networkModified) tunEnabled=\($0.tunEnabled) tunEffectsWired=\($0.tunEffectsWired)"
                  } ?? "预览→确认→复验门禁已接线；可注入 enableOwnTun；外隧道/未清场/\(RouterTunApplyExecuteGate.clearWindowID) 未确认 → 诚实拒绝；活路径默认 unwired"),
            .init(code: "pf_arming", title: "独立 PF 断流武装", status: .partial,
                  evidence: pfArming.map {
                      "门禁已接线；\($0.summary) networkModified=\($0.networkModified) pfRulesLoaded=\($0.pfRulesLoaded) armed=\($0.armed)"
                  } ?? "预览→确认→复验门禁已接线；\(RouterPFArmingExecuteGate.confirmationWindowID) 未确认 → 诚实拒绝；真实武装仍须你确认；legacy preview armed=\(pfPreview.armed)"),
            .init(code: "live_matrix_fill", title: "矩阵 live 填格", status: liveFillStatus,
                  evidence: liveFillEvidence.isEmpty
                    ? "loopback hitCorrelation 填格已接线；远端/应用格仍 blocked 待清场；livePassed 仅计 collectorAuthenticated"
                    : liveFillEvidence),
            .init(code: "fault_acceptance", title: "故障验收枚举", status: .partial,
                  evidence: faults.summary),
            .init(code: "final_delivery", title: "最终交付验收", status: .gap,
                  evidence: "目标未完成；verified=\(faults.verifiedCount)/\(faults.faults.count)；本清单不能宣称产品完成")
        ]
        return .init(policyVersion: policyVersion, items: items,
                     routingVerified: false, accepted: false, canClaimProductComplete: false,
                     summary: "交付核对：已接线门禁/配方多项为 partial；真实 TUN/PF/应用矩阵/最终验收仍为 gap。\(faults.summary)")
    }
}
