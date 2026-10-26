import Foundation

/// Rollback preview/path for sealed `accepted` / `previousAccepted` pointers.
/// Historical digests never count as a new run success. Configuration restore,
/// process restore, network cleanup, and traffic re-acceptance are reported separately.
/// Does not change TUN/routes/PF or write accepted without a fresh promotion seal.
public enum RouterAcceptedRollback {
    public static let policyVersion = 1

    public enum SourceKind: String, Equatable, Sendable {
        case previousAccepted
        case accepted
    }

    public struct Dimension: Equatable, Sendable {
        public let name: String
        public let status: String
        public let detail: String
    }

    public struct Preview: Equatable, Sendable {
        public let id: UUID
        public let source: SourceKind
        public let plan: RouterPlan
        public let profile: RouterSystemProfile
        public let historicalConfigurationDigest: String
        public let historicalEvidenceDigest: String
        public let issuedAt: Date
        public let expiresAt: Date
        public let dimensions: [Dimension]
        public let historicalSuccessTransfersToNewInstance: Bool
        public let canExecute: Bool
        public let blockers: [String]
        public let summary: String

        public func isFresh(now: Date = Date()) -> Bool {
            now >= issuedAt && now < expiresAt
        }
    }

    public struct ExecuteReport: Equatable, Sendable {
        public let previewID: UUID
        public let executed: Bool
        public let networkModified: Bool
        public let journalMutated: Bool
        public let historicalDigestTreatedAsNewSuccess: Bool
        public let dimensions: [Dimension]
        public let summary: String
    }

    public enum Failure: Error, Equatable {
        case missingSource
        case stalePreview
        case disarmed
        case historicalDigestReuseForbidden
    }

    public struct ExecuteArming: Equatable, Sendable {
        public enum Kind: Equatable, Sendable {
            /// Production default: preview-only; execute always refuses network mutation.
            case productionPreviewOnly
            /// Production guarded execute arming for `RouterAcceptedRollbackExecuteGate`.
            /// Still does not authorize silent TUN/route/PF mutation by itself.
            case productionGuardedExecute
            /// Unit-test harness proving the execute gate path without claiming live success.
            case unitTestPreviewPath
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

    /// Build a fresh rollback preview from sealed accepted fields. Re-preview required each time.
    public static func preview(source: SourceKind, plan: RouterPlan, profile: RouterSystemProfile,
                               configurationDigest: String, evidenceDigest: String,
                               now: Date = Date(), ttl: TimeInterval = 60) throws -> Preview {
        let accepted = RouterAcceptedConfiguration(
            plan: plan, profile: profile, configurationDigest: configurationDigest,
            acceptanceEvidenceDigest: evidenceDigest)
        try RouterSystemProvider.validateAcceptedConfiguration(accepted)
        return makePreview(source: source, accepted: accepted, now: now, ttl: ttl)
    }

    /// Prefer `previousAccepted`, else `accepted`. Throws if neither is sealed/valid.
    static func preview(from journal: RouterSystemJournal, preferPrevious: Bool = true,
                        now: Date = Date(), ttl: TimeInterval = 60) throws -> Preview {
        let source: SourceKind
        let accepted: RouterAcceptedConfiguration
        if preferPrevious, let previous = journal.previousAccepted {
            source = .previousAccepted; accepted = previous
        } else if let current = journal.accepted {
            source = .accepted; accepted = current
        } else if let previous = journal.previousAccepted {
            source = .previousAccepted; accepted = previous
        } else {
            throw Failure.missingSource
        }
        try RouterSystemProvider.validateAcceptedConfiguration(accepted)
        return makePreview(source: source, accepted: accepted, now: now, ttl: ttl)
    }

    public static func requireFresh(_ preview: Preview, now: Date = Date()) throws {
        guard preview.isFresh(now: now) else { throw Failure.stalePreview }
    }

    public static func armExecute(preview: Preview, kind: ExecuteArming.Kind = .productionPreviewOnly,
                                  now: Date = Date(), ttl: TimeInterval = 60) throws -> ExecuteArming {
        try requireFresh(preview, now: now)
        let window = min(max(ttl, 1), 120)
        return .init(id: UUID(), kind: kind, previewID: preview.id, issuedAt: now,
                     expiresAt: now.addingTimeInterval(window))
    }

    /// Executable path gate. Never treats historical digests as new success.
    /// Production arming refuses mutation; unit-test arming only proves the gate reports dimensions.
    public static func execute(preview: Preview, arming: ExecuteArming?,
                               now: Date = Date()) throws -> ExecuteReport {
        try requireFresh(preview, now: now)
        guard let arming, arming.isValid(now: now), arming.previewID == preview.id else {
            throw Failure.disarmed
        }
        // Explicit guard: callers must not pass historical digest as a substitute success token.
        if preview.historicalSuccessTransfersToNewInstance {
            throw Failure.historicalDigestReuseForbidden
        }
        let dimensions: [Dimension]
        switch arming.kind {
        case .productionPreviewOnly:
            dimensions = preview.dimensions.map {
                .init(name: $0.name, status: "blocked_pending_new_operation",
                      detail: $0.detail + " · 须新预览/新实例；历史摘要不转移。")
            }
            return .init(previewID: preview.id, executed: false, networkModified: false,
                         journalMutated: false, historicalDigestTreatedAsNewSuccess: false,
                         dimensions: dimensions,
                         summary: "回退执行未进行：生产仅允许预览。配置/进程/网络/流量须分别重新验收；旧 digest ≠ 新成功。")
        case .productionGuardedExecute:
            // Legacy entry without observation/confirm — refuse mutation; use ExecuteGate.execute.
            dimensions = preview.dimensions.map {
                .init(name: $0.name, status: "blocked_pending_execute_gate",
                      detail: $0.detail + " · 须经 RouterAcceptedRollbackExecuteGate（确认+复验+清场）。")
            }
            return .init(previewID: preview.id, executed: false, networkModified: false,
                         journalMutated: false, historicalDigestTreatedAsNewSuccess: false,
                         dimensions: dimensions,
                         summary: "回退执行未进行：已武装 guarded execute，但须走 ExecuteGate（显式确认+复验）；未改网络。")
        case .unitTestPreviewPath:
            dimensions = [
                .init(name: "configurationRestore", status: "fixture_path_only",
                      detail: "单元测试路径已走到配置维；非 live 文件恢复。"),
                .init(name: "processRestore", status: "fixture_path_only",
                      detail: "单元测试路径已走到进程维；非 live 进程恢复。"),
                .init(name: "networkCleanup", status: "fixture_path_only",
                      detail: "单元测试路径已走到网络维；未改 TUN/路由/PF。"),
                .init(name: "trafficReacceptance", status: "not_completed",
                      detail: "历史证据不转移到新实例；须新流量验收。")
            ]
            return .init(previewID: preview.id, executed: true, networkModified: false,
                         journalMutated: false, historicalDigestTreatedAsNewSuccess: false,
                         dimensions: dimensions,
                         summary: "单元测试回退路径已演练；networkModified=false；历史 digest 未当作新成功。")
        }
    }

    public static func emptyJournalStatus() -> String {
        "无 sealed previousAccepted/accepted，无法生成回退预览。须先经证据门禁写入指针。"
    }

    private static func makePreview(source: SourceKind, accepted: RouterAcceptedConfiguration,
                                    now: Date, ttl: TimeInterval) -> Preview {
        let window = min(max(ttl, 1), 120)
        let dimensions = [
            Dimension(name: "configurationRestore", status: "preview_only",
                      detail: "将目标配置摘要 \(accepted.configurationDigest.prefix(12))… 列为候选；须新操作身份与 stage，不能复用旧管理密钥。"),
            Dimension(name: "processRestore", status: "unverified",
                      detail: "历史进程/实例身份不转移到新运行；停止/拉起须单独报告。"),
            Dimension(name: "networkCleanup", status: "unverified",
                      detail: "网络清理与 footprint 核对未在本预览执行；不静默改你的代理客户端/路由/PF。"),
            Dimension(name: "trafficReacceptance", status: "required",
                      detail: "即使历史 accepted 有效，新实例仍须重新流量验收；旧 evidence digest 不是新成功。")
        ]
        let blockers = [
            "repreview_required_each_attempt",
            "historical_digest_is_not_new_success",
            "separate_config_process_network_traffic_reports",
            "production_execute_refuses_network_mutation"
        ]
        return .init(id: UUID(), source: source, plan: accepted.plan, profile: accepted.profile,
                     historicalConfigurationDigest: accepted.configurationDigest,
                     historicalEvidenceDigest: accepted.acceptanceEvidenceDigest,
                     issuedAt: now, expiresAt: now.addingTimeInterval(window),
                     dimensions: dimensions,
                     historicalSuccessTransfersToNewInstance: false,
                     canExecute: false,
                     blockers: blockers,
                     summary: "回退预览（\(source.rawValue)）：历史配置 \(accepted.configurationDigest.prefix(12))… 仅作候选。配置/进程/网络/流量分项未完成；旧 digest ≠ 新成功；须重新预览后才能谈执行。")
    }
}
