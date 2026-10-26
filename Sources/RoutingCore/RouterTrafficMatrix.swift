import Foundation

/// Executable traffic-matrix inventory for a plan. Enumerates required TCP/UDP/DNS/IPv4/IPv6
/// cases plus product-level rows (existing connections, core-exit fault, foreign tunnel).
/// Never claims live matrix completion or writes accepted. Does not change the network.
public enum RouterTrafficMatrix {
    public static let policyVersion = 1

    public enum CellKind: String, Equatable, Sendable, CaseIterable {
        case applicationTraffic
        case controlPlaneDNS
        case existingConnectionMigration
        case coreExitFailClosed
        case foreignTunnelCoexistence
    }

    public enum CellStatus: String, Equatable, Sendable {
        /// Required but no offline or live evidence.
        case notRun
        /// Offline harness confirmed the cell exists in the required set / recipe shape only.
        case fixtureShapeOnly
        /// Live takeover window would be needed; not executed.
        case liveUntested
        /// Independent capability still missing (e.g. fail-closed PF not armed).
        case capabilityGap
    }

    public struct Cell: Equatable, Sendable {
        public let kind: CellKind
        public let label: String
        public let transport: String?
        public let family: String?
        public let status: CellStatus
        public let gaps: [String]
    }

    public struct Report: Equatable, Sendable {
        public let policyVersion: Int
        public let planDigest: String
        public let cells: [Cell]
        public let applicationCaseCount: Int
        public let controlPlaneCaseCount: Int
        public let livePassedCount: Int
        public let canClaimMatrixComplete: Bool
        public let summary: String

        public var countsByStatus: [CellStatus: Int] {
            Dictionary(grouping: cells, by: \.status).mapValues(\.count)
        }
    }

    /// Production inventory: every required cell is honestly untested or a capability gap.
    public static func report(plan: RouterPlan, profile: RouterSystemProfile) throws -> Report {
        try build(plan: plan, profile: profile, markApplicationFixtureShape: false)
    }

    /// Offline harness: application/control-plane required sets are marked fixtureShapeOnly
    /// (shape inventory only). Product rows stay liveUntested / capabilityGap.
    public static func fixtureShapeInventory(plan: RouterPlan,
                                             profile: RouterSystemProfile) throws -> Report {
        try build(plan: plan, profile: profile, markApplicationFixtureShape: true)
    }

    private static func build(plan: RouterPlan, profile: RouterSystemProfile,
                              markApplicationFixtureShape: Bool) throws -> Report {
        let digest = try RouterSystemProvider.digest(plan: plan, profile: profile)
        let traffic = try RouterTrafficCoveragePolicy.requirements(plan)
        let control = try RouterControlPlaneCoverage.requirements(plan: plan, profile: profile)
        let appStatus: CellStatus = markApplicationFixtureShape ? .fixtureShapeOnly : .notRun
        let appGap = markApplicationFixtureShape
            ? "offline_required_set_shape_only"
            : "live_collector_unavailable"
        var cells: [Cell] = []
        for item in traffic {
            cells.append(.init(
                kind: .applicationTraffic,
                label: "rule=\(item.rule?.uuidString ?? "fallback") · \(item.variation.rawValue) · \(item.transport.rawValue)/\(item.family.rawValue)",
                transport: item.transport.rawValue, family: item.family.rawValue, status: appStatus,
                gaps: [appGap, "not_live_matrix_pass"]))
        }
        for item in control {
            cells.append(.init(
                kind: .controlPlaneDNS,
                label: "\(item.id.role.rawValue) · \(item.id.transport.rawValue)/\(item.id.family.rawValue) · \(item.id.query.rawValue)",
                transport: item.id.transport.rawValue, family: item.id.family.rawValue, status: appStatus,
                gaps: item.gaps.map(\.rawValue) + ["not_live_matrix_pass"]))
        }
        cells.append(.init(
            kind: .existingConnectionMigration,
            label: "existing_connections_do_not_automatically_migrate",
            transport: nil, family: nil, status: .liveUntested,
            gaps: ["existing_connection_matrix_untested", "requires_live_takeover_window"]))
        let failClosed = RouterCoreExitFailClosed.productionGap(for: plan)
        cells.append(.init(
            kind: .coreExitFailClosed,
            label: failClosed.status,
            transport: nil, family: nil,
            status: failClosed.verified ? .fixtureShapeOnly : .capabilityGap,
            gaps: failClosed.blockers + ["reject_rules_are_not_proof"]))
        cells.append(.init(
            kind: .foreignTunnelCoexistence,
            label: "requireClear_foreign_tunnel_or_system_proxy",
            transport: nil, family: nil, status: .liveUntested,
            gaps: ["foreign_tunnel_clear_window_required", "no_silent_stop_of_peers"]))

        let summary: String
        if markApplicationFixtureShape {
            summary = "离线矩阵配方已枚举 \(cells.count) 格（应用 \(traffic.count)、控制面 \(control.count)）；无 live 通过，不能提升 accepted。"
        } else {
            summary = "流量矩阵尚未 live 验收：TCP/UDP/DNS/双栈与已有连接/故障格均为未测或能力缺口；REJECT≠断流证明。"
        }
        return .init(policyVersion: policyVersion, planDigest: digest, cells: cells,
                     applicationCaseCount: traffic.count, controlPlaneCaseCount: control.count,
                     livePassedCount: 0, canClaimMatrixComplete: false, summary: summary)
    }
}
