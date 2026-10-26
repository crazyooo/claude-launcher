import Foundation

/// Fills matrix cells using loopback hitCorrelation IPC against an active system instance.
/// Remote / application traffic cells stay blocked pending a clear window.
/// `livePassed` only increments when evidence has `collectorAuthenticated && !routingVerified`.
/// Never mutates the network or writes accepted.
public enum RouterTrafficMatrixLoopbackFiller {
    public static let policyVersion = 1
    public static let loopbackAddress = "127.0.0.1"
    public static let defaultPort = RouterSystemCompiler.controllerPort

    public struct Probe: Equatable, Sendable {
        public let cellKind: RouterTrafficMatrix.CellKind
        public let cellLabel: String
        public let address: String
        public let port: UInt16
        public let reply: RouterHitCorrelationReply

        public init(cellKind: RouterTrafficMatrix.CellKind, cellLabel: String,
                    address: String, port: UInt16, reply: RouterHitCorrelationReply) {
            self.cellKind = cellKind
            self.cellLabel = cellLabel
            self.address = address
            self.port = port
            self.reply = reply
        }

        public var isLoopbackTarget: Bool {
            address == "127.0.0.1" || address == "::1" || address == "localhost"
        }
    }

    public enum InstanceGate: Equatable, Sendable {
        case allow(instance: UUID)
        case refuse(String)
    }

    /// Loopback fill only needs an active instance — refuseOwnTun does not block loopback probes.
    public static func decideInstanceGate(systemPhase: String?, systemInstance: UUID?) -> InstanceGate {
        guard systemPhase == "active", let instance = systemInstance else {
            return .refuse("no_active_system_instance")
        }
        return .allow(instance: instance)
    }

    /// Control-plane inventory cells are the only loopback fill candidates.
    public static func loopbackCandidates(from inventory: RouterTrafficMatrix.Report) -> [RouterTrafficMatrix.Cell] {
        inventory.cells.filter { $0.kind == .controlPlaneDNS }
    }

    public static func evidence(from probes: [Probe]) -> [RouterTrafficMatrixLiveRunner.CellEvidence] {
        probes.compactMap { probe in
            guard probe.isLoopbackTarget,
                  probe.reply.outcome == "correlated",
                  probe.reply.canPromoteAccepted == false,
                  probe.reply.journalMutated == false else { return nil }
            return .init(kind: probe.cellKind, label: probe.cellLabel,
                         collectorAuthenticated: probe.reply.collectorAuthenticated,
                         routingVerified: false)
        }
    }

    public static func run(plan: RouterPlan, profile: RouterSystemProfile,
                           systemPhase: String?, systemInstance: UUID?,
                           refuseOwnTun: Bool?,
                           probes: [Probe] = []) throws -> RouterTrafficMatrixLiveRunner.Report {
        let inventory = try RouterTrafficMatrix.report(plan: plan, profile: profile)
        let instanceGate = decideInstanceGate(systemPhase: systemPhase, systemInstance: systemInstance)
        let evidence = evidence(from: probes)
        let evidenceIndex = Dictionary(
            evidence.map { ("\($0.kind.rawValue)|\($0.label)", $0) },
            uniquingKeysWith: { first, _ in first })
        let probeIndex = Dictionary(
            probes.map { ("\($0.cellKind.rawValue)|\($0.cellLabel)", $0) },
            uniquingKeysWith: { first, _ in first })

        let cells: [RouterTrafficMatrixLiveRunner.LiveCell] = inventory.cells.map { cell in
            remap(cell, instanceGate: instanceGate, refuseOwnTun: refuseOwnTun,
                  evidence: evidenceIndex["\(cell.kind.rawValue)|\(cell.label)"],
                  probe: probeIndex["\(cell.kind.rawValue)|\(cell.label)"])
        }
        let livePassed = cells.filter { $0.outcome == .livePassed }.count
        let refused = cells.filter { $0.outcome == .refused }.count
        let blocked = cells.filter { $0.outcome == .blocked }.count
        let untested = cells.filter { $0.outcome == .untested }.count
        let gate: RouterTrafficMatrixLiveRunner.GateDecision
        switch instanceGate {
        case .allow(let id): gate = .allow(instance: id)
        case .refuse(let reason): gate = .refuse(reason)
        }
        let summary: String
        switch instanceGate {
        case .refuse(let reason):
            summary = "矩阵 loopback 填格拒绝（\(reason)）：远端/应用格保持 blocked；livePassed=\(livePassed)；未改网络、未写 accepted。"
        case .allow:
            summary = "矩阵 loopback 填格（active 实例）：控制面 loopback 可经 hitCorrelation 取证；应用/远端格 blocked 待清场；livePassed=\(livePassed) 仅计 collectorAuthenticated；complete=false。"
        }
        return .init(policyVersion: RouterTrafficMatrixLiveRunner.policyVersion,
                     planDigest: inventory.planDigest, gate: gate, cells: cells,
                     applicationCaseCount: inventory.applicationCaseCount,
                     controlPlaneCaseCount: inventory.controlPlaneCaseCount,
                     livePassedCount: livePassed, refusedCount: refused, blockedCount: blocked,
                     untestedCount: untested, canClaimMatrixComplete: false,
                     networkMutated: false, acceptedWritten: false, summary: summary)
    }

    private static func remap(_ cell: RouterTrafficMatrix.Cell,
                              instanceGate: InstanceGate,
                              refuseOwnTun: Bool?,
                              evidence: RouterTrafficMatrixLiveRunner.CellEvidence?,
                              probe: Probe?) -> RouterTrafficMatrixLiveRunner.LiveCell {
        switch cell.kind {
        case .applicationTraffic, .existingConnectionMigration:
            // Loopback fill never grants the conversation clear window; app cells stay blocked
            // with precise scaffolding reasons (tun-apply-clear-window-v1).
            let window = RouterAppTrafficMatrixAttestation.ClearWindowState.productionDefault(
                systemPhase: {
                    switch instanceGate {
                    case .allow: return "active"
                    case .refuse: return nil
                    }
                }(),
                systemInstance: {
                    if case .allow(let id) = instanceGate { return id }
                    return nil
                }(),
                refuseOwnTun: refuseOwnTun,
                requireClearWouldPass: refuseOwnTun.map { !$0 })
            return RouterAppTrafficMatrixAttestation.liveCell(
                from: cell, window: window, evidence: evidence)
        case .controlPlaneDNS:
            if let evidence, evidence.countsAsLivePass {
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .livePassed,
                             reason: "loopback_hit_correlation_authenticated",
                             gaps: cell.gaps.filter { $0 != "not_live_matrix_pass" })
            }
            if let probe, probe.reply.outcome == "correlated", !probe.reply.collectorAuthenticated {
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .untested,
                             reason: "loopback_probe_returned_collector_unauthenticated",
                             gaps: cell.gaps + ["awaiting_collectorAuthenticated"])
            }
            if let probe, probe.reply.outcome == "refused" {
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .refused,
                             reason: "hit_correlation_refused:\(probe.reply.reason)",
                             gaps: cell.gaps + ["loopback_probe_refused"])
            }
            switch instanceGate {
            case .refuse(let reason):
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .refused, reason: reason,
                             gaps: cell.gaps + ["loopback_fill_refused"])
            case .allow:
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .untested,
                             reason: "loopback_hit_correlation_pending",
                             gaps: cell.gaps + ["awaiting_authenticated_loopback_probe"])
            }
        case .foreignTunnelCoexistence:
            if refuseOwnTun == true {
                return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                             family: cell.family, outcome: .blocked,
                             reason: "foreign_tunnel_clear_window_required",
                             gaps: cell.gaps)
            }
            return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                         family: cell.family, outcome: .untested,
                         reason: "coexistence_not_traffic_pass",
                         gaps: cell.gaps + ["not_live_matrix_pass"])
        case .coreExitFailClosed:
            return .init(kind: cell.kind, label: cell.label, transport: cell.transport,
                         family: cell.family, outcome: .capabilityGap,
                         reason: "pf_arming_not_confirmed",
                         gaps: cell.gaps + ["pf_preview_only_until_user_confirms"])
        }
    }
}
