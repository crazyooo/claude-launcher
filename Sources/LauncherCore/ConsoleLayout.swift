import Foundation

/// P2 display copy for the right-hand detail panel. Text only: nothing here is read by launch decisions.
public enum GateCopy {
    public static let ids = ["exit", "block", "protocols", "routing", "startup", "background"]

    /// What the gate's evidence actually covers.
    public static func scope(_ id: String) -> String {
        switch id {
        case "exit": return "本轮预检对当前入口目标站点的 HTTPS trace 出口，与你确认的固定出口比对。"
        case "block": return "root 后台对批准目的地址的 PF 规则观测，以及经过自有连接器的转发开关。"
        case "protocols": return "受管理配置仅接受 IPv4 本地入口和出口基准，连接器拒绝显式 IPv6 目标；远端域名地址族与 IPv6 / UDP 旁路尚未验收。"
        case "routing": return "本机 DNS 配置诊断、自有连接器的连接计数，以及可选 Mihomo 控制接口的连接表。"
        case "startup": return "当前入口最近一次预检（30 秒有效），以及统一启动门禁的许可状态。"
        case "background": return "root 后台的规则 / DNS 证据续采，以及连接器守卫心跳。"
        default: return "该项写明的检查范围。"
        }
    }

    /// What the gate's evidence can NOT prove, even when every item in it is observed.
    public static func limitation(_ id: String) -> String {
        switch id {
        case "exit": return "出口 IP 匹配不能证明住宅属性，也不能代表应用实际业务会话走同一出口。"
        case "block": return "规则可见不等于断流生效；代理退出、TUN 消失、已有连接等故障场景尚未验收。"
        case "protocols": return "接口存在与否、单个 IPv6 阻断命中，都不能证明全路径没有旁路。"
        case "routing": return "控制接口看不到完全绕过代理内核的连接；空连接表不能证明没有泄漏。"
        case "startup": return "网络预检匹配不会解锁受保护启动；所有启动入口仍需严格门禁验收。"
        case "background": return "后台持续观测不等于持续强制隔离；自动修复不授予启动许可。"
        default: return "已观测只覆盖该项写明的范围。"
        }
    }

    /// One concrete next step, worst evidence first. Never suggests that the UI can unlock launch.
    public static func nextStep(_ gate: ConsoleGate, pfGuide: FaultGuide? = nil) -> String {
        switch gate.state {
        case .failed:
            if ["block", "background"].contains(gate.id), let pfGuide { return pfGuide.nextStep }
            switch gate.id {
            case "exit", "startup": return "在你的代理客户端客户端确认节点可用、出口与确认出口一致后，点“重新检测”。"
            case "protocols", "routing": return "查看下方异常项的说明，修正本机配置后点“重新检测”。"
            default: return "查看下方异常项的说明；处理后点“重新检测”。"
            }
        case .expired:
            if ["block", "background"].contains(gate.id) {
                return "等待后台报告刷新（约 3 秒）；若持续过期，在诊断工作台查看 PF 后台状态。"
            }
            return "点“重新检测”取得新证据；过期结果不会被当作通过。"
        case .checking:
            return "等待本轮检测完成。"
        case .unverified, .observed:
            return "剩余未验证项尚无验收方法或未接入数据源，界面操作不能把它们变为已观测；受保护启动保持锁定。"
        }
    }
}

extension GateCopy {
    /// Next step for a non-gate topology node.
    public static func nextStep(_ node: TopologyNode) -> String {
        switch node.state {
        case .failed: return node.column == .infra && ["infra-pf", "infra-observer"].contains(node.id)
            ? "在诊断工作台查看 PF 后台故障说明，按其中的终端复检步骤处理；界面不会清除锁存故障。"
            : "查看上面的证据说明，处理后点“重新检测”。"
        case .expired: return "点“重新检测”或等待自动刷新；过期结果不会被当作通过。"
        case .checking: return "等待本轮检测完成。"
        case .unverified: return node.id == "infra-mihomo"
            ? "可选：在连接监控页接入已确认的 Mihomo 控制接口；接入只用于观察，不授予启动许可。"
            : "尚未取得数据；点“重新检测”。未验证项不会计为通过。"
        case .observed: return "无需操作；这项证据只覆盖上面写明的范围，受保护启动仍锁定。"
        }
    }
}

/// P2 overview topology. Edges are only drawn from data we have:
/// `.observedPath` (solid) = the path the current, passing preflight request actually used;
/// `.dependency` (dashed) = which gate depends on which component. A dependency edge never means traffic flowed.
public struct TopologyNode: Identifiable, Equatable {
    public enum Column: Int, CaseIterable { case app, gate, infra, service
        public var title: String {
            switch self { case .app: return "应用入口"; case .gate: return "检查门禁"; case .infra: return "本机与代理"; case .service: return "目标服务" }
        }
    }
    public let id: String
    public let column: Column
    public let title: String
    public let subtitle: String
    public let state: DisplayState
    public let symbol: String
    public let scope: String
    public let limitation: String
    public let facts: [String]
    /// Sample / validity times shown in the detail panel; empty when there is no current sample.
    public var times: [String] = []
}

public struct TopologyEdge: Identifiable, Equatable {
    public enum Kind: String { case observedPath, dependency
        public var legend: String {
            switch self {
            case .observedPath: return "实线：本轮预检请求实际经过的路径，仅在预检有效期内显示"
            case .dependency: return "虚线：依赖关系，不代表流量经过"
            }
        }
    }
    public var id: String { from + ">" + to }
    public let from: String
    public let to: String
    public let kind: Kind
}

public struct Topology {
    public let nodes: [TopologyNode]
    public let edges: [TopologyEdge]
    public func nodes(in column: TopologyNode.Column) -> [TopologyNode] { nodes.filter { $0.column == column } }
    public func node(_ id: String) -> TopologyNode? { nodes.first { $0.id == id } }

    public static let footnote = "只画有数据支撑的连线：实线来自当前有效的预检，虚线只表示依赖。未取得数据的中转节点不会补画；没有实线时表示本轮没有可用路径证据。"

    /// `statuses` holds the per-entry preflight status the app already computes; `selected` is the entry being checked.
    public static func build(selected: CheckTarget, statuses: [CheckTarget: ProtectionStatus], report: PreflightReport?,
                             gates: [ConsoleGate], firewall: PFObservation?, connector: ConnectorSnapshot?,
                             controller: ControllerSnapshot?, endpoint: String, now: Date) -> Topology {
        var nodes: [TopologyNode] = []
        var edges: [TopologyEdge] = []
        func times(_ status: ProtectionStatus?) -> [String] {
            guard let status, status.display != .checking, let checked = status.checkedAt else { return [] }
            return ["预检完成于 " + PFObservation.clock(checked)] +
                (status.validUntil.map { ["预检有效至 " + PFObservation.clock($0)] } ?? ["预检已失效（不再作为当前证据）"])
        }
        let current = statuses[selected]
        let pathEvidence = current?.networkPassed == true && current?.display == .observed
        let bound = report?.target == selected ? report : nil

        for target in CheckTarget.allCases {
            let status = statuses[target]
            nodes.append(.init(id: "app-" + target.rawValue, column: .app, title: target.title,
                               subtitle: status?.networkStatus ?? "未验证（尚未检测）", state: status?.display ?? .unverified,
                               symbol: target == .vscode ? "chevron.left.forwardslash.chevron.right" : "desktopcomputer",
                               scope: "该入口最近一次网络预检（30 秒有效）。",
                               limitation: "预检只看本轮探测请求；不代表该应用的所有连接都经过受控路径，受保护启动仍锁定。",
                               facts: [status?.explanation ?? "尚未取得该入口的检测结果。"] +
                                   (status?.checkedAt.map { ["预检完成于 " + PFObservation.clock($0)] } ?? []),
                               times: times(status)))
        }
        for gate in gates {
            nodes.append(.init(id: "gate-" + gate.id, column: .gate, title: gate.title, subtitle: gate.summary, state: gate.state,
                               symbol: gate.symbol, scope: GateCopy.scope(gate.id), limitation: GateCopy.limitation(gate.id),
                               facts: gate.evidence.map { "\($0.state.label) · \($0.title)：\($0.detail)" }))
        }
        edges.append(.init(from: "app-" + selected.rawValue, to: "gate-startup", kind: .dependency))

        let pf = firewall.flatMap { $0.isCurrent(at: now) ? $0 : nil }
        let owned = connector.flatMap { $0.isCurrent(at: now) ? $0 : nil }
        let live = controller.flatMap { $0.isCurrent(endpoint: endpoint, now: now) ? $0 : nil }
        let entrance = current?.entrance ?? "尚未取得"
        let pfState: DisplayState = firewall == nil ? .unverified : pf == nil ? .expired : pf!.rules_observed ? .observed : .failed
        let observerState: DisplayState = firewall == nil ? .unverified : pf == nil ? .expired :
            pf!.manual_recheck_required ? .failed : pf!.evidence_fresh ? .observed : .checking
        let infra: [TopologyNode] = [
            .init(id: "infra-proxy", column: .infra, title: "代理入口", subtitle: entrance,
                  state: current?.display ?? .unverified, symbol: "network",
                  scope: "预检请求选用的本机代理入口。", limitation: "入口可达不代表所有应用连接都经过它。",
                  facts: ["预检状态：" + (current?.networkStatus ?? "未验证（尚未检测）")], times: times(current)),
            .init(id: "infra-connector", column: .infra, title: "自有连接器", subtitle: owned.map { "当前 \($0.connectionCount) 条连接" } ?? "没有新鲜状态",
                  state: connector == nil ? .unverified : owned == nil ? .expired : .observed, symbol: "cable.connector",
                  scope: "经过自有连接器的转发开关与连接计数。", limitation: "只覆盖经过此连接器的流量；应用完整隔离尚未验收。",
                  facts: [owned?.explanation ?? "没有新鲜的连接器状态（超过 4 秒或未连接）。"],
                  times: owned.map { ["连接器采样于 " + PFObservation.clock($0.sampledAt)] } ?? []),
            .init(id: "infra-pf", column: .infra, title: "PF 目的地址规则", subtitle: pfState == .observed ? "规则已观测（仅限批准地址）" : pfState.label,
                  state: pfState, symbol: "lock.shield",
                  scope: "root 后台对批准目的地址的规则观测。", limitation: GateCopy.limitation("block"),
                  facts: ["PF 后台：" + PFObservation.statusLine(firewall, now: now)],
                  times: pf.map { ["后台检查于 " + PFObservation.clock($0.checkedAtDate)] } ?? []),
            .init(id: "infra-observer", column: .infra, title: "DNS 证据后台", subtitle: PFObservation.statusLine(firewall, now: now),
                  state: observerState, symbol: "waveform.path.ecg",
                  scope: "root 后台对目标域名 DNS 与出口证据的续采。", limitation: GateCopy.limitation("background"),
                  facts: [pf?.diagnosticDescription ?? "后台报告缺失或已过期。"] + (pf?.diagnosticLines(at: now) ?? []),
                  times: (pf.map { ["后台检查于 " + PFObservation.clock($0.checkedAtDate)] } ?? []) +
                      (observerState == .observed ? pf?.evidenceExpiresDate.map { ["DNS 证据有效至 " + PFObservation.clock($0)] } ?? [] : [])),
            .init(id: "infra-mihomo", column: .infra, title: "Mihomo 控制接口", subtitle: live.map { "\($0.totalConnections) 条活跃连接" } ?? "未接入",
                  state: live == nil ? .unverified : .observed, symbol: "point.3.connected.trianglepath.dotted",
                  scope: "可选的代理内核连接表（非原子采样）。", limitation: GateCopy.limitation("routing"),
                  facts: [live == nil ? "未接入已确认的控制接口。HTTP 代理入口不等于控制接口。" : "进程归属和实际出口仍需独立确认。"],
                  times: live.map { ["控制接口采样于 " + PFObservation.clock(Date(timeIntervalSince1970: $0.completedAt))] } ?? [])
        ]
        nodes += infra
        for (gate, component) in [("exit", "infra-proxy"), ("block", "infra-pf"), ("block", "infra-connector"),
                                  ("routing", "infra-connector"), ("routing", "infra-mihomo"),
                                  ("background", "infra-observer"), ("background", "infra-connector")]
            where gates.contains(where: { $0.id == gate }) {
            edges.append(.init(from: "gate-" + gate, to: component, kind: .dependency))
        }

        for host in selected.hosts {
            let observation = bound?.observations.first { $0.host == host }
            let state: DisplayState
            if current?.display == .checking { state = .checking }
            else if observation == nil { state = current?.display == .expired ? .expired : .unverified }
            else if current?.display == .expired { state = .expired }
            else { state = observation!.check.result == .passed && observation!.ip != nil ? .observed : .failed }
            nodes.append(.init(id: "svc-" + host, column: .service, title: host,
                               subtitle: state == .observed ? "探测出口 " + (observation?.ip ?? "") : state.label,
                               state: state, symbol: "globe",
                               scope: "本轮预检对该域名的 HTTPS trace。", limitation: "trace 出口只代表这一次探测请求，不代表应用会话。",
                               facts: observation.map { o in
                                   ["trace 出口：\(o.ip ?? "未取得")", "探测结果：\(o.check.result == .passed ? "出口匹配" : "未通过")",
                                    "耗时 \(o.milliseconds) ms"] + (o.country.map { ["trace 地区标记：\($0)（不证明住宅属性）"] } ?? [])
                               } ?? ["本轮没有该域名的探测结果。"],
                               times: state == .observed || state == .failed ? times(current) : []))
            if pathEvidence && state == .observed {
                edges.append(.init(from: "infra-proxy", to: "svc-" + host, kind: .observedPath))
            }
        }
        if pathEvidence && edges.contains(where: { $0.kind == .observedPath }) {
            edges.insert(.init(from: "app-" + selected.rawValue, to: "infra-proxy", kind: .observedPath), at: 0)
        }
        return .init(nodes: nodes, edges: edges)
    }
}

extension Topology {
    public var hasObservedPath: Bool { edges.contains { $0.kind == .observedPath } }
    public func edges(touching id: String) -> [TopologyEdge] { edges.filter { $0.from == id || $0.to == id } }
    /// The node itself plus every node one edge away; used for hover / selection highlight.
    public func neighborhood(of id: String) -> Set<String> {
        Set([id] + edges(touching: id).flatMap { [$0.from, $0.to] })
    }
    public func describe(_ edge: TopologyEdge, from id: String) -> String {
        let other = edge.from == id ? edge.to : edge.from
        let name = node(other)?.title ?? other
        let arrow = edge.from == id ? "→" : "←"
        switch edge.kind {
        case .observedPath: return "实线 \(arrow) \(name)：本轮预检请求经过（仅预检有效期内）"
        case .dependency: return "虚线 \(arrow) \(name)：依赖关系，不代表流量经过"
        }
    }
    public var pathNote: String {
        hasObservedPath ? "实线来自当前有效的预检，约 30 秒后自动消失；它只代表这次探测请求，不代表应用会话。"
                        : "当前没有实线：预检未通过、已过期或尚未检测。点“重新检测”后，若出口匹配，30 秒内会显示实线。"
    }
    public static let noEdgesNote = "没有连线：这个节点暂无路径证据，也没有登记的依赖。"
}
