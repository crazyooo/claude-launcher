import Foundation

/// Plain-language preview of why system takeover would be refused while a foreign capture remains.
/// Does not change routes, proxies, or TUN. Never claims routing_verified or accepted.
public enum RouterCoexistenceBrief {
    public struct NetworkFacts: Equatable, Sendable {
        public let complete: Bool
        public let tunnelCaptureInterfaces: [String]
        public let connectedVPN: Bool?
        public let applicationProxyEnabled: Bool?
        public let automaticProxyEnabled: Bool?
        public let userCoreJobPresent: Bool?
        public init(complete: Bool, tunnelCaptureInterfaces: [String], connectedVPN: Bool?,
                    applicationProxyEnabled: Bool?, automaticProxyEnabled: Bool?,
                    userCoreJobPresent: Bool?) {
            self.complete = complete
            self.tunnelCaptureInterfaces = tunnelCaptureInterfaces
            self.connectedVPN = connectedVPN
            self.applicationProxyEnabled = applicationProxyEnabled
            self.automaticProxyEnabled = automaticProxyEnabled
            self.userCoreJobPresent = userCoreJobPresent
        }
    }

    public struct Report: Equatable, Sendable {
        public let title: String
        public let refuseOwnTun: Bool
        public let reasons: [String]
        public let pathNotes: [String]
        public let nextActions: [String]
        public let wouldChangeIfClear: [String]
        public let routingVerified: Bool
        public let accepted: Bool
        public init(title: String, refuseOwnTun: Bool, reasons: [String], pathNotes: [String],
                    nextActions: [String], wouldChangeIfClear: [String],
                    routingVerified: Bool = false, accepted: Bool = false) {
            self.title = title; self.refuseOwnTun = refuseOwnTun; self.reasons = reasons
            self.pathNotes = pathNotes; self.nextActions = nextActions
            self.wouldChangeIfClear = wouldChangeIfClear
            self.routingVerified = false; self.accepted = false
            _ = routingVerified; _ = accepted
        }
    }

    /// Mirrors `RouterSystemProvider.requireClear` refusal conditions without weakening them.
    public static func compose(network: NetworkFacts, path: CurrentPathPortrait.Snapshot?) -> Report {
        var reasons: [String] = []
        if !network.complete {
            reasons.append("网络观察不完整或采样期间发生变化；当前不能据此授权接管。")
        }
        if network.applicationProxyEnabled == true {
            reasons.append("系统应用代理已启用。requireClear 会拒绝启用本工具 TUN，避免外连归到代理进程后按应用分流失真。")
        }
        if network.automaticProxyEnabled == true {
            reasons.append("系统自动代理／PAC 已启用。requireClear 会拒绝启用本工具 TUN。")
        }
        if network.connectedVPN == true {
            reasons.append("系统 VPN 服务处于连接相关状态。requireClear 会拒绝启用本工具 TUN。")
        }
        if !network.tunnelCaptureInterfaces.isEmpty {
            let names = network.tunnelCaptureInterfaces.joined(separator: "、")
            reasons.append("路由表上已有转发隧道接口（\(names)）。requireClear 会拒绝启用本工具 TUN；不会自动停止你的代理客户端或其他组件。")
        }
        if network.userCoreJobPresent != false {
            reasons.append("自有管理内核任务仍在或状态未知。切换或启用前需先查询并处理，requireClear 不会在未知状态下放行。")
        }

        var pathNotes: [String] = []
        if let path {
            if path.targets.contains(where: { $0.resolved.map(CurrentPathPortrait.isFakeMappedIPv4) == true }) {
                pathNotes.append("当前走线看到 198.18.0.0/15 假地址：增强模式/TUN 多半已接管 DNS。「不经系统代理」探测仍可能走隧道，不代表没开代理。")
            }
            if path.targets.contains(where: { $0.routeKind == "tunnel" }) {
                pathNotes.append("观察目标路由经隧道。与上面的转发隧道观察一致时，本工具自己的 TUN 保持拒绝。")
            }
            for line in path.lines where line.routeKind == "tunnel" {
                pathNotes.append("已保存线路「\(line.name)」入口经隧道：默认「测试这条线路」可能失败，请用路径对照或等外部隧道让开。")
            }
            pathNotes.append(contentsOf: path.nextSteps.prefix(2))
        } else {
            pathNotes.append("尚未附带「当前走线」采样；可先打开侧栏识别，再回来对照。")
        }

        let refuse = !reasons.isEmpty
        let title: String
        if refuse {
            title = "当前条件会拒绝启用本工具 TUN（只读预览，未改网络）"
        } else if network.complete {
            title = "只读观察未看到 requireClear 已知阻挡项；仍须经系统组件正式预览，且不表示已接管或 accepted"
        } else {
            title = "观察依据不足，不能声称可以启用本工具 TUN"
        }

        var next: [String] = []
        if refuse {
            next.append("若要测已保存线路：用路径对照，或你自行让开外部隧道后再测。本工具不会替你关你的代理客户端。")
            next.append("若要启用本工具分流：须先消除上述阻挡（或你明确确认的共存窗口），再点「生成变更预览」；预览通过前不会创建 TUN。")
        } else {
            next.append("可在「系统流量路由」生成变更预览。预览会说明将创建的 TUN/DNS；应用前仍要你确认。")
        }
        next.append("本页不提升 routing_verified 或 accepted，也不代表 Desktop/CLI 通过。")

        let wouldChange = [
            "若将来观察放行且你确认应用：将创建本工具拥有的 TUN、相关路由与 DNS 拦截，并按已保存规则处理新连接。",
            "不会自动停止你的代理客户端、小火箭或其他代理；已有连接、浏览器 helper 与实际出口仍需单独验收。",
            "内核退出后的严格断流尚未验证；内部 REJECT 规则不能代替独立系统层证明。详细配方见「系统流量路由」。"
        ]

        return .init(title: title, refuseOwnTun: refuse, reasons: Array(reasons.prefix(12)),
                     pathNotes: Array(pathNotes.prefix(12)), nextActions: Array(next.prefix(8)),
                     wouldChangeIfClear: wouldChange)
    }
}
