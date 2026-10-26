import Foundation
import LauncherCore

/// Website observations are deliberately separate from EnvironmentReport and its verdict.
enum WebsiteResultSource: String, CaseIterable, Identifiable {
    case netCoffee, ipSuper
    var id: String { rawValue }
    var title: String { self == .netCoffee ? "Net.Coffee" : "IPSuper" }
    var url: URL {
        URL(string: self == .netCoffee ? NetCoffeeDetection.claude.url : IPSuperDetection.claude.url)!
    }
    var scope: String {
        self == .netCoffee
            ? "出口 IP、地区、Claude 连通性与网站评分"
            : "此链接提供环境风控评分，不提供出口 IP、地区或 Claude 连通性。"
    }

    func accepts(_ candidate: URL) -> Bool {
        candidate.scheme == "https" && candidate.host == url.host &&
            (candidate.port == nil || candidate.port == 443) &&
            candidate.user == nil && candidate.password == nil &&
            ["/claude", "/claude/"].contains(candidate.path)
    }

    var fields: [(id: String, label: String)] {
        switch self {
        case .netCoffee:
            return [("claudeIP", "Claude 出口 IP"), ("claudeGeo", "Claude 出口地区"),
                    ("cfIP", "Cloudflare 出口 IP"), ("cfGeo", "Cloudflare 出口地区"),
                    ("region", "地区"), ("city", "城市"), ("ipType", "IP 属性"),
                    ("score", "网站信任评分"), ("support", "Claude 支持地区"),
                    ("claude", "claude.ai"), ("anthropic", "anthropic.com")]
        case .ipSuper:
            return [("risk", "网站风险等级"), ("score", "网站风控得分"),
                    ("count", "已检测指标"), ("highRisk", "高风险特征数")]
        }
    }

    /// Only the displayed result DOM is read. No requests to private APIs or page internals.
    var extractionScript: String {
        let adapter: String
        switch self {
        case .netCoffee:
            adapter = #"""
            const recognized = !!document.querySelector('#ipHeroClaude') && !!document.querySelector('#claudeAvailContent');
            const row = (root, label) => [...document.querySelectorAll(root + ' .risk-row')]
                .find(n => text(n.querySelector('.risk-label')) === label)?.querySelector('.risk-value');
            const fields = {
                claudeIP: value(document.querySelector('#ipAddrClaude')),
                claudeGeo: value(document.querySelector('#ipGeoClaude')),
                cfIP: value(document.querySelector('#ipAddr')),
                cfGeo: value(document.querySelector('#ipGeo')),
                region: value(row('#propsContent', '地区')),
                city: value(row('#propsContent', '城市')),
                ipType: value(row('#propsContent', 'IP 属性')),
                score: value(document.querySelector('#gaugeScore')),
                support: value(document.querySelector('#claudeRegionSupport')),
                claude: value(row('#claudeAvailContent', 'claude.ai')),
                anthropic: value(row('#claudeAvailContent', 'anthropic.com'))
            };
            """#
        case .ipSuper:
            adapter = #"""
            const root = document.querySelector('.detector-container');
            const recognized = !!root?.querySelector('.summary-card');
            const metric = label => [...(root?.querySelectorAll('.metric-item') || [])]
                .find(n => text(n.querySelector('.metric-label')) === label)?.querySelector('.metric-value');
            const done = text(metric('已检测指标')) === '9/9';
            const fields = {
                risk: done ? value(root?.querySelector('.summary-header .status-badge')) : '',
                score: done ? value(metric('综合风控得分')) : '',
                count: done ? value(metric('已检测指标')) : '',
                highRisk: done ? value(metric('高风险特征数')) : ''
            };
            """#
        }
        return #"""
        (() => {
            const text = n => (n?.innerText || '').replace(/\s+/g, ' ').trim().slice(0, 240);
            const value = n => {
                if (!n || !n.getClientRects().length || n.querySelector('.loading-bar, .skeleton, .loader')) return '';
                const s = text(n);
                return /^(加载|检测|查询|获取|等待).*(中|稍候)|^loading|^checking|^[—–-]+$|^\.\.\.$/i.test(s) ? '' : s;
            };
        """# + "\n" + adapter + "\n" + #"""
            const challenge = /just a moment|attention required|verify you are human|安全验证|人机验证/i.test(document.title)
                || !!document.querySelector('#challenge-running, #challenge-stage');
            return {url: location.href, recognized, challenge, fields};
        })()
        """#
    }
}

struct WebsiteResultField: Equatable, Identifiable {
    let id: String
    let label: String
    let value: String?
}

struct WebsiteResultSnapshot: Equatable {
    let source: WebsiteResultSource
    let observedAt: Date
    let fields: [WebsiteResultField]
    var receivedCount: Int { fields.filter { $0.value != nil }.count }
    var complete: Bool { receivedCount == fields.count }

    init?(source: WebsiteResultSource, payload: Any, at: Date) {
        guard let object = payload as? [String: Any],
              let urlText = object["url"] as? String, let url = URL(string: urlText), source.accepts(url),
              object["recognized"] as? Bool == true, object["challenge"] as? Bool != true,
              let values = object["fields"] as? [String: String] else { return nil }
        self.source = source
        observedAt = at
        fields = source.fields.map { field in
            let value = values[field.id]?.components(separatedBy: .whitespacesAndNewlines)
                .filter { !$0.isEmpty }.joined(separator: " ") ?? ""
            return .init(id: field.id, label: field.label, value: value.isEmpty ? nil : String(value.prefix(240)))
        }
    }
}

enum WebsiteReadingPhase: String {
    case idle = "尚未读取", loading = "读取中", captured = "已读取网页结果"
    case partial = "仅取得部分结果", unavailable = "未取得结果", stale = "结果已过期"
}

struct WebsiteReading {
    var phase: WebsiteReadingPhase = .idle
    var snapshot: WebsiteResultSnapshot?
    var message = "点击「读取两页结果」，在本页查看网站返回的数据。"
}
