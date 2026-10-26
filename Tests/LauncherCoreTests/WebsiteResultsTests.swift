import XCTest
import WebKit
@testable import LauncherApp

final class WebsiteResultsTests: XCTestCase {
    func testSourceBoundaryAndPartialFailuresStayLiteral() throws {
        let payload: [String: Any] = ["url": "https://ip.net.coffee/claude/", "recognized": true,
            "fields": ["claudeIP": "获取失败", "claude": "不可访问", "region": "", "cfIP": "203.0.113.4",
                       "private": "must not be imported"]]
        let result = try XCTUnwrap(WebsiteResultSnapshot(source: .netCoffee, payload: payload, at: Date()))
        XCTAssertEqual(result.receivedCount, 3)
        XCTAssertFalse(result.complete)
        XCTAssertEqual(result.fields.first { $0.id == "claude" }?.value, "不可访问")
        XCTAssertNil(result.fields.first { $0.id == "region" }?.value)
        XCTAssertFalse(result.fields.contains { $0.id == "private" })
        XCTAssertNil(WebsiteResultSnapshot(source: .ipSuper, payload: payload, at: Date()))
        for url in ["http://ip.net.coffee/claude/", "https://ip.net.coffee.evil/claude/",
                    "https://user@ip.net.coffee/claude/", "https://ip.net.coffee/", "https://ip.net.coffee:444/claude/"] {
            XCTAssertFalse(WebsiteResultSource.netCoffee.accepts(try XCTUnwrap(URL(string: url))))
        }
    }

    func testChallengeAndUnrecognizedPagesDoNotBecomeEvidence() {
        for flags in [["recognized": false], ["recognized": true, "challenge": true]] {
            var payload: [String: Any] = ["url": WebsiteResultSource.ipSuper.url.absoluteString,
                                         "fields": ["score": "0/100"]]
            flags.forEach { payload[$0.key] = $0.value }
            XCTAssertNil(WebsiteResultSnapshot(source: .ipSuper, payload: payload, at: Date()))
        }
    }

    @MainActor func testRenderedNetCoffeeDOMKeepsLoadingUnknownAndReadsFailure() async throws {
        let source = WebsiteResultSource.netCoffee
        let page = WKWebView(frame: .init(x: 0, y: 0, width: 1200, height: 900))
        let html = """
        <div id="ipHeroClaude"><div id="ipAddrClaude"><div class="loading-bar">203.0.113.99</div></div>
        <div id="ipGeoClaude">获取失败</div></div>
        <div id="ipAddr">203.0.113.4</div>
        <div id="propsContent"><div class="risk-row"><span class="risk-label">地区</span><span class="risk-value">United States</span></div></div>
        <div id="claudeAvailContent"><div class="risk-row"><span class="risk-label">claude.ai</span><span class="risk-value">不可访问</span></div>
        <div class="risk-row"><span class="risk-label">anthropic.com</span><span class="risk-value">较慢 4905ms</span></div></div>
        <div id="claudeRegionSupport" style="display:none">正常</div>
        <script>window.secret='must not be read'</script>
        """
        try await load(html, into: page, source: source)
        defer { page.stopLoading() }
        let payload = try await page.evaluateJavaScript(source.extractionScript, in: nil, contentWorld: .defaultClient)
        let result = try XCTUnwrap(WebsiteResultSnapshot(source: source, payload: payload as Any, at: Date()))
        XCTAssertNil(result.fields.first { $0.id == "claudeIP" }?.value)
        XCTAssertNil(result.fields.first { $0.id == "support" }?.value)
        XCTAssertEqual(result.fields.first { $0.id == "claudeGeo" }?.value, "获取失败")
        XCTAssertEqual(result.fields.first { $0.id == "region" }?.value, "United States")
        XCTAssertEqual(result.fields.first { $0.id == "claude" }?.value, "不可访问")
        XCTAssertEqual(result.fields.first { $0.id == "anthropic" }?.value, "较慢 4905ms")
        XCTAssertFalse(result.complete)
    }

    @MainActor func testIPSuperDoesNotPublishItsInitialZeroBeforeNineChecksFinish() async throws {
        let source = WebsiteResultSource.ipSuper
        let page = WKWebView(frame: .init(x: 0, y: 0, width: 1200, height: 900))
        let html = """
        <div class="detector-container"><div class="summary-card">
        <div class="summary-header"><span class="status-badge">环境安全</span></div>
        <div class="metric-item"><span class="metric-label">综合风控得分</span><span class="metric-value">0/100</span></div>
        <div class="metric-item"><span class="metric-label">已检测指标</span><span class="metric-value" id="count">0/9</span></div>
        <div class="metric-item"><span class="metric-label">高风险特征数</span><span class="metric-value">0</span></div>
        </div></div>
        """
        try await load(html, into: page, source: source)
        defer { page.stopLoading() }
        var payload = try await page.evaluateJavaScript(source.extractionScript, in: nil, contentWorld: .defaultClient)
        XCTAssertEqual(WebsiteResultSnapshot(source: source, payload: payload as Any, at: Date())?.receivedCount, 0)
        _ = try await page.evaluateJavaScript("document.querySelector('#count').innerText = '9/9'")
        payload = try await page.evaluateJavaScript(source.extractionScript, in: nil, contentWorld: .defaultClient)
        XCTAssertEqual(WebsiteResultSnapshot(source: source, payload: payload as Any, at: Date())?.complete, true)
    }

    @MainActor private func load(_ html: String, into page: WKWebView, source: WebsiteResultSource) async throws {
        let loaded = expectation(description: "local HTML loaded")
        let delegate = WebsiteFixtureNavigation { loaded.fulfill() }
        page.navigationDelegate = delegate
        page.loadHTMLString(html, baseURL: source.url)
        await fulfillment(of: [loaded], timeout: 10)
        withExtendedLifetime(delegate) {}
        page.navigationDelegate = nil
    }
}

@MainActor private final class WebsiteFixtureNavigation: NSObject, WKNavigationDelegate {
    let loaded: () -> Void
    init(loaded: @escaping () -> Void) { self.loaded = loaded }
    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { loaded() }
}

final class WebsiteResultsLiveTests: XCTestCase {
    @MainActor func testRealWebsiteReadback() async throws {
        guard ProcessInfo.processInfo.environment["CLAUDE_LAUNCHER_LIVE_WEBSITES"] == "1" else {
            throw XCTSkip("Opt-in only: opens the two real public detection pages in WebKit.")
        }
        let session = WebsiteResultsSession()
        session.refresh()
        for _ in 0..<500 {
            if !session.busy { break }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        defer { session.cancel() }
        XCTAssertFalse(session.busy)
        for source in WebsiteResultSource.allCases {
            let reading = try XCTUnwrap(session.readings[source])
            print("WEBSITE_LIVE \(source.title): \(reading.phase.rawValue) — \(reading.message)")
            for field in reading.snapshot?.fields ?? [] { print("  \(field.label): \(field.value ?? "未取得")") }
            XCTAssertGreaterThan(reading.snapshot?.receivedCount ?? 0, 0, source.title)
        }
        session.invalidate()
        XCTAssertTrue(session.readings.values.allSatisfy { $0.phase == .stale })
    }
}
