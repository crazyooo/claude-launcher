import AppKit
import WebKit
import SwiftUI

/// Explicit, bounded reads; periodic local inspection never starts website traffic.
@MainActor final class WebsiteResultsSession: ObservableObject {
    @Published private(set) var readings: [WebsiteResultSource: WebsiteReading] = [:]
    private var readers: [WebsiteResultSource: WebsitePageReader] = [:]
    private var generation = UUID()
    var busy: Bool { !readers.isEmpty }

    func refresh() {
        guard !busy else { return }
        generation = UUID()
        let ticket = generation
        for source in WebsiteResultSource.allCases {
            readings[source] = .init(phase: .loading, message: "正在等待网站运行检测，最长 45 秒。")
            let reader = WebsitePageReader(source: source) { [weak self] reading in
                guard let self, self.generation == ticket else { return }
                if reading.phase != .loading { self.readers[source] = nil }
                self.readings[source] = reading
            }
            readers[source] = reader
            reader.start()
        }
    }

    func cancel() {
        invalidate(message: "已停止读取，请按需重新读取。")
    }

    func invalidate(message: String = "网络或配置已变化，请重新读取网站结果。") {
        generation = UUID()
        for reader in readers.values { reader.cancel() }
        readers.removeAll()
        for source in Array(readings.keys) {
            readings[source]?.phase = .stale
            readings[source]?.message = message
        }
    }

    func expire(at now: Date) {
        for source in Array(readings.keys) {
            guard let reading = readings[source], reading.phase != .loading, reading.phase != .stale,
                  let at = reading.snapshot?.observedAt,
                  now < at || now.timeIntervalSince(at) > 300 else { continue }
            readings[source]?.phase = .stale
            readings[source]?.message = "这是上次读取的结果，请重新读取后再参考。"
        }
    }
}

/// A fresh, nonpersistent WebKit page executes the website's normal public UI.
/// The reader has no access to browser cookies, Claude credentials or local reports.
@MainActor final class WebsitePageReader: NSObject, WKNavigationDelegate {
    private let source: WebsiteResultSource
    private let timeout: TimeInterval
    private let update: (WebsiteReading) -> Void
    private var webView: WKWebView?
    private var poll: Timer?
    private var deadline: Timer?
    private var evaluating = false
    private var latest: WebsiteResultSnapshot?
    private var previousFields: [WebsiteResultField]?
    private var recognized = false

    init(source: WebsiteResultSource, timeout: TimeInterval = 45, update: @escaping (WebsiteReading) -> Void) {
        self.source = source; self.timeout = timeout; self.update = update
    }

    deinit { poll?.invalidate(); deadline?.invalidate() }

    func start() {
        guard webView == nil else { return }
        let configuration = WKWebViewConfiguration()
        configuration.websiteDataStore = .nonPersistent()
        configuration.preferences.javaScriptCanOpenWindowsAutomatically = false
        let page = WKWebView(frame: NSRect(x: 0, y: 0, width: 1200, height: 900), configuration: configuration)
        page.navigationDelegate = self
        webView = page
        deadline = Timer.scheduledTimer(withTimeInterval: timeout, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.timedOut() }
        }
        poll = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.sample() }
        }
        page.load(URLRequest(url: source.url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout))
    }

    func cancel() {
        poll?.invalidate(); deadline?.invalidate()
        poll = nil; deadline = nil
        webView?.navigationDelegate = nil
        webView?.stopLoading()
        webView = nil
    }

    private func sample() {
        guard let page = webView, !evaluating, let url = page.url, source.accepts(url) else { return }
        evaluating = true
        page.evaluateJavaScript(source.extractionScript, in: nil, in: .defaultClient) { [weak self, weak page] result in
            guard let self, let page, self.webView === page else { return }
            self.evaluating = false
            guard case .success(let payload) = result else { return }
            if (payload as? [String: Any])?["challenge"] as? Bool == true {
                self.finish(message: "网站要求验证，请打开原网页处理；本次读取已停止。")
                return
            }
            guard let snapshot = WebsiteResultSnapshot(source: self.source, payload: payload, at: Date()) else { return }
            self.recognized = true
            let stable = snapshot.complete && self.previousFields == snapshot.fields
            self.previousFields = snapshot.fields
            // An empty new sample must never keep an earlier successful value alive.
            self.latest = snapshot
            if stable {
                self.finish(message: "已读取网页显示值；网站自身的失败结果也会原样显示。")
            } else {
                self.update(.init(phase: .loading, snapshot: snapshot,
                                  message: "已取得 \(snapshot.receivedCount)/\(snapshot.fields.count) 项，等待其余结果…"))
            }
        }
    }

    private func timedOut() {
        finish(message: recognized ? "等待网站结果超时；未返回的字段保留为未取得。" : "网页未加载完成或结果结构已变化；未取得可识别的检测结果。")
    }

    private func finish(message: String) {
        guard webView != nil else { return }
        let snapshot = latest
        let phase: WebsiteReadingPhase = snapshot?.complete == true ? .captured :
            ((snapshot?.receivedCount ?? 0) > 0 ? .partial : .unavailable)
        cancel()
        update(.init(phase: phase, snapshot: snapshot, message: message))
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) { sample() }
    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) { failed(error) }
    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) { failed(error) }
    func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        finish(message: "网页进程已结束，请按需重新读取。")
    }

    private func failed(_ error: Error) {
        let code = (error as NSError).code
        let detail = [-1200, -1201, -1202, -1203, -1204, -1205, -1206].contains(code)
            ? "网页 TLS 或证书校验失败；未绕过校验。"
            : "网页加载失败（错误码 \(code)）；请检查线路或打开原网页。"
        finish(message: detail)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        // Subresources run normally; top-level redirects cannot turn the reader into a browser.
        guard navigationAction.targetFrame?.isMainFrame != false else { decisionHandler(.allow); return }
        guard let url = navigationAction.request.url, source.accepts(url) else {
            decisionHandler(.cancel)
            finish(message: "网站跳转离开指定检测页，请打开原网页查看。")
            return
        }
        decisionHandler(.allow)
    }
}
