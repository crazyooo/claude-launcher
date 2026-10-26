import Foundation

/// One bounded request to a fixed loopback origin. Never inherits a system proxy or follows redirects.
final class RouterLocalRequest: NSObject, URLSessionDataDelegate {
    private var bytes = Data()
    private var continuation: CheckedContinuation<Data, Error>?
    private var session: URLSession?
    private var accepted = false
    private var expectedStatus = 200

    static func version(port: UInt16, secret: String) async throws -> String {
        // A controller that ignores bearer authentication cannot prove this instance's identity.
        _ = try await RouterLocalRequest().get(port: port, secret: "invalid-" + UUID().uuidString, status: 401)
        let request = RouterLocalRequest()
        let data = try await request.get(port: port, secret: secret, status: 200)
        struct Version: Decodable { let version: String }
        guard let value = try? JSONDecoder().decode(Version.self, from: data), value.version == "v" + RouterCoreRelease.version else {
            throw RouterRuntimeError.ownershipUnknown
        }
        return value.version
    }
    private func get(port: UInt16, secret: String, status: Int) async throws -> Data {
        expectedStatus = status
        let config = URLSessionConfiguration.ephemeral
        config.connectionProxyDictionary = ["HTTPEnable": 0, "HTTPSEnable": 0, "SOCKSEnable": 0,
                                            "ProxyAutoConfigEnable": 0, "ProxyAutoDiscoveryEnable": 0]
        config.httpCookieStorage = nil; config.urlCache = nil
        config.timeoutIntervalForRequest = 2; config.timeoutIntervalForResource = 3
        let queue = OperationQueue(); queue.maxConcurrentOperationCount = 1
        let session = URLSession(configuration: config, delegate: self, delegateQueue: queue)
        self.session = session
        var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/version")!)
        request.setValue("Bearer " + secret, forHTTPHeaderField: "Authorization")
        request.cachePolicy = .reloadIgnoringLocalCacheData
        return try await withCheckedThrowingContinuation { continuation in
            self.continuation = continuation; session.dataTask(with: request).resume()
        }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) { completionHandler(nil) }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping (URLSession.ResponseDisposition) -> Void) {
        accepted = (response as? HTTPURLResponse)?.statusCode == expectedStatus && response.expectedContentLength <= 16_384
        completionHandler(accepted ? .allow : .cancel)
    }
    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        if bytes.count + data.count > 16_384 { accepted = false; dataTask.cancel() }
        else { bytes.append(data) }
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        let continuation = self.continuation; self.continuation = nil
        if error == nil && accepted { continuation?.resume(returning: bytes) }
        else { continuation?.resume(throwing: RouterRuntimeError.operationFailed) }
        session.invalidateAndCancel(); self.session = nil
    }
}
