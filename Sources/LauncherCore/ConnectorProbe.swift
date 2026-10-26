import Foundation
import Security

struct ConnectorProbeResult: Sendable {
    var samples: [String: String]
    var services: [String: ConnectorServiceResponse] = [:]
    var settled: Bool
}

enum ConnectorProbeProfile: Sendable { case traceOnly, coordinatedRecovery }

enum ConnectorService: String, CaseIterable, Sendable {
    case desktop, api
    var host: String { self == .desktop ? "claude.ai" : "api.anthropic.com" }
    var url: String { "https://" + host + (self == .desktop ? "/" : "/v1/messages") }
}

struct ConnectorServiceResponse: Codable, Sendable {
    let status: Int
    var reachable: Bool { (200...499).contains(status) && status != 429 }
    static func complete(_ values: [String: Self]) -> Bool {
        Set(values.keys) == Set(ConnectorService.allCases.map(\.rawValue)) && values.values.allSatisfy(\.reachable)
    }
}

enum ConnectorProbe {
    static func token() -> String? {
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return nil }
        return bytes.map { String(format: "%02x", $0) }.joined()
    }
    struct Invocation: Sendable {
        let arguments: [String]
        let input: Data
        let timeout: Double
    }
    private enum Observation: Sendable {
        case trace(String, String?, Bool)
        case service(String, ConnectorServiceResponse?, Bool)
    }
    static func serviceInvocation(_ service: ConnectorService, port: UInt16, token: String) -> Invocation {
        .init(arguments: ["-q", "--config", "-", "--proxy-basic", "--silent", "--head", "--output", "/dev/null",
                          "--proxy", "http://127.0.0.1:\(port)", "--noproxy", "", "--connect-timeout", "3", "--max-time", "6",
                          "--proto", "=https", "--write-out", "%{http_code}", service.url],
              input: Data("proxy-user = \"probe:\(token)\"\n".utf8), timeout: 7)
    }
    static func serviceResponse(_ result: BoundedProcess.Capture) -> ConnectorServiceResponse? {
        guard result.complete, result.data.count == 3, result.data.allSatisfy({ (48...57).contains($0) }),
              let code = Int(String(decoding: result.data, as: UTF8.self)), (100...599).contains(code) else { return nil }
        return .init(status: code)
    }
    static func sample(port: UInt16, token: String, profile: ConnectorProbeProfile,
                       run: @escaping @Sendable (Invocation) -> BoundedProcess.Capture = {
                           BoundedProcess.capture(executable: "/usr/bin/curl", arguments: $0.arguments, timeout: $0.timeout, input: $0.input)
                       }) async -> ConnectorProbeResult {
        guard port > 0, token.utf8.count == 64, token.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            return .init(samples: [:], settled: true)
        }
        return await withTaskGroup(of: Observation.self) { group in
            for host in ConnectorConfiguration.hosts {
                group.addTask {
                    let result = run(.init(arguments: [
                        "-q", "--config", "-", "--proxy-basic", "--silent", "--fail",
                        "--proxy", "http://127.0.0.1:\(port)", "--noproxy", "", "--connect-timeout", "3", "--max-time", "8",
                        "--max-filesize", "16384", "--proto", "=https", "--write-out", "\n%{http_code}", "https://\(host)/cdn-cgi/trace"
                    ], input: Data("proxy-user = \"probe:\(token)\"\n".utf8), timeout: 9))
                    let text = String(decoding: result.data, as: UTF8.self)
                    guard result.complete, let end = text.lastIndex(of: "\n"),
                          let code = Int(text[text.index(after: end)...].trimmingCharacters(in: .whitespacesAndNewlines)) else {
                        return .trace(host, nil, result.settled)
                    }
                    return .trace(host, TraceResponse.parse(String(text[..<end]), status: code)?.ip, result.settled)
                }
            }
            if profile == .coordinatedRecovery {
                for service in ConnectorService.allCases {
                    group.addTask {
                        let result = run(serviceInvocation(service, port: port, token: token))
                        return .service(service.rawValue, serviceResponse(result), result.settled)
                    }
                }
            }
            var result = ConnectorProbeResult(samples: [:], settled: true)
            // Await every worker, including failures/cancellation; no detached curl is abandoned.
            for await item in group {
                switch item {
                case let .trace(host, ip, settled):
                    if let ip { result.samples[host] = ip }; result.settled = result.settled && settled
                case let .service(key, response, settled):
                    if let response { result.services[key] = response }; result.settled = result.settled && settled
                }
            }
            return result
        }
    }
}
