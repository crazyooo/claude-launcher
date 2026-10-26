import XCTest
@testable import LauncherCore

final class ConsoleTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private var settings: PreflightSettings { var result = PreflightSettings(); result.expectedIP = "203.0.113.43"; return result }
    private func report(client: CheckResult = .passed, stable: CheckResult = .passed) -> PreflightReport {
        let target = CheckTarget.desktop
        let checks = [NetworkCheck("client", "client", client, "PRIVATE_DETAILS"), .init("unchanged", "unchanged", stable, "PRIVATE_DETAILS")] +
            (["baseline", "transport", "service"] + target.hosts.map { "exit:" + $0 }).map { NetworkCheck($0, $0, .passed, "PRIVATE_DETAILS") }
        let observations = target.hosts.map {
            DomainObservation(host: $0, ip: "203.0.113.43", country: "US", transport: "PRIVATE_TRANSPORT", milliseconds: 1,
                              check: .init("exit:" + $0, $0, .passed, "PRIVATE_DETAILS"))
        }
        return .init(target: target, startedAt: now, completedAt: now, context: "PRIVATE_CONTEXT", checks: checks, observations: observations)
    }
    private func gates(_ report: PreflightReport?, at time: Date? = nil, target: CheckTarget = .desktop, checking: Bool = false) -> [ConsoleGate] {
        ConsoleProjection.gates(report: report, settings: settings, target: target, checking: checking, now: time ?? now, firewall: nil, controller: nil, endpoint: "")
    }
    func testExitIsIndependentOfClientFailure() {
        let result = gates(report(client: .failed))
        XCTAssertEqual(result[0].evidence[0].level, .observed)
        XCTAssertEqual(result[4].evidence[0].level, .failed)
        XCTAssertFalse(StrictProtection.verified)
    }
    func testNoCompleteGateFromSuccessfulProbes() {
        let result = gates(report())
        XCTAssertEqual(result.count, 6)
        XCTAssertFalse(result.contains { $0.level == .observed })
        XCTAssertThrowsError(try StrictProtection.requireVerified())
    }
    func testInvalidatedSamplesCannotShowObservedExit() {
        for result in [gates(nil), gates(report(), at: now.addingTimeInterval(31)), gates(report(), target: .vscode),
                       gates(report(stable: .failed)), gates(report(), checking: true)] {
            XCTAssertNotEqual(result[0].evidence[0].level, .observed)
        }
    }
    func testEndpointValidationAndCanonicalization() throws {
        XCTAssertEqual(try ControllerConfiguration.canonicalEndpoint("http://127.0.0.1:09090/"), "http://127.0.0.1:9090")
        XCTAssertEqual(try ControllerConfiguration.canonicalEndpoint("http://[::1]:9090"), "http://[::1]:9090")
        for invalid in ["http://localhost:9090", "http://127.0.0.1:9090?", "http://u:pw@127.0.0.1:80", "http://127.0.0.1:0", "http://127.0.0.1:65536", "https://127.0.0.1:80", "http://127.0.0.1:80/configs", "http://127.0.0.1:80\n"] {
            XCTAssertThrowsError(try ControllerConfiguration.canonicalEndpoint(invalid), invalid)
        }
        XCTAssertThrowsError(try ControllerConfiguration.validateToken("x\r\nheader"))
        XCTAssertThrowsError(try ControllerConfiguration.validateToken(""))
        XCTAssertNoThrow(try ControllerConfiguration.validateToken(String(repeating: "\"", count: 4096)))
    }
    func testSnapshotBindsEndpointAndRequestStart() throws {
        let json = """
        {"endpoint":"http://127.0.0.1:9090","startedAt":1800000000,"completedAt":1800000005,"version":"x","mode":"rule","ruleCount":1,"proxyCount":1,"totalConnections":0,"upload":0,"download":0,"connections":[]}
        """
        let value = try JSONDecoder().decode(ControllerSnapshot.self, from: Data(json.utf8))
        XCTAssertTrue(value.isCurrent(endpoint: value.endpoint, now: now.addingTimeInterval(10)))
        XCTAssertFalse(value.isCurrent(endpoint: "http://127.0.0.1:9091", now: now.addingTimeInterval(10)))
        XCTAssertFalse(value.isCurrent(endpoint: value.endpoint, now: now.addingTimeInterval(21)))
        XCTAssertFalse(value.isCurrent(endpoint: value.endpoint, now: now))
    }
    func testDiagnosticExportExcludesDetailsAndIdentifiers() throws {
        let (operation, authorization) = try RecoveryFixture().prepared()
        var recovery = RecoveryCoordinator(); recovery.restore(operation)
        let data = ConsoleDiagnostics.data(report: report(), gates: gates(report()), controller: nil, now: now, recovery: recovery)
        let text = String(decoding: data, as: UTF8.self)
        for privateValue in ["PRIVATE", "203.0.113.43", "password", "token", operation.hold.id.uuidString,
                             authorization.request.id, operation.settingsDigest, operation.localContext,
                             operation.environmentDigest, authorization.request.context.runtime_sha256] {
            XCTAssertFalse(text.contains(privateValue))
        }
        let result = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        XCTAssertEqual(result["launch_authorized"] as? Bool, false)
        let exported = try XCTUnwrap(result["recoveryOperation"] as? [String: String])
        XCTAssertEqual(Set(exported.keys), ["mode", "checkpoint", "target", "launch_authorized", "protection_verified"])
        XCTAssertEqual(exported["mode"], "observationOnly")
        XCTAssertEqual(exported["checkpoint"], "prepare")
    }
}
