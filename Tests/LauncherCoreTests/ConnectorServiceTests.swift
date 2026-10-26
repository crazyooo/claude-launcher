import XCTest
@testable import LauncherCore

private final class ProbeFixture: @unchecked Sendable {
    let lock = NSLock()
    var invocations: [ConnectorProbe.Invocation] = []
    let serviceCode: Int
    let unsettled: Bool
    init(serviceCode: Int = 401, unsettled: Bool = false) { self.serviceCode = serviceCode; self.unsettled = unsettled }
    func run(_ call: ConnectorProbe.Invocation) -> BoundedProcess.Capture {
        lock.lock(); invocations.append(call); lock.unlock()
        if call.arguments.contains("--head") {
            return .init(data: Data(String(serviceCode).utf8), complete: !unsettled, settled: !unsettled)
        }
        return .init(data: Data("ip=192.0.2.1\nloc=US\ntls=TLSv1.3\n\n200".utf8), complete: true, settled: true)
    }
}

final class ConnectorServiceTests: XCTestCase {
    let token = String(repeating: "a", count: 64)
    func testServiceParsingPreservesReachabilityWithoutClaimingAccountAccess() {
        for code in [200, 301, 401, 403, 404, 499] {
            let response = ConnectorProbe.serviceResponse(.init(data: Data(String(code).utf8), complete: true, settled: true))
            XCTAssertEqual(response?.reachable, true)
        }
        for code in [100, 199, 429, 500, 503, 599] {
            XCTAssertEqual(ConnectorProbe.serviceResponse(.init(data: Data(String(code).utf8), complete: true, settled: true))?.reachable, false)
        }
        for text in ["", "200\n", "200junk", "000", "600", "true", "-20"] {
            XCTAssertNil(ConnectorProbe.serviceResponse(.init(data: Data(text.utf8), complete: true, settled: true)))
        }
        XCTAssertNil(ConnectorProbe.serviceResponse(.init(data: Data("200".utf8), complete: false, settled: true)))
    }
    func testRecoveryRunsExactlyFiveFixedRequestsAndLegacyOnlyThree() async {
        for profile: ConnectorProbeProfile in [.traceOnly, .coordinatedRecovery] {
            let fixture = ProbeFixture()
            let result = await ConnectorProbe.sample(port: 12345, token: token, profile: profile, run: fixture.run)
            XCTAssertEqual(Set(result.samples.keys), Set(ConnectorConfiguration.hosts)); XCTAssertTrue(result.settled)
            XCTAssertEqual(fixture.invocations.count, profile == .traceOnly ? 3 : 5)
            XCTAssertEqual(ConnectorServiceResponse.complete(result.services), profile == .coordinatedRecovery)
            for call in fixture.invocations {
                XCTAssertFalse(call.arguments.contains(where: { $0.contains(token) }))
                XCTAssertTrue(String(decoding: call.input, as: UTF8.self).contains(token))
                XCTAssertTrue(call.arguments.contains("http://127.0.0.1:12345"))
                XCTAssertFalse(call.arguments.contains("--location")); XCTAssertFalse(call.arguments.contains("--retry"))
                if call.arguments.contains("--head") {
                    XCTAssertFalse(call.arguments.contains("--fail")); XCTAssertEqual(call.timeout, 7)
                    XCTAssertTrue(ConnectorService.allCases.map(\.url).contains(call.arguments.last!))
                }
            }
        }
    }
    func testInvalidTokenDoesNotLaunchAndUnsettledServiceIsPropagated() async {
        let invalid = await ConnectorProbe.sample(port: 12345, token: "x\nproxy=bad", profile: .coordinatedRecovery) { _ in
            XCTFail("invalid credential invoked runner"); return .init(data: Data(), complete: false, settled: true)
        }
        XCTAssertTrue(invalid.samples.isEmpty)
        let fixture = ProbeFixture(unsettled: true)
        let failed = await ConnectorProbe.sample(port: 12345, token: token, profile: .coordinatedRecovery, run: fixture.run)
        XCTAssertFalse(failed.settled); XCTAssertTrue(failed.services.isEmpty); XCTAssertEqual(fixture.invocations.count, 5)
    }
    func testCancellationWaitsForEveryServiceWorker() async {
        let entered = expectation(description: "service entered"), release = DispatchSemaphore(value: 0)
        let finished = expectation(description: "all workers returned")
        finished.isInverted = true
        let fixture = ProbeFixture(), token = token
        let task = Task {
            let result = await ConnectorProbe.sample(port: 12345, token: token, profile: .coordinatedRecovery) { call in
                if call.arguments.last == ConnectorService.api.url {
                    entered.fulfill(); _ = release.wait(timeout: .now() + 2)
                }
                return fixture.run(call)
            }
            finished.fulfill(); return result
        }
        await fulfillment(of: [entered], timeout: 1)
        task.cancel()
        await fulfillment(of: [finished], timeout: 0.05)
        release.signal()
        let result = await task.value
        XCTAssertTrue(result.settled); XCTAssertEqual(fixture.invocations.count, 5)
    }
}
