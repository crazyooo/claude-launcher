import XCTest
import Darwin
@testable import RoutingCore

final class RouterConnectionIntegrationTests: XCTestCase {
    private func sample(_ query: RouterConnectionQuery, mode: RouterConnectionMode = .system) -> RouterConnectionSnapshot {
        let now = Date(), time = ProcessInfo.processInfo.systemUptime
        return .init(version: 1, request: query.request,
            binding: .init(mode: mode, installation: mode == .system ? UUID() : nil,
                instance: query.instance ?? UUID(), epoch: String(repeating: "a", count: 64), configurationDigest: String(repeating: "b", count: 64)),
            startedAt: now, completedAt: now, startedUptime: time, completedUptime: time,
            uploadTotal: Int64.max, downloadTotal: 9_007_199_254_740_993, totalConnections: 0, rows: [])
    }
    func testQueryDiscoveryAndStrictRequestFields() throws {
        for instance in [nil, UUID()] {
            let query = RouterConnectionQuery(request: UUID(), instance: instance)
            let result = try RouterConnectionQuery.decode(JSONEncoder().encode(query))
            XCTAssertEqual(result.instance, instance); XCTAssertEqual(result.request, query.request)
        }
        let id = UUID().uuidString
        for text in [
            #"{"version":true,"action":"connections","request":"\#(id)"}"#,
            #"{"version":1,"action":"connections","request":"\#(id)","instance":null}"#,
            #"{"version":1,"action":"connections","request":"\#(id)","endpoint":"http://elsewhere"}"#,
            #"{"version":1,"version":1,"action":"connections","request":"\#(id)"}"#,
            #"{"version":1,"action":"stop","request":"\#(id)"}"#
        ] { XCTAssertThrowsError(try RouterConnectionQuery.decode(Data(text.utf8))) }
    }
    func testWirePreservesCountersAndSeparatesControlReplies() throws {
        let query = RouterConnectionQuery(request: UUID(), instance: UUID())
        let bytes = try RouterConnectionWire.response(to: query) { self.sample(query) }
        let decoded = try RouterConnectionWire.decode(bytes, query: query)
        XCTAssertEqual(decoded.uploadTotal, Int64.max)
        XCTAssertEqual(decoded.downloadTotal, 9_007_199_254_740_993)
        XCTAssertFalse(decoded.routingVerified)
        XCTAssertThrowsError(try RouterSystemReply.decode(bytes))
        XCTAssertThrowsError(try RouterConnectionWire.decode(bytes, query: .init(request: UUID(), instance: query.instance)))
        XCTAssertThrowsError(try RouterConnectionWire.decode(bytes, query: .init(request: query.request, instance: UUID())))
        let failed = try RouterConnectionWire.response(to: query) { throw RouterConnectionFailure.noActiveInstance }
        XCTAssertThrowsError(try RouterConnectionWire.decode(failed, query: query)) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .noActiveInstance)
        }
        XCTAssertThrowsError(try RouterConnectionWire.decode(failed, query: .init(request: UUID(), instance: nil))) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .invalidResponse)
        }
        XCTAssertThrowsError(try RouterConnectionWire.decode(JSONEncoder().encode(sample(query, mode: .userManaged)), query: query))
        XCTAssertThrowsError(try RouterConnectionWire.decode(bytes, query: query,
            now: Date().addingTimeInterval(20), uptime: ProcessInfo.processInfo.systemUptime + 20)) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .stale)
        }
        XCTAssertThrowsError(try RouterConnectionWire.decode(Data(#"{"version":1,"error":"invalidRequest"}"#.utf8), query: query)) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .unsupportedComponent)
        }
        for raw in [#"{"version":true,"error":"invalidRequest"}"#,
                    #"{"version":1,"error":"operationUnsettled"}"#,
                    #"{"version":1,"status":{}}"#] {
            XCTAssertThrowsError(try RouterConnectionWire.decode(Data(raw.utf8), query: query)) {
                XCTAssertEqual($0 as? RouterConnectionFailure, .invalidResponse)
            }
        }
    }
    func testSocketRoutesConnectionsWithoutExecutingProvider() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        try pair.forEach(RouterSystemFrame.configure)
        defer { close(pair[0]) }
        let query = RouterConnectionQuery(request: UUID(), instance: nil), expected = sample(.init(request: UUID(), instance: nil))
        let done = expectation(description: "readonly server")
        let server = RouterSystemSocketServer(ownerUID: getuid(), connections: { query in
            RouterConnectionSnapshot(version: 1, request: query.request, binding: expected.binding,
                startedAt: expected.startedAt, completedAt: expected.completedAt,
                startedUptime: expected.startedUptime, completedUptime: expected.completedUptime,
                uploadTotal: expected.uploadTotal, downloadTotal: expected.downloadTotal, totalConnections: 0, rows: [])
        }, execute: { _ in XCTFail("connections must not reconcile"); throw RouterSystemError.invalidRequest })
        let serverFD = pair[1]
        DispatchQueue.global().async {
            server.handle(fd: serverFD, acceptedAt: ProcessInfo.processInfo.systemUptime)
            close(serverFD); done.fulfill()
        }
        let result = try RouterSystemClient.exchange(JSONEncoder().encode(query), fd: pair[0], peer: getuid(),
            deadline: ProcessInfo.processInfo.systemUptime + 2)
        XCTAssertEqual(try RouterConnectionWire.decode(result, query: query).uploadTotal, Int64.max)
        wait(for: [done], timeout: 2)
    }
    func testConnectionHTTPBudgetIsSeparateAndEOFIsStillRequired() throws {
        func response(_ count: Int) -> Data {
            Data(("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(count)\r\n\r\n" + String(repeating: " ", count: count)).utf8)
        }
        let maximum = RouterConnectionProjection.bodyLimit
        XCTAssertEqual(try RouterSystemControllerHTTP.parse(response(maximum), endpoint: .connections).body.count, maximum)
        XCTAssertThrowsError(try RouterSystemControllerHTTP.parse(response(maximum)))
        XCTAssertThrowsError(try RouterSystemControllerHTTP.parse(response(maximum + 1), endpoint: .connections)) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .responseTooLarge)
        }
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { pair.forEach { close($0) } }
        let valid = response(0)
        _ = valid.withUnsafeBytes { Darwin.write(pair[1], $0.baseAddress, $0.count) }
        XCTAssertThrowsError(try RouterSystemControllerHTTP.fixtureExchange(fd: pair[0],
            deadline: ProcessInfo.processInfo.systemUptime + 0.03, endpoint: .connections))
    }
    func testAuthenticationSequenceNeverFetchesConnectionsAfterFailedChallengeOrVersion() throws {
        let secret = String(repeating: "a", count: 64)
        for fault in 0..<4 {
            var paths: [RouterSystemControllerHTTP.Endpoint] = []
            let result = Result { try RouterSystemControllerHTTP.authenticatedConnections(secret: secret) { path, token in
                paths.append(path)
                if paths.count == 1 {
                    XCTAssertEqual(path, .version); XCTAssertNotEqual(token, secret)
                    return .init(status: fault == 1 ? 200 : 401, body: Data())
                }
                XCTAssertEqual(token, secret)
                if path == .version {
                    return .init(status: fault == 2 ? 401 : 200,
                        body: Data(("{\"meta\":true,\"version\":\"v" + (fault == 3 ? "0.0.0" : RouterCoreRelease.version) + "\"}").utf8))
                }
                return .init(status: 200, body: Data("{}".utf8))
            }}
            if fault == 0 {
                XCTAssertEqual(try result.get(), Data("{}".utf8)); XCTAssertEqual(paths, [.version, .version, .connections])
            } else {
                XCTAssertThrowsError(try result.get()); XCTAssertFalse(paths.contains(.connections))
            }
        }
    }
    func testConnectionEndpointUsesRealBoundedSocketRead() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]) }
        let done = expectation(description: "http fixture")
        let server = pair[1]
        DispatchQueue.global().async {
            defer { close(server); done.fulfill() }
            var request = Data(), buffer = [UInt8](repeating: 0, count: 1024)
            while request.range(of: Data("\r\n\r\n".utf8)) == nil {
                let n = Darwin.read(server, &buffer, buffer.count)
                guard n > 0 else { XCTFail("missing request"); return }
                request.append(contentsOf: buffer.prefix(n))
            }
            XCTAssertTrue(String(decoding: request, as: UTF8.self).hasPrefix("GET /connections HTTP/1.0\r\n"))
            let body = Data(repeating: 32, count: 70_000)
            var response = Data("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 70000\r\n\r\n".utf8)
            response.append(body)
            var offset = 0
            while offset < response.count {
                let count = response.withUnsafeBytes { Darwin.write(server, $0.baseAddress!.advanced(by: offset), response.count - offset) }
                guard count > 0 else { XCTFail("write failed"); return }
                offset += count
            }
        }
        let response = try RouterSystemControllerHTTP.fixtureExchange(fd: pair[0],
            deadline: ProcessInfo.processInfo.systemUptime + 3, endpoint: .connections)
        XCTAssertEqual(response.body.count, 70_000)
        wait(for: [done], timeout: 3)
    }
    func testExistingRootLeaseCannotCreateMissingFileAndDetectsReplacement() throws {
        let f = try RouterSystemDispatchFixture()
        let before = try FileManager.default.contentsOfDirectory(atPath: f.url.path).sorted()
        XCTAssertThrowsError(try RouterSystemHostLease.acquireExisting(in: f.directory, purpose: .operation))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.url.path).sorted(), before)
        let created = try RouterSystemHostLease.acquire(in: f.directory, purpose: .operation)
        XCTAssertThrowsError(try RouterSystemHostLease.acquireExisting(in: f.directory, purpose: .operation)) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .busy)
        }
        created.release()
        let held = try RouterSystemHostLease.acquireExisting(in: f.directory, purpose: .operation)
        XCTAssertEqual(renameat(f.directory.fd, "operation.lock", f.directory.fd, "operation.saved"), 0)
        try f.directory.create("operation.lock", data: Data())
        XCTAssertThrowsError(try held.verify())
    }
    func testVerifiedMaterialRedactsCredentialsAndControllerSecret() throws {
        let secret = String(repeating: "a", count: 64)
        let material = try RouterConnectionMaterial.read(["secret": secret, "proxies": [
            ["username": "account-name", "password": "private-password"], ["username": "account-name"]
        ]])
        XCTAssertEqual(Set(material.redactions), [secret, "account-name", "private-password"])
        XCTAssertThrowsError(try RouterConnectionMaterial.read(["secret": secret, "proxies": [["password": 3]]]))
    }
}

final class RouterSystemConnectionReaderTests: XCTestCase {
    private final class Harness {
        let base = try! RouterSystemDispatchFixture()
        var state: RouterSystemJournal
        var loads = 0, bodies = 0
        var hook: (() -> Void)?
        var secret = String(repeating: "a", count: 64)
        var listenerGeneration: UInt64 = 8
        var processUID: UInt32 = 0
        var now: TimeInterval = 100
        init() throws {
            let fence = try base.baseline.create(intent: base.intent, configurationDigest: base.digest, host: base.host, snapshot: base.snapshot())
            state = .empty(); state.installation = base.identity; state.intent = base.intent
            state.phase = .active; state.reason = "capture_observed_traffic_acceptance_pending"
            state.work = base.work; state.dispatch = fence; state.configurationDigest = base.digest
            state.footprint = .init(instance: base.intent.id, work: base.work, configurationDigest: base.digest,
                interfaceName: "utun9", interfaceIndex: 9, addresses: ["198.18.0.1"], routeSignatures: ["fixture"])
        }
        func read() throws -> RouterConnectionSnapshot {
            let reader = RouterSystemConnections(identity: base.identity, readers: .init(load: { _ in
                self.loads += 1; return self.state
            }, material: { _ in .init(secret: self.secret, redactions: [self.secret]) }, process: { _ in
                .init(work: self.base.work, uid: self.processUID, realUID: self.processUID,
                      parentPID: self.base.host.pid, processGroup: self.base.host.pid)
            }, listeners: { _, _ in .observed([.init(descriptor: 8, generation: self.listenerGeneration)]) },
            body: { _, _ in
                self.bodies += 1; self.hook?()
                return Data(#"{"uploadTotal":123,"downloadTotal":456,"connections":null}"#.utf8)
            }, clock: { (Date(timeIntervalSince1970: self.now), self.now) }))
            return try reader.read(.init(request: UUID(), instance: nil))
        }
    }
    func testActiveSampleIsReadOnlyAndEmptyIsAnActualResponse() throws {
        let h = try Harness(), before = try JSONEncoder().encode(h.state)
        let sample = try h.read()
        XCTAssertEqual(sample.totalConnections, 0); XCTAssertEqual(sample.uploadTotal, 123)
        XCTAssertEqual(h.loads, 2); XCTAssertEqual(h.bodies, 1)
        XCTAssertEqual(try JSONDecoder().decode(RouterSystemJournal.self, from: before).revision, h.state.revision)
        XCTAssertFalse(sample.protectionVerified)
    }
    func testInactiveAndUncertainStatesNeverReadHTTP() throws {
        for phase in [RouterSystemJournal.Phase.idle, .prepared, .stopped, .fault] {
            let h = try Harness()
            if phase == .idle { h.state = .empty(); h.state.installation = h.base.identity }
            else if phase == .prepared || phase == .stopped {
                h.state.phase = phase; h.state.work = nil; h.state.footprint = nil
                h.state.dispatch = nil; h.state.configurationDigest = nil
                h.state.reason = phase == .prepared ? "prepared_not_applied" : "unused_preview_cancelled"
            } else { h.state.phase = phase; h.state.reason = "runtime_evidence_incomplete" }
            XCTAssertThrowsError(try h.read()) {
                XCTAssertEqual($0 as? RouterConnectionFailure, phase == .fault ? .unavailable : .noActiveInstance)
            }
            XCTAssertEqual(h.bodies, 0)
        }
    }
    func testMutationDuringHTTPDiscardsResult() throws {
        for kind in 0..<5 {
            let h = try Harness()
            h.hook = {
                switch kind {
                case 0: h.state.revision = UUID()
                case 1: h.secret = String(repeating: "b", count: 64)
                case 2: h.listenerGeneration += 1
                case 3: h.processUID = 501
                default: h.now += 6
                }
            }
            XCTAssertThrowsError(try h.read())
        }
    }
}
