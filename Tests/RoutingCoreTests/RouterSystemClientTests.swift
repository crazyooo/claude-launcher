import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemClientTests: XCTestCase {
    private func envelope(_ status: RouterSystemStatus) throws -> Data {
        try JSONEncoder().encode(RouterSystemReply(status: status, error: nil))
    }
    private func prepared() throws -> RouterSystemJournal {
        var state = RouterSystemJournal.empty()
        let plan = RouterPlan(proxies: [], rules: [], defaultDestination: .direct)
        let profile = RouterSystemProfile(resolver: .cloudflare), now = Date()
        state.intent = .init(id: UUID(), plan: plan, profile: profile,
            digest: try RouterSystemCompiler.digest(plan: plan, profile: profile), networkFingerprint: String(repeating: "a", count: 64),
            issued: .init(bootID: UUID(), uptime: 1, date: now), expiresAt: now.addingTimeInterval(60), deadlineUptime: 61)
        state.phase = .prepared; state.reason = "prepared_not_applied"
        return state
    }
    func testEncoderUsesServerWhitelistForAllCommands() throws {
        let state = try prepared(), item = try XCTUnwrap(state.intent)
        let credential = RouterSystemCredential(reference: UUID(), value: .init(username: "fixture-user", password: "fixture-secret"))
        let commands: [RouterSystemRequest] = [.prepare(id: item.id, plan: item.plan, profile: item.profile),
            .apply(id: item.id, credentials: [credential]), .status(id: nil), .status(id: item.id), .stop(id: item.id)]
        for command in commands { XCTAssertNoThrow(try RouterSystemDecoder.decode(RouterSystemClient.encode(command))) }
        let bytes = try RouterSystemClient.encode(.apply(id: item.id, credentials: [credential]))
        guard case .apply(let id, let values) = try RouterSystemDecoder.decode(bytes) else { return XCTFail("wrong action") }
        XCTAssertEqual(id, item.id); XCTAssertEqual(values.first?.value.password, "fixture-secret")
        XCTAssertThrowsError(try RouterSystemClient.encode(.apply(id: item.id, credentials: [credential, credential])))
    }
    func testRepliesBindEveryScopedRequestToOriginalID() throws {
        let state = try prepared(), item = try XCTUnwrap(state.intent), bytes = try envelope(.init(state))
        for id in [item.id, UUID()] {
            let commands: [RouterSystemRequest] = [.prepare(id: id, plan: item.plan, profile: item.profile),
                .apply(id: id, credentials: []), .status(id: id), .stop(id: id)]
            for command in commands {
                if id == item.id { XCTAssertEqual(try RouterSystemClient.decode(bytes, for: command).instance, item.id) }
                else { XCTAssertThrowsError(try RouterSystemClient.decode(bytes, for: command)) }
            }
        }
        XCTAssertEqual(try RouterSystemClient.decode(bytes, for: .status(id: nil)).instance, item.id)
    }
    func testStrictBooleansConstantsOptionalFieldsAndReasons() throws {
        let bytes = try envelope(.init(.empty()))
        let base = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for (field, wrong): (String, Any) in [
            ("routingVerified", true), ("protectionVerified", 0), ("launchAuthorized", NSNull()),
            ("processObserved", 1), ("reason", "arbitrary_reason"), ("phase", "running"),
            ("extra", "ignored?"), ("instance", NSNull()), ("ipv6CaptureObserved", 0),
            ("processObserved", true), ("controllerHealthy", true), ("captureObserved", true)
        ] {
            var object = base, status = try XCTUnwrap(base["status"] as? [String: Any])
            status[field] = wrong; object["status"] = status
            XCTAssertThrowsError(try RouterSystemReply.decode(JSONSerialization.data(withJSONObject: object)), field)
        }
        XCTAssertFalse(try RouterSystemReply.decode(bytes).launchAuthorized)
        XCTAssertThrowsError(try RouterSystemReply.decode(Data(#"{"version":1,"version":1,"status":{}}"#.utf8)))
        XCTAssertThrowsError(try RouterSystemReply.decode(Data(#"{"version":true,"error":"conflict"}"#.utf8)))
        XCTAssertThrowsError(try RouterSystemReply.decode(Data(#"{"version":1,"error":"private arbitrary error"}"#.utf8)))
        XCTAssertThrowsError(try RouterSystemReply.decode(Data(#"{"version":1,"error":"networkConflict"}"#.utf8))) {
            XCTAssertEqual($0 as? RouterSystemError, .networkConflict)
        }
    }
    func testObservedRuntimeAndCleanupCannotContradictEachOther() throws {
        var state = try prepared(); state.phase = .active; state.reason = "capture_observed_traffic_acceptance_pending"
        let id = try XCTUnwrap(state.intent?.id)
        let observation = RouterSystemRuntimeObservation(instance: id, ownershipConfirmed: true, processAlive: true,
            controllerHealthy: true, capturePresent: true, footprint: nil, startWorkSettled: true, ipv6CaptureObserved: false)
        let status = try RouterSystemReply.decode(envelope(.init(state, observation: observation)))
        XCTAssertTrue(status.captureObserved); XCTAssertEqual(status.ipv6CaptureObserved, false)
        XCTAssertThrowsError(try RouterSystemReply.decode(envelope(.init(state))))
        state.phase = .stopped; state.reason = "owned_cleanup_confirmed"
        XCTAssertThrowsError(try RouterSystemReply.decode(envelope(.init(state, observation: observation))))
        XCTAssertTrue(try RouterSystemReply.decode(envelope(.init(state))).cleanupConfirmed)
    }
    func testRealClientExchangeWaitsForServerAndHalfCloses() throws {
        var fds: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
        defer { close(fds[0]) }
        try fds.forEach(RouterSystemFrame.configure)
        let done = expectation(description: "server")
        let server = RouterSystemSocketServer(ownerUID: getuid()) { request in
            guard case .status(nil) = request else { throw RouterSystemError.invalidRequest }
            return .init(.empty())
        }
        let serverFD = fds[1]
        DispatchQueue.global().async {
            server.handle(fd: serverFD, acceptedAt: ProcessInfo.processInfo.systemUptime)
            close(serverFD); done.fulfill()
        }
        let reply = try RouterSystemClient.exchange(RouterSystemClient.encode(.status(id: nil)), fd: fds[0], peer: getuid(),
            deadline: ProcessInfo.processInfo.systemUptime + 2)
        XCTAssertEqual(try RouterSystemClient.decode(reply, for: .status(id: nil)).phase, "idle")
        wait(for: [done], timeout: 2)
    }
    func testClientRejectsNonRootPeerBeforeSendingAndRequiresReplyEOF() throws {
        for wrongPeer in [true, false] {
            var fds: [Int32] = [-1, -1]
            XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds), 0)
            defer { fds.forEach { close($0) } }
            try fds.forEach(RouterSystemFrame.configure)
            let reply = try envelope(.init(.empty()))
            try RouterSystemFrame.send(reply, fd: fds[1], maximum: RouterSystemFrame.replyLimit,
                deadline: ProcessInfo.processInfo.systemUptime + 1)
            XCTAssertThrowsError(try RouterSystemClient.exchange(RouterSystemClient.encode(.status(id: nil)),
                fd: fds[0], peer: wrongPeer ? getuid() + 1 : getuid(), deadline: ProcessInfo.processInfo.systemUptime + 0.05))
            if wrongPeer {
                var byte: UInt8 = 0
                XCTAssertEqual(recv(fds[1], &byte, 1, 0), -1); XCTAssertEqual(errno, EAGAIN)
            }
        }
    }
}
