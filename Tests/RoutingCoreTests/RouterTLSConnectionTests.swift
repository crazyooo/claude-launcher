import XCTest
import Darwin
@testable import RoutingCore

final class RouterTLSConnectionTests: XCTestCase {
    private typealias Owner = RouterTLSConnection
    private let tlsName = "tls-fixture.invalid"

    func testTLSIPv4IPv6SNIAndEchoStayOnObservedConnection() async throws {
        for family in [4, 6] {
            let fixture = try RouterTLSFixture(family: family)
            defer { fixture.stop() }
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: fixture.anchor, until: ProcessInfo.processInfo.systemUptime + 5)
            defer { owner.close() }
            let before = try await owner.sample()
            let nonce = UUID()
            let exchange = try await owner.exchange(nonce: nonce)
            let after = try await owner.sample()
            XCTAssertEqual(before.source, .fixture)
            XCTAssertEqual(before.trust, .fixtureAnchor)
            XCTAssertEqual(before.serverName, tlsName)
            XCTAssertTrue([UInt16(0x0303), UInt16(0x0304)].contains(before.protocolVersion))
            XCTAssertEqual(before.socket.socket, after.socket.socket)
            XCTAssertEqual(before.socket.process, after.socket.process)
            XCTAssertEqual(exchange.before.socket.socket, before.socket.socket)
            XCTAssertEqual(exchange.after.socket.socket, after.socket.socket)
            XCTAssertEqual(exchange.reply.nonce, nonce)
            XCTAssertEqual(exchange.reply.serverReportedPeerIP, fixture.ready.host)
            XCTAssertFalse(before.collectorAuthenticated)
            XCTAssertFalse(before.canPromoteAccepted)
            XCTAssertFalse(exchange.egressVerified)
            XCTAssertFalse(exchange.canPromoteAccepted)
            owner.close()
            let report = try await fixture.finish()
            XCTAssertEqual(report.sni, tlsName)
            XCTAssertEqual(report.nonce, nonce.uuidString.lowercased())
            XCTAssertEqual(report.peer, fixture.ready.host)
            XCTAssertTrue(report.eof)
            XCTAssertNil(report.error_kind)
        }
    }

    func testTLS12AndTLS13ReportActualNegotiatedVersion() async throws {
        for (mode, expected) in [("tls12", UInt16(0x0303)), ("tls13", UInt16(0x0304))] {
            let fixture = try RouterTLSFixture(mode: mode)
            defer { fixture.stop() }
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: fixture.anchor, until: ProcessInfo.processInfo.systemUptime + 5)
            defer { owner.close() }
            let sample = try await owner.sample()
            XCTAssertEqual(sample.protocolVersion, expected)
            _ = try await owner.exchange(nonce: UUID())
            owner.close()
            let report = try await fixture.finish()
            XCTAssertEqual(report.version, mode == "tls12" ? "TLSv1.2" : "TLSv1.3")
            XCTAssertTrue(report.eof)
        }
    }

    func testWrongHostnameDefaultTrustAndExpiredLeafRejectTLS() async throws {
        for mode in ["wrong_name", "untrusted", "expired"] {
            let fixture = try RouterTLSFixture(mode: mode == "expired" ? "expired" : "normal")
            defer { fixture.stop() }
            do {
                let owner = try await Owner.loopbackFixture(target: fixture.target,
                    serverName: mode == "wrong_name" ? "other-fixture.invalid" : tlsName,
                    anchorDER: mode == "untrusted" ? nil : fixture.anchor,
                    until: ProcessInfo.processInfo.systemUptime + 5)
                owner.close()
                XCTFail("Invalid TLS identity was accepted: \(mode)")
            } catch { XCTAssertEqual(error as? Owner.Failure, .tlsFailed, mode) }
            let report = try await fixture.finish()
            XCTAssertEqual(report.sni, mode == "wrong_name" ? "other-fixture.invalid" : tlsName)
            XCTAssertNil(report.nonce)
            XCTAssertNotNil(report.error_kind)
        }
    }

    func testWrongNonceAndTruncatedReplyPermanentlyInvalidateOwner() async throws {
        for mode in ["wrong_nonce", "truncated"] {
            let fixture = try RouterTLSFixture(mode: mode)
            defer { fixture.stop() }
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: fixture.anchor, until: ProcessInfo.processInfo.systemUptime + 5)
            defer { owner.close() }
            do { _ = try await owner.exchange(nonce: UUID()); XCTFail("Invalid reply accepted") }
            catch {
                if mode == "wrong_nonce" { XCTAssertEqual(error as? RouterTCPEchoError, .wrongNonce) }
                else {
                    XCTAssertTrue([Owner.Failure.eof, .tlsFailed, .connectionFailed].contains(error as? Owner.Failure))
                }
            }
            do { _ = try await owner.sample(); XCTFail("Failed owner reused") } catch { }
            _ = try await fixture.finish()
        }
    }

    func testHandshakeDeadlineAndTaskCancellationCloseActualSocket() async throws {
        for cancel in [false, true] {
            let fixture = try RouterTLSFixture(mode: "blackhole")
            defer { fixture.stop() }
            let target = try fixture.target
            let anchor = try fixture.anchor
            let deadline = ProcessInfo.processInfo.systemUptime + (cancel ? 5 : 0.4)
            let task = Task {
                try await Owner.loopbackFixture(target: target, serverName: self.tlsName,
                    anchorDER: anchor, until: deadline)
            }
            try await fixture.awaitEvent()
            if cancel { task.cancel() }
            do { let owner = try await task.value; owner.close(); XCTFail("Blackhole completed TLS") }
            catch { XCTAssertEqual(error as? Owner.Failure, cancel ? .cancelled : .timedOut) }
            let report = try await fixture.finish()
            XCTAssertTrue(report.eof)
        }
    }

    func testInvalidInputsAndPrecancelledTaskNeverConnect() async throws {
        let target = try Owner.Endpoint(address: "127.0.0.1", port: 1)
        do {
            let owner = try await Owner.installed(target: target, serverName: tlsName, until: .infinity)
            owner.close(); XCTFail("Nonroot installed factory opened")
        } catch { XCTAssertEqual(error as? Owner.Failure, .unavailable) }
        for value in ["", "127.0.0.1", "invalid name", "host.invalid\u{0}"] {
            do {
                let owner = try await Owner.loopbackFixture(target: target, serverName: value,
                    until: ProcessInfo.processInfo.systemUptime + 5)
                owner.close(); XCTFail("Invalid server name accepted")
            } catch { XCTAssertEqual(error as? Owner.Failure, .invalidTarget) }
        }
        do {
            let remote = try Owner.Endpoint(address: "203.0.113.1", port: 443)
            let owner = try await Owner.loopbackFixture(target: remote, serverName: tlsName,
                until: ProcessInfo.processInfo.systemUptime + 5)
            owner.close(); XCTFail("Nonloopback fixture opened")
        } catch { XCTAssertEqual(error as? Owner.Failure, .unavailable) }
        let fixture = try RouterTLSFixture(mode: "blackhole")
        defer { fixture.stop() }
        let cancelledTarget = try fixture.target
        let anchor = try fixture.anchor
        let task = Task {
            withUnsafeCurrentTask { $0?.cancel() }
            return try await Owner.loopbackFixture(target: cancelledTarget, serverName: self.tlsName,
                anchorDER: anchor,
                until: ProcessInfo.processInfo.systemUptime + 5)
        }
        do { let owner = try await task.value; owner.close(); XCTFail("Cancelled task opened") }
        catch { XCTAssertEqual(error as? Owner.Failure, .cancelled) }
        XCTAssertFalse(FileManager.default.fileExists(atPath: fixture.directory.appendingPathComponent("accepted.json").path))
    }

    func testDifferentTemporaryAnchorDoesNotTrustPeer() async throws {
        let fixture = try RouterTLSFixture()
        let other = try RouterTLSFixture()
        defer { fixture.stop(); other.stop() }
        do {
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: other.anchor, until: ProcessInfo.processInfo.systemUptime + 5)
            owner.close(); XCTFail("Unrelated anchor trusted peer")
        } catch { XCTAssertEqual(error as? Owner.Failure, .tlsFailed) }
        let report = try await fixture.finish()
        XCTAssertNil(report.nonce)
        XCTAssertNotNil(report.error_kind)
    }

    func testTLS11OnlyPeerIsRejectedAtProtocolNegotiation() async throws {
        let fixture = try RouterTLSFixture(mode: "tls11")
        defer { fixture.stop() }
        do {
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: fixture.anchor, until: ProcessInfo.processInfo.systemUptime + 5)
            owner.close(); XCTFail("Obsolete protocol accepted")
        } catch { XCTAssertEqual(error as? Owner.Failure, .tlsFailed) }
        let report = try await fixture.finish()
        XCTAssertNil(report.nonce)
        XCTAssertEqual(report.ssl_library, "SSL")
        XCTAssertTrue(["UNSUPPORTED_PROTOCOL", "TLSV1_ALERT_PROTOCOL_VERSION"].contains(report.ssl_reason),
                      "Server must reject a protocol mismatch, not fail local TLS setup: \(report.ssl_reason ?? "none")")
    }

    func testPendingEchoRejectsConcurrentWorkAndHonorsCancelCloseAndOriginalDeadline() async throws {
        for action in ["cancel", "close", "deadline", "cap"] {
            let fixture = try RouterTLSFixture(mode: "silent_echo")
            defer { fixture.stop() }
            let start = ProcessInfo.processInfo.systemUptime
            let deadline = start + (action == "deadline" ? 1.5 : (action == "cap" ? 60 : 5))
            let owner = try await Owner.loopbackFixture(target: fixture.target, serverName: tlsName,
                anchorDER: fixture.anchor, until: deadline)
            defer { owner.close() }
            let task = Task { try await owner.exchange(nonce: UUID()) }
            try await fixture.awaitEvent("request.json")
            do { _ = try await owner.sample(); XCTFail("Concurrent sample accepted") }
            catch { XCTAssertEqual(error as? Owner.Failure, .busy) }
            do { _ = try await owner.exchange(nonce: UUID()); XCTFail("Concurrent exchange accepted") }
            catch { XCTAssertEqual(error as? Owner.Failure, .busy) }
            if action == "cancel" { task.cancel() }
            if action == "close" { owner.close() }
            let expected: Owner.Failure = action == "cancel" ? .cancelled : (action == "close" ? .closed : .timedOut)
            do { _ = try await task.value; XCTFail("Silent peer returned an echo") }
            catch { XCTAssertEqual(error as? Owner.Failure, expected, action) }
            if action == "deadline" {
                XCTAssertLessThan(ProcessInfo.processInfo.systemUptime, deadline + 0.75)
            } else if action == "cap" {
                XCTAssertLessThan(ProcessInfo.processInfo.systemUptime, start + 5.75)
            }
            do { _ = try await owner.sample(); XCTFail("Terminal owner reused") }
            catch { XCTAssertEqual(error as? Owner.Failure, expected) }
            let report = try await fixture.finish()
            XCTAssertTrue(report.eof)
        }
    }
}
