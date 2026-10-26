import XCTest
import Darwin
@testable import RoutingCore

final class RouterOwnedTCPIOTests: XCTestCase {
    private final class Harness {
        let boot = UUID(), nonce = UUID()
        var now = 10.0, wallOffset = 1000.0
        var sent = Data(), input = Data()
        var sends = 0, receives = 0, polls = 0
        var sendHook: ((Int, Data) -> (Int, Int32)?)?
        var receiveHook: ((Int, Int) -> (Data?, Int32)?)?
        var pollHook: ((Int, Int16) -> (Int32, Int32, Int16))?
        var clock: RouterSystemClock { .init(bootID: boot, uptime: now, date: Date(timeIntervalSince1970: now + wallOffset)) }
        init() throws {
            input = try RouterTCPEchoWire.response(nonce, actualPeerIP: "127.0.0.1")
        }
        var effects: RouterOwnedTCPIO.Effects {
            .init(send: { fd, bytes in
                XCTAssertEqual(fd, 42); self.sends += 1
                if let result = self.sendHook?(self.sends, bytes) { return result }
                let count = min(7, bytes.count)
                self.sent.append(bytes.prefix(count))
                return (count, 0)
            }, receive: { fd, maximum in
                XCTAssertEqual(fd, 42); self.receives += 1
                XCTAssertLessThanOrEqual(maximum, 512)
                if let result = self.receiveHook?(self.receives, maximum) { return result }
                let result = Data(self.input.prefix(min(3, maximum)))
                self.input = self.input.dropFirst(result.count)
                return (result, 0)
            }, poll: { fd, direction, milliseconds in
                XCTAssertEqual(fd, 42); self.polls += 1
                XCTAssertGreaterThan(milliseconds, 0); XCTAssertLessThanOrEqual(milliseconds, 100)
                return self.pollHook?(self.polls, direction) ?? (1, 0, direction)
            })
        }
        func run(deadline: Double = 60) throws -> RouterOwnedTCPIO.Observation {
            try RouterOwnedTCPIO.exchange(fd: 42, nonce: nonce, until: deadline, clock: { self.clock }, io: effects)
        }
    }
    private func assertCompleteRequest(_ bytes: Data, nonce: UUID,
                                       file: StaticString = #filePath, line: UInt = #line) throws {
        // A second JSON encoding may legitimately choose a different key order.
        // Validate the actual fragmented writes as exactly one complete request.
        XCTAssertEqual(try RouterTCPEchoWire.bodyLength(bytes.prefix(4)), bytes.count - 4,
                       file: file, line: line)
        XCTAssertEqual(try RouterTCPEchoWire.parseRequest(bytes.dropFirst(4)), nonce,
                       file: file, line: line)
    }
    func testPartialIOConsumesOneFrameAndActualRequestBytes() throws {
        let h = try Harness()
        let trailing = Data("another frame is not consumed".utf8)
        h.input.append(trailing)
        let result = try h.run()
        try assertCompleteRequest(h.sent, nonce: h.nonce)
        XCTAssertEqual(h.input, trailing)
        XCTAssertGreaterThan(h.sends, 1); XCTAssertGreaterThan(h.receives, 2)
        XCTAssertEqual(result.reply.serverReportedPeerIP, "127.0.0.1")
        XCTAssertFalse(result.peerAuthenticated); XCTAssertFalse(result.egressVerified)
    }
    func testEINTRAndWouldBlockUseSameExchangeWithShortPollRetries() throws {
        let h = try Harness()
        h.sendHook = { count, _ in count == 1 ? (-1, EINTR) : (count == 2 ? (-1, EAGAIN) : nil) }
        h.receiveHook = { count, _ in count == 1 ? (nil, EINTR) : (count == 2 ? (nil, EAGAIN) : nil) }
        h.pollHook = { count, direction in
            h.now += 0.01
            if count == 1 { return (-1, EINTR, 0) }
            if count == 2 { return (0, 0, 0) }
            return (1, 0, direction)
        }
        _ = try h.run()
        XCTAssertEqual(h.polls, 4)
        try assertCompleteRequest(h.sent, nonce: h.nonce)
    }
    func testFatalSendAndReceiveFailuresAreNotRetried() throws {
        for code: Int32 in [EPIPE, ECONNRESET, EBADF] {
            let h = try Harness()
            h.sendHook = { _, _ in (-1, code) }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.sends, 1); XCTAssertEqual(h.receives, 0)
        }
        for count in [0, 10_000] {
            let h = try Harness()
            h.sendHook = { _, _ in (count, 0) }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.sends, 1)
        }
        for result: (Data?, Int32) in [(nil, EPIPE), (Data(), 0), (Data(repeating: 0, count: 5), 0)] {
            let h = try Harness()
            h.receiveHook = { _, _ in result }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.receives, 1)
        }
    }
    func testBadPollEventsAndMidFrameEOFFail() throws {
        for event in [POLLNVAL, POLLERR, POLLHUP, POLLOUT, 0] {
            let h = try Harness()
            h.receiveHook = { _, _ in (nil, EAGAIN) }
            h.pollHook = { _, _ in (1, 0, Int16(event)) }
            XCTAssertThrowsError(try h.run())
            XCTAssertEqual(h.polls, 1)
        }
        for prefixCount in [0, 2, 4, 6] {
            let h = try Harness()
            h.input = h.input.prefix(prefixCount)
            XCTAssertThrowsError(try h.run()) { XCTAssertEqual($0 as? RouterTCPEchoError, .eof) }
        }
    }
    func testHeaderBodyAndRetriesShareOriginalAndFiveSecondDeadlines() throws {
        for deadline in [11.0, 60.0] {
            let h = try Harness()
            h.receiveHook = { count, _ in
                // Header succeeds before timeout; body never becomes available.
                if count > 2 { h.now += 0.5; return (nil, EINTR) }
                return nil
            }
            XCTAssertThrowsError(try h.run(deadline: deadline)) {
                XCTAssertEqual($0 as? RouterOwnedProbeError, .timedOut)
            }
            XCTAssertEqual(h.now, min(deadline, 15))
            XCTAssertLessThanOrEqual(h.receives, 12)
        }
        let h = try Harness()
        h.sendHook = { _, _ in h.now += 0.25; return (-1, EINTR) }
        XCTAssertThrowsError(try h.run(deadline: 11))
        XCTAssertEqual(h.sends, 4); XCTAssertEqual(h.receives, 0)
        for deadline in [Double.nan, .infinity, -.infinity, 10] {
            let h = try Harness()
            XCTAssertThrowsError(try h.run(deadline: deadline))
            XCTAssertEqual(h.sends, 0)
        }
    }
    func testPollTimeoutsContinueOnlyInsideDeadline() throws {
        let h = try Harness()
        h.receiveHook = { _, _ in (nil, EAGAIN) }
        h.pollHook = { _, _ in h.now += 0.25; return (0, 0, 0) }
        XCTAssertThrowsError(try h.run(deadline: 11))
        XCTAssertEqual(h.polls, 4)
    }
    func testConsecutiveWallOrUptimeReversalCannotHideInsideTotalInterval() throws {
        for wallOnly in [false, true] {
            let h = try Harness()
            h.sendHook = { count, _ in
                if count == 1 { h.now += 1 }
                if count == 2 {
                    if wallOnly { h.wallOffset -= 0.25 } else { h.now -= 0.25 }
                }
                return nil
            }
            XCTAssertThrowsError(try h.run()) { XCTAssertEqual($0 as? RouterOwnedProbeError, .timedOut) }
            XCTAssertEqual(h.sends, 2)
        }
    }
    func testCancellationStopsBeforeFurtherIO() async throws {
        let h = try Harness()
        let result = await Task { () -> RouterOwnedProbeError? in
            h.sendHook = { _, _ in withUnsafeCurrentTask { $0?.cancel() }; return (-1, EINTR) }
            do { _ = try h.run(); return nil } catch { return error as? RouterOwnedProbeError }
        }.value
        XCTAssertEqual(result, .cancelled)
        XCTAssertEqual(h.sends, 1); XCTAssertEqual(h.receives, 0); XCTAssertEqual(h.polls, 0)
    }
}
