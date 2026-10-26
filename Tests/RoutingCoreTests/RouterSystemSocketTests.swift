import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemSocketTests: XCTestCase {
    private func pair() throws -> [Int32] {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw RouterSystemError.operationUnsettled }
        do { try fds.forEach(RouterSystemFrame.configure) }
        catch { fds.forEach { close($0) }; throw error }
        return fds
    }
    private func raw(_ body: Data) -> Data {
        var length = UInt32(body.count).bigEndian
        var result = withUnsafeBytes(of: &length) { Data($0) }; result.append(body); return result
    }
    private func writeRaw(_ data: Data, to fd: Int32) {
        let count = data.withUnsafeBytes { Darwin.send(fd, $0.baseAddress, data.count, 0) }
        XCTAssertEqual(count, data.count)
    }
    func testSplitHeaderAndBodyWaitsForHalfClose() throws {
        let fds = try pair(); defer { fds.forEach { close($0) } }
        let body = Data("split frame".utf8), done = expectation(description: "writer")
        let wire = raw(body)
        DispatchQueue.global().async {
            for value in wire { self.writeRaw(Data([value]), to: fds[0]); usleep(1000) }
            shutdown(fds[0], SHUT_WR); done.fulfill()
        }
        XCTAssertEqual(try RouterSystemFrame.receive(fds[1], maximum: 100, deadline: ProcessInfo.processInfo.systemUptime + 2), body)
        wait(for: [done], timeout: 2)
    }
    func testExactOneMiBBoundaryAndOversizedHeader() throws {
        let fds = try pair(); defer { fds.forEach { close($0) } }
        let body = Data(repeating: 65, count: RouterSystemFrame.requestLimit), done = expectation(description: "large writer")
        DispatchQueue.global().async {
            do { try RouterSystemFrame.send(body, fd: fds[0], maximum: RouterSystemFrame.requestLimit, deadline: ProcessInfo.processInfo.systemUptime + 3) }
            catch { XCTFail("bounded send failed") }
            shutdown(fds[0], SHUT_WR); done.fulfill()
        }
        XCTAssertEqual(try RouterSystemFrame.receive(fds[1], maximum: RouterSystemFrame.requestLimit, deadline: ProcessInfo.processInfo.systemUptime + 3), body)
        wait(for: [done], timeout: 3)
        let tooLarge = try pair(); defer { tooLarge.forEach { close($0) } }
        var length = UInt32(RouterSystemFrame.requestLimit + 1).bigEndian
        writeRaw(withUnsafeBytes(of: &length) { Data($0) }, to: tooLarge[0])
        XCTAssertThrowsError(try RouterSystemFrame.receive(tooLarge[1], maximum: RouterSystemFrame.requestLimit, deadline: ProcessInfo.processInfo.systemUptime + 1))
    }
    func testTruncatedTrailingAndMissingHalfCloseRejected() throws {
        let message = raw(Data("test".utf8))
        for mode in 0..<4 {
            let fds = try pair(); defer { fds.forEach { close($0) } }
            let bytes = mode == 0 ? message.dropLast() : mode == 1 ? message + Data([0]) : mode == 2 ? message + message : message
            writeRaw(Data(bytes), to: fds[0])
            if mode != 3 { shutdown(fds[0], SHUT_WR) }
            XCTAssertThrowsError(try RouterSystemFrame.receive(fds[1], maximum: 100, deadline: ProcessInfo.processInfo.systemUptime + 0.05))
        }
    }
    func testSlowDripCannotRenewAbsoluteDeadline() throws {
        let fds = try pair(); defer { fds.forEach { close($0) } }
        let done = expectation(description: "slow writer")
        DispatchQueue.global().async {
            self.writeRaw(Data([0]), to: fds[0]); usleep(60_000)
            self.writeRaw(Data([0]), to: fds[0]); done.fulfill()
        }
        let began = ProcessInfo.processInfo.systemUptime
        XCTAssertThrowsError(try RouterSystemFrame.receive(fds[1], maximum: 100, deadline: began + 0.03))
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - began, 0.5)
        wait(for: [done], timeout: 1)
    }
    func testKernelPeerUIDAndDisconnectedWriter() throws {
        let fds = try pair()
        defer { close(fds[0]) }
        XCTAssertNoThrow(try RouterSystemFrame.requirePeer(fds[0], uid: getuid()))
        XCTAssertThrowsError(try RouterSystemFrame.requirePeer(fds[0], uid: getuid() + 1))
        close(fds[1])
        XCTAssertThrowsError(try RouterSystemFrame.send(Data("test".utf8), fd: fds[0], maximum: 100, deadline: ProcessInfo.processInfo.systemUptime + 1))
    }
    func testServerExecutesOnlyAfterCompleteAuthenticatedRequest() throws {
        for suffix in [Data(), Data([0])] {
            let fds = try pair(); defer { close(fds[0]) }
            var executions = 0
            let server = RouterSystemSocketServer(ownerUID: getuid()) { _ in executions += 1; return .init(.empty()) }
            let done = expectation(description: "handler")
            DispatchQueue.global().async {
                server.handle(fd: fds[1], acceptedAt: ProcessInfo.processInfo.systemUptime)
                close(fds[1]); done.fulfill()
            }
            writeRaw(raw(Data(#"{"version":1,"action":"status"}"#.utf8)) + suffix, to: fds[0]); shutdown(fds[0], SHUT_WR)
            _ = try RouterSystemFrame.receive(fds[0], maximum: RouterSystemFrame.replyLimit, deadline: ProcessInfo.processInfo.systemUptime + 2)
            wait(for: [done], timeout: 2)
            XCTAssertEqual(executions, suffix.isEmpty ? 1 : 0)
        }
    }
    func testErrorReplyRedactsUnderlyingExceptionAndWrongUIDDoesNotDispatch() throws {
        for correctUID in [true, false] {
            let fds = try pair(); defer { close(fds[0]) }
            var executions = 0
            let server = RouterSystemSocketServer(ownerUID: correctUID ? getuid() : getuid() + 1) { _ in
                executions += 1; throw NSError(domain: "private-password-do-not-echo", code: 1)
            }
            let done = expectation(description: "error handler")
            DispatchQueue.global().async {
                server.handle(fd: fds[1], acceptedAt: ProcessInfo.processInfo.systemUptime)
                shutdown(fds[1], SHUT_WR); done.fulfill()
            }
            writeRaw(raw(Data(#"{"version":1,"action":"status"}"#.utf8)), to: fds[0]); shutdown(fds[0], SHUT_WR)
            let response = try RouterSystemFrame.receive(fds[0], maximum: RouterSystemFrame.replyLimit, deadline: ProcessInfo.processInfo.systemUptime + 2)
            wait(for: [done], timeout: 2); close(fds[1])
            XCTAssertFalse(String(decoding: response, as: UTF8.self).contains("private-password"))
            XCTAssertEqual(executions, correctUID ? 1 : 0)
        }
    }
    func testLostReplyDoesNotRetryExecution() throws {
        let fds = try pair()
        let id = UUID().uuidString
        writeRaw(raw(Data("{\"version\":1,\"action\":\"apply\",\"id\":\"\(id)\",\"credentials\":[]}".utf8)), to: fds[0])
        shutdown(fds[0], SHUT_WR); close(fds[0])
        var executions = 0
        let server = RouterSystemSocketServer(ownerUID: getuid()) { _ in executions += 1; return .init(.empty()) }
        server.handle(fd: fds[1], acceptedAt: ProcessInfo.processInfo.systemUptime)
        close(fds[1]); XCTAssertEqual(executions, 1)
    }
}
