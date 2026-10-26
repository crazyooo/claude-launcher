import XCTest
import Darwin
@testable import LauncherCore

final class RecoveryMutationTests: XCTestCase {
    func testCancelBeforeSendAndPartialWriteNeverRetry() throws {
        let command = try XCTUnwrap(RecoveryFixture().operation().pending)
        for cancel in [true, false] {
            let permit = try RecoveryMutationPermit(command: command, generation: 1)
            var calls = 0
            if cancel { permit.cancel() }
            for _ in 0..<2 {
                XCTAssertThrowsError(try permit.write(-1, data: Data([1, 2]), deadline: connectorTime() + 1) { _, _ in calls += 1; return 1 })
            }
            XCTAssertEqual(calls, cancel ? 0 : 1)
        }
    }
    func testRealNonblockingSocketWritesExactlyOneFrame() throws {
        let command = try XCTUnwrap(RecoveryFixture().operation().pending)
        let permit = try RecoveryMutationPermit(command: command, generation: 2)
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        try ConnectorSocket.prepare(pair[0]); try ConnectorSocket.prepare(pair[1])
        let bytes = try JSONEncoder().encode(command)
        try permit.write(pair[0], data: bytes + Data([10]), deadline: connectorTime() + 1)
        XCTAssertEqual(try ConnectorSocket.read(pair[1], limit: 8192, deadline: connectorTime() + 1), bytes)
        permit.cancel()
        XCTAssertThrowsError(try permit.write(pair[0], data: bytes + Data([10]), deadline: connectorTime() + 1))
        var item = pollfd(fd: pair[1], events: Int16(POLLIN), revents: 0)
        XCTAssertEqual(poll(&item, 1, 0), 0)
    }
    func testWriteBeforeCancellationMayArriveButCannotRepeat() throws {
        let command = try XCTUnwrap(RecoveryFixture().operation().pending)
        let permit = try RecoveryMutationPermit(command: command, generation: 3)
        let entered = expectation(description: "write entered"), finished = expectation(description: "writer returned")
        let cancelled = expectation(description: "cancellation returned"), release = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            do {
                try permit.write(-1, data: Data([1]), deadline: connectorTime() + 2) { _, data in
                    entered.fulfill(); _ = release.wait(timeout: .now() + 1); return data.count
                }
            } catch { XCTFail("fixture write failed") }
            finished.fulfill()
        }
        wait(for: [entered], timeout: 1)
        DispatchQueue.global().async { permit.cancel(); cancelled.fulfill() }
        release.signal(); wait(for: [finished, cancelled], timeout: 2)
        XCTAssertThrowsError(try permit.write(-1, data: Data([1]), deadline: connectorTime() + 1) { _, _ in XCTFail("repeated"); return 1 })
    }
}
