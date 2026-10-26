import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemControllerHTTPTests: XCTestCase {
    private typealias HTTP = RouterSystemControllerHTTP
    private let valid = "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
    func testEOFAndLengthFraming() throws {
        XCTAssertEqual(try HTTP.parse(Data(valid.utf8)).body, Data("{}".utf8))
        XCTAssertEqual(try HTTP.parse(Data(valid.replacingOccurrences(of: "Content-Length: 2\r\n", with: "").utf8)).status, 200)
        XCTAssertEqual(try HTTP.parse(Data("HTTP/1.0 401 Unauthorized\r\n\r\nDenied".utf8)).status, 401)
        for bad in [valid + "x", String(valid.dropLast()), valid.replacingOccurrences(of: "Length: 2", with: "Length: -2"),
                    valid.replacingOccurrences(of: "Length: 2", with: "Length: 2\r\ncontent-length: 2"),
                    valid.replacingOccurrences(of: "Length: 2", with: "Length: 2\r\nTransfer-Encoding: chunked"),
                    valid.replacingOccurrences(of: "Length: 2", with: "Length: 2\r\nContent-Encoding: gzip")] {
            XCTAssertThrowsError(try HTTP.parse(Data(bad.utf8)))
        }
    }
    func testResponseSyntaxAndLimits() {
        let invalid = [valid.replacingOccurrences(of: "200 OK", with: "302 Found"),
            valid.replacingOccurrences(of: "\r\n", with: "\n"),
            valid.replacingOccurrences(of: "Content-Type:", with: " Content-Type:"),
            valid.replacingOccurrences(of: "application/json", with: "text/plain"),
            valid.replacingOccurrences(of: "Content-Length", with: "Content\0Length"),
            valid.replacingOccurrences(of: "Content-Length: 2", with: "X-Long: " + String(repeating: "a", count: 17000)),
            "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n" + String(repeating: "a", count: 65536)]
        for bad in invalid { XCTAssertThrowsError(try HTTP.parse(Data(bad.utf8))) }
    }
    private func pair() throws -> [Int32] {
        var pair = [Int32](repeating: -1, count: 2)
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw RouterSystemError.operationUnsettled }
        for fd in pair { XCTAssertEqual(fcntl(fd, F_SETNOSIGPIPE, 1), 0) }
        return pair
    }
    func testRealSocketpairPartialResponseAndEOFMandatory() throws {
        let sockets = try pair(), complete = expectation(description: "fixture response")
        defer { close(sockets[0]) }
        let payload = Data(valid.utf8)
        DispatchQueue.global().async {
            defer { close(sockets[1]); complete.fulfill() }
            var request = [UInt8](repeating: 0, count: 4096)
            let read = Darwin.read(sockets[1], &request, request.count)
            XCTAssertGreaterThan(read, 0)
            let text = String(decoding: request.prefix(max(0, read)), as: UTF8.self)
            XCTAssertTrue(text.hasPrefix("GET /configs HTTP/1.0\r\n"))
            for byte in payload {
                var value = byte
                XCTAssertEqual(Darwin.write(sockets[1], &value, 1), 1)
            }
        }
        XCTAssertEqual(try HTTP.fixtureExchange(fd: sockets[0], deadline: ProcessInfo.processInfo.systemUptime + 2).body, Data("{}".utf8))
        wait(for: [complete], timeout: 2)
    }
    func testCompleteBodyWithoutEOFStillTimesOutAndClosedPeerDoesNotSignal() throws {
        let sockets = try pair()
        defer { sockets.forEach { close($0) } }
        let bytes = Data(valid.utf8)
        XCTAssertEqual(bytes.withUnsafeBytes { Darwin.write(sockets[1], $0.baseAddress, $0.count) }, bytes.count)
        XCTAssertThrowsError(try HTTP.fixtureExchange(fd: sockets[0], deadline: ProcessInfo.processInfo.systemUptime + 0.03))
        let closed = try pair(); close(closed[1]); defer { close(closed[0]) }
        XCTAssertThrowsError(try HTTP.fixtureExchange(fd: closed[0], deadline: ProcessInfo.processInfo.systemUptime + 0.2))
    }
    func testInvalidSecretAndExpiredDeadlineMakeNoRequest() {
        XCTAssertThrowsError(try HTTP.declaration(secret: "wrong\r\nheader", until: ProcessInfo.processInfo.systemUptime + 1))
        XCTAssertThrowsError(try HTTP.declaration(secret: String(repeating: "a", count: 64), until: ProcessInfo.processInfo.systemUptime - 1))
    }
}
