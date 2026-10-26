import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemCommandTests: XCTestCase {
    private func runner() throws -> RouterSystemCommand { try .init(ownerUID: 501) }
    func testCapturesOnlyStdoutAndPreservesExitCode() throws {
        let runner = try runner()
        let (result, bytes) = try runner.fixtureCapture("/bin/sh", ["-c", "printf observed; printf secret >&2; exit 7"], timeout: 1)
        XCTAssertEqual(result.exitCode, 7)
        XCTAssertTrue(result.settled); XCTAssertFalse(result.timedOut)
        XCTAssertEqual(String(decoding: bytes, as: UTF8.self), "observed")
        let (next, _) = try runner.fixtureCapture("/usr/bin/true", [], timeout: 1)
        XCTAssertEqual(next.exitCode, 0)
    }
    func testTimeoutKillsAndReapsExactChildEvenWhenTermIgnored() throws {
        let runner = try runner()
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("router-command-pid-" + UUID().uuidString)
        let began = ProcessInfo.processInfo.systemUptime
        let (result, bytes) = try runner.fixtureCapture("/bin/sh",
            ["-c", "trap '' TERM; printf '%s' $$ > \"$1\"; while :; do :; done", "fixture", file.path], timeout: 0.1)
        XCTAssertTrue(result.timedOut); XCTAssertTrue(result.settled); XCTAssertTrue(bytes.isEmpty)
        XCTAssertEqual(result.exitCode, 128 + SIGKILL)
        XCTAssertLessThan(ProcessInfo.processInfo.systemUptime - began, 2.5)
        let pid = try XCTUnwrap(Int32(String(contentsOf: file, encoding: .utf8)))
        var status: Int32 = 0
        XCTAssertEqual(waitpid(pid, &status, WNOHANG), -1)
        XCTAssertEqual(errno, ECHILD)
        XCTAssertEqual(try runner.fixtureCapture("/usr/bin/true", [], timeout: 1).0.exitCode, 0)
    }
    func testOverflowDiscardsOutputAndAllowsOnlySettledNextCommand() throws {
        let runner = try runner()
        XCTAssertThrowsError(try runner.fixtureCapture("/usr/bin/yes", ["private-value"], timeout: 1)) { error in
            XCTAssertFalse(String(describing: error).contains("private-value"))
        }
        XCTAssertEqual(try runner.fixtureCapture("/usr/bin/true", [], timeout: 1).0.exitCode, 0)
    }
    func testEOFDoesNotSubstituteForExit() throws {
        let began = ProcessInfo.processInfo.systemUptime
        let (result, data) = try runner().fixtureCapture("/bin/sh", ["-c", "exec 1>&-; exec /bin/sleep 0.15"], timeout: 1)
        XCTAssertFalse(result.timedOut); XCTAssertTrue(result.settled); XCTAssertTrue(data.isEmpty)
        XCTAssertGreaterThanOrEqual(ProcessInfo.processInfo.systemUptime - began, 0.14)
    }
    func testExitWithoutPipeEOFRemainsBoundedAndIsNotSuccess() throws {
        let (result, data) = try runner().fixtureCapture("/bin/sh", ["-c", "/bin/sleep 0.3 & exit 0"], timeout: 0.06)
        XCTAssertTrue(result.timedOut); XCTAssertTrue(result.settled); XCTAssertTrue(data.isEmpty)
        // Only the direct child is owned; this fixture descendant exits itself, without any network work.
        Thread.sleep(forTimeInterval: 0.35)
    }
    func testConcurrentRequestIsRejectedBeforeSpawn() throws {
        let runner = try runner(), done = expectation(description: "first request")
        let file = FileManager.default.temporaryDirectory.appendingPathComponent("router-command-start-" + UUID().uuidString)
        DispatchQueue.global().async {
            do {
                _ = try runner.fixtureCapture("/bin/sh", ["-c", "printf ready > \"$1\"; exec /bin/sleep 0.3", "fixture", file.path], timeout: 1)
            } catch { XCTFail("first command failed") }
            done.fulfill()
        }
        let deadline = ProcessInfo.processInfo.systemUptime + 1
        while !FileManager.default.fileExists(atPath: file.path) && ProcessInfo.processInfo.systemUptime < deadline { usleep(1000) }
        XCTAssertTrue(FileManager.default.fileExists(atPath: file.path))
        XCTAssertThrowsError(try runner.fixtureCapture("/usr/bin/true", [], timeout: 1))
        wait(for: [done], timeout: 2)
    }
    func testSpawnFailureAndWhitelistRejectArbitraryArguments() throws {
        let runner = try runner()
        XCTAssertThrowsError(try runner.fixtureCapture("/nonexistent/router-command", [], timeout: 1))
        XCTAssertEqual(try runner.fixtureCapture("/usr/bin/true", [], timeout: 1).0.exitCode, 0)
        for (path, args) in [("/bin/sh", ["-c", "true"]),
                             ("/bin/launchctl", ["bootout", "system"]),
                             ("/bin/launchctl", ["print", "gui/502/" + RouterCoreRelease.label]),
                             ("/usr/sbin/netstat", ["-rn", "-f", "inet", "extra"])] {
            XCTAssertThrowsError(try runner.captureObservation(path, args, 3))
        }
        XCTAssertThrowsError(try RouterSystemCommand(ownerUID: 0))
    }
    func testPinnedCoreValidationThroughPOSIXRunnerWithNetworkDenied() throws {
        guard let path = ProcessInfo.processInfo.environment["ROUTER_TEST_PINNED_CORE"] else {
            throw XCTSkip("Set ROUTER_TEST_PINNED_CORE for the offline core integration test")
        }
        let runner = try runner()
        let base = try XCTUnwrap(RouterRuntimeFiles.physicalPath(FileManager.default.temporaryDirectory))
        let configuration = try RouterSystemCompiler.compile(
            plan: .init(proxies: [], rules: [], defaultDestination: .direct), profile: .init(resolver: .quad9),
            secret: String(repeating: "a", count: 64), credentials: [:])
        try RouterCoreCheck.checkBytes(core: URL(fileURLWithPath: path), data: configuration.privateJSON,
            workspace: URL(fileURLWithPath: base).appendingPathComponent("system-posix-check-" + UUID().uuidString),
            loadCore: RouterCoreRelease.verifiedBytes, execute: { path, args, timeout in
                try runner.fixtureCapture(path, args, timeout: timeout).0
            })
    }
}
