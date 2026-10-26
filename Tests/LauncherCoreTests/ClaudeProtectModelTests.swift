import XCTest
import CryptoKit
@testable import LauncherApp

@MainActor private final class ProtectFixture {
    var armed = false
    var installationValid = true
    var authHook: (() async -> Void)?
    var mutation = ProtectCommandResult()
    var commands: [ProtectCommand] = []
    var authCalls = 0
    let conf = "fixture rules\n"
    var sha: String { SHA256.hash(data: Data(conf.utf8)).map { String(format: "%02x", $0) }.joined() }
    func json(_ value: [String: Any], code: Int32 = 0) -> ProtectCommandResult {
        .init(exitCode: code, output: String(data: try! JSONSerialization.data(withJSONObject: value), encoding: .utf8)!)
    }
    func model() -> ClaudeProtectModel {
        .init(effects: .init(run: { command in
            self.commands.append(command)
            if command.arguments.contains("verify-installation") {
                return self.json(["status": self.installationValid ? "verified" : "blocked", "security_version": 2],
                                 code: self.installationValid ? 0 : 78)
            }
            if command.arguments.contains("generate") {
                return self.json(["status": "generated", "conf": self.conf, "conf_sha256": self.sha])
            }
            if command.arguments.contains("dry-run") {
                return self.json(["status": "dry_run_ok", "conf_sha256": self.sha])
            }
            if command.executable == "/usr/bin/osascript" {
                self.authCalls += 1
                await self.authHook?()
                if self.mutation.timedOut || self.mutation.exitCode != 0 { return self.mutation }
                self.armed = command.arguments.joined().contains("'enable'")
                return self.json(["product": "claude_protect_l3", "armed": self.armed,
                                  "status": self.armed ? "applied_anchor" : "unloaded_anchor"])
            }
            if command.arguments.contains(where: { $0.hasSuffix("claude_protect_guard.py") }) {
                return self.json(["product": "claude_protect_l4", "healthy": true, "proxy_port": 1082])
            }
            return self.json(["product": "claude_protect_l3", "status": "status", "armed": self.armed])
        }), toolsRoot: "/fixture")
    }
}

final class ClaudeProtectModelTests: XCTestCase {
    @MainActor private func settle(_ predicate: () -> Bool, file: StaticString = #filePath, line: UInt = #line) async throws {
        for _ in 0..<500 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        XCTFail("protect operation did not settle", file: file, line: line)
    }

    @MainActor func testRefreshRemainsAvailableDuringSystemAuthorizationAndNoDuplicateEnable() async throws {
        let fixture = ProtectFixture(), pause = DetectorTestPause()
        fixture.authHook = { await pause.wait() }
        let model = fixture.model()
        defer { pause.resume() }
        model.enableL3()
        try await settle { pause.waiting }
        XCTAssertTrue(model.busy)
        model.enableL3()
        model.refresh()
        try await settle { !model.refreshing && model.l3Armed == false }
        XCTAssertTrue(model.busy)
        XCTAssertEqual(fixture.authCalls, 1)
        pause.resume()
        try await settle { !model.busy && !model.refreshing && model.l3Armed == true }
        XCTAssertEqual(fixture.authCalls, 1)
        XCTAssertTrue(model.message.contains("系统已确认"))
        let mutations = fixture.commands.filter { $0.executable == "/usr/bin/osascript" }
        XCTAssertEqual(mutations.count, 1)
        XCTAssertTrue(mutations[0].arguments.joined().contains("with administrator privileges"))
        XCTAssertTrue(mutations[0].arguments.joined().contains("/Library/PrivilegedHelperTools/"))
        XCTAssertFalse(mutations[0].arguments.joined().contains("/fixture"))
        XCTAssertFalse(fixture.commands.contains { $0.arguments.contains("/usr/local/sbin/claude-protect-pf") })
        XCTAssertTrue(fixture.commands.filter { $0.executable == "/usr/bin/sudo" }.allSatisfy { $0.arguments.last == "status" })
    }

    @MainActor func testCancellationAndAuthorizationFailureDoNotRetryOrUsePasswordlessMutation() async throws {
        for result in [ProtectCommandResult(exitCode: 1, error: "User canceled. (-128)"),
                       ProtectCommandResult(exitCode: 1, error: "Authorization failed")] {
            let fixture = ProtectFixture()
            fixture.mutation = result
            let model = fixture.model()
            model.enableL3()
            try await settle { !model.busy && !model.refreshing }
            XCTAssertEqual(fixture.authCalls, 1)
            XCTAssertFalse(fixture.armed)
            XCTAssertFalse(model.message.isEmpty)
            XCTAssertTrue(fixture.commands.filter { $0.executable == "/usr/bin/sudo" }.allSatisfy { $0.arguments.last == "status" })
        }
    }

    @MainActor func testMissingOrUnsafeInstallationNeverElevatesBundledOrLegacyCode() async throws {
        let fixture = ProtectFixture()
        fixture.installationValid = false
        let model = fixture.model()
        model.enableL3()
        try await settle { !model.busy && !model.refreshing }
        XCTAssertEqual(fixture.authCalls, 0)
        XCTAssertFalse(fixture.commands.contains { $0.executable == "/usr/bin/sudo" })
        XCTAssertTrue(model.message.contains("安全升级"))
    }

    @MainActor func testCommandFailureSurvivesAutomaticAndManualRefresh() async throws {
        let fixture = ProtectFixture()
        fixture.mutation = fixture.json(["status": "blocked", "reason": "enable_hook_failed"], code: 78)
        let model = fixture.model()
        model.enableL3()
        try await settle { !model.busy && !model.refreshing }
        XCTAssertTrue(model.message.contains("开启未完成"))
        let message = model.message
        model.refresh()
        try await settle { !model.refreshing }
        XCTAssertEqual(model.message, message)
    }

    @MainActor func testTimedOutMutationReleasesBusyButDoesNotSilentlyRetry() async throws {
        for timeout in [ProtectCommandResult(exitCode: -1, timedOut: true),
                        ProtectCommandResult(exitCode: 1, error: "AppleEvent timed out. (-1712)")] {
            let fixture = ProtectFixture()
            fixture.mutation = timeout
            let model = fixture.model()
            model.enableL3()
            try await settle { !model.busy && !model.refreshing }
            XCTAssertTrue(model.mutationOutcomeUnknown)
            model.enableL3()
            model.refresh()
            try await settle { !model.refreshing }
            XCTAssertEqual(fixture.authCalls, 1)
        }
    }

    @MainActor func testEnableRegeneratesAfterPreviewAndDisableUsesSystemAuthorizationToo() async throws {
        let fixture = ProtectFixture(), model = fixture.model()
        model.previewL3()
        try await settle { !model.busy }
        model.enableL3()
        try await settle { !model.busy && !model.refreshing }
        XCTAssertEqual(fixture.commands.filter { $0.arguments.contains("generate") }.count, 2)
        model.disableL3()
        try await settle { !model.busy && !model.refreshing }
        XCTAssertEqual(fixture.authCalls, 2)
        XCTAssertEqual(model.l3Armed, false)
    }

    @MainActor func testIncompleteStatusNeverBecomesDisabledOrEnabled() {
        XCTAssertNil(ClaudeProtectModel.armed(nil))
        XCTAssertNil(ClaudeProtectModel.armed(["armed": true]))
        XCTAssertNil(ClaudeProtectModel.armed(["product": "claude_protect_l3", "status": "status", "armed": false, "soft": true]))
    }
}

final class ProtectProcessTests: XCTestCase {
    func testHangingProcessHasBoundedTimeout() async {
        let start = Date()
        let result = await ProtectProcess.run(.init(executable: "/bin/sleep", arguments: ["5"], timeout: 0.1))
        XCTAssertTrue(result.timedOut)
        XCTAssertFalse(result.succeeded)
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }

    func testBothOutputPipesAreDrainedBeforeExit() async {
        let result = await ProtectProcess.run(.init(executable: "/usr/bin/python3", arguments: ["-I", "-B", "-c",
            "import sys; sys.stdout.write('x'*100000); sys.stderr.write('y'*100000)"], timeout: 5))
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.output.count, 100000)
        XCTAssertEqual(result.error.count, 100000)
    }

    func testInheritedOpenPipeDoesNotDelayCompletedParent() async {
        let start = Date()
        let result = await ProtectProcess.run(.init(executable: "/bin/sh", arguments: ["-c", "sleep 3 & printf done"], timeout: 5))
        XCTAssertTrue(result.succeeded)
        XCTAssertEqual(result.output, "done")
        XCTAssertLessThan(Date().timeIntervalSince(start), 2)
    }
}
