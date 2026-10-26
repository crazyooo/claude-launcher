import XCTest
@testable import RoutingCore

/// Offline gate tests for the PF arming script loader + arming recipe.
/// The live-verified invocation (2026-10-24) is: `/opt/homebrew/bin/python3 -S
/// tools/router_pf_failclosed.py …` with osascript admin elevation for root steps.
final class RouterPFArmingScriptEffectsTests: XCTestCase {
    private var repoRoot: String {
        let file = #filePath
        guard let range = file.range(of: "/Tests/") else { fatalError("unexpected test path") }
        return String(file[..<range.lowerBound])
    }

    private func tempDir() -> String {
        let dir = NSTemporaryDirectory() + "pf-script-effects-" + UUID().uuidString
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Fixture interpreter: records the forwarded argv, emits a canned applied JSON.
    private func fixtureScript(record: String, payload: String) -> String {
        let path = tempDir() + "/fake_python.sh"
        let body = """
        #!/bin/bash
        printf '%s\\n' "$0" "$@" > '\(record)'
        echo '\(payload)'
        """
        try? body.write(toFile: path, atomically: true, encoding: .utf8)
        try? FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: path)
        return path
    }

    private func preview(planDigest: String) -> RouterPFArmingExecuteGate.Preview {
        .init(id: UUID(), planDigest: planDigest, designedLayer: .packetFilterAnchorDefaultDeny,
              subjectCount: 1, bullets: [], issuedAt: Date(), expiresAt: Date().addingTimeInterval(60),
              dimensions: [], routingVerified: false, accepted: false,
              wouldMutateNetworkIfArmed: true,
              confirmationWindowID: RouterPFArmingExecuteGate.confirmationWindowID,
              rulesetApplicable: true, rulesetBlockers: [], summary: "test")
    }

    let digest = String(repeating: "6", count: 64)

    func testDigestGateRefusesMismatchedPreviewWithoutSpawn() {
        let record = tempDir() + "/record"
        let config = RouterPFArmingScriptEffects.Config(
            python: "/bin/bash", pythonFlags: [],
            script: fixtureScript(record: record, payload: "{}"),
            artifactPath: "/tmp/artifact.json", planDigest: digest,
            acknowledgeMutation: true, confirmWindow: true)
        let effects = RouterPFArmingScriptEffects.make(config: config)
        let outcome = try! effects.loadFailClosed!(preview(planDigest: String(repeating: "7", count: 64)))
        XCTAssertFalse(outcome.armed)
        XCTAssertFalse(outcome.networkModified)
        XCTAssertEqual(outcome.detail, "script_loader_plan_digest_gate")
        XCTAssertFalse(FileManager.default.fileExists(atPath: record), "must refuse without spawning")
    }

    func testDigestGateRefusesShortDigestWithoutSpawn() {
        // Regression: the previous `a == b || b.count == 64` shape let any 64-hex
        // config digest bypass the preview binding. A short configured digest must
        // refuse even when it equals the preview digest.
        let record = tempDir() + "/record"
        let short = String(repeating: "6", count: 32)
        let config = RouterPFArmingScriptEffects.Config(
            python: "/bin/bash", pythonFlags: [],
            script: fixtureScript(record: record, payload: "{}"),
            artifactPath: "/tmp/artifact.json", planDigest: short,
            acknowledgeMutation: true, confirmWindow: true)
        let effects = RouterPFArmingScriptEffects.make(config: config)
        let outcome = try! effects.loadFailClosed!(preview(planDigest: short))
        XCTAssertEqual(outcome.detail, "script_loader_plan_digest_gate")
        XCTAssertFalse(FileManager.default.fileExists(atPath: record))
    }

    func testMissingDualConfirmFlagsRefuseWithoutSpawn() {
        let record = tempDir() + "/record"
        let config = RouterPFArmingScriptEffects.Config(
            python: "/bin/bash", pythonFlags: [],
            script: fixtureScript(record: record, payload: "{}"),
            artifactPath: "/tmp/artifact.json", planDigest: digest,
            acknowledgeMutation: true, confirmWindow: false)
        let effects = RouterPFArmingScriptEffects.make(config: config)
        let outcome = try! effects.loadFailClosed!(preview(planDigest: digest))
        XCTAssertEqual(outcome.detail, "script_loader_refused_missing_dual_confirm_flags")
        XCTAssertFalse(FileManager.default.fileExists(atPath: record))
    }

    func testApplySpawnsScriptWithExpectedArguments() throws {
        let record = tempDir() + "/record"
        let script = fixtureScript(record: record, payload:
            "{\"armed\": true, \"pf_modified\": true, \"pf_rules_loaded\": true, \"status\": \"applied_anchor\"}")
        let config = RouterPFArmingScriptEffects.Config(
            python: "/bin/bash", pythonFlags: [], script: script,
            artifactPath: "/tmp/artifact.json", planDigest: digest,
            acknowledgeMutation: true, confirmWindow: true)
        let effects = RouterPFArmingScriptEffects.make(config: config)
        let outcome = try XCTUnwrap(try effects.loadFailClosed!(preview(planDigest: digest)))
        XCTAssertTrue(outcome.armed)
        XCTAssertTrue(outcome.networkModified)
        XCTAssertTrue(outcome.pfRulesLoaded)
        XCTAssertTrue(outcome.detail.contains("applied_anchor"))
        let recorded = try String(contentsOfFile: record, encoding: .utf8).split(separator: "\n").map(String.init)
        XCTAssertEqual(recorded, [
            script, "apply", "--artifact", "/tmp/artifact.json",
            "--plan-digest", digest,
            "--i-confirm-pf-arming-user-confirm-v1", "--i-acknowledge-network-mutation",
        ])
    }

    func testDirectInvocationPrependsInterpreterFlags() {
        let config = RouterPFArmingScriptEffects.Config(
            python: "/opt/homebrew/bin/python3", pythonFlags: ["-S"],
            script: "/repo/tools/router_pf_failclosed.py",
            artifactPath: "/tmp/a.json", planDigest: digest,
            acknowledgeMutation: true, confirmWindow: true)
        let invocation = RouterPFArmingScriptEffects.wrappedInvocation(
            config: config,
            arguments: RouterPFArmingScriptEffects.applyArguments(config: config))
        XCTAssertEqual(invocation.executable, "/opt/homebrew/bin/python3")
        XCTAssertEqual(invocation.arguments.first, "-S")
        XCTAssertEqual(invocation.arguments.dropFirst().first, "/repo/tools/router_pf_failclosed.py")
        XCTAssertTrue(invocation.arguments.contains("--i-confirm-pf-arming-user-confirm-v1"))
    }

    func testOsascriptAdminWrapsQuotedCommandLine() throws {
        let config = RouterPFArmingScriptEffects.Config(
            python: "/opt/homebrew/bin/python3", pythonFlags: ["-S"],
            script: "/repo/tools/router_pf_failclosed.py",
            artifactPath: "/tmp/a.json", planDigest: digest,
            acknowledgeMutation: true, confirmWindow: true,
            elevation: .osascriptAdmin)
        let invocation = RouterPFArmingScriptEffects.wrappedInvocation(
            config: config,
            arguments: RouterPFArmingScriptEffects.applyArguments(config: config))
        XCTAssertEqual(invocation.executable, "/usr/bin/osascript")
        XCTAssertEqual(invocation.arguments.first, "-e")
        let appleScript = try XCTUnwrap(invocation.arguments.last)
        XCTAssertTrue(appleScript.contains("with administrator privileges"))
        // Interpreter + flags + script are all shell-quoted inside the AppleScript line.
        XCTAssertTrue(appleScript.contains("'/opt/homebrew/bin/python3'"))
        XCTAssertTrue(appleScript.contains("'-S'"))
        XCTAssertTrue(appleScript.contains("'/repo/tools/router_pf_failclosed.py'"))
        XCTAssertTrue(appleScript.contains("'--i-acknowledge-network-mutation'"))
    }

    func testUnloadAndStatusArgumentShapes() {
        let config = RouterPFArmingScriptEffects.Config(
            python: "/bin/bash", pythonFlags: [], script: "/repo/tools/router_pf_failclosed.py",
            artifactPath: "/tmp/a.json", planDigest: digest)
        XCTAssertEqual(RouterPFArmingScriptEffects.commandArguments(
            command: .unload, config: config, confirmUnload: true),
            ["/repo/tools/router_pf_failclosed.py", "unload", "--i-confirm-unload"])
        XCTAssertEqual(RouterPFArmingScriptEffects.commandArguments(
            command: .unload, config: config, confirmUnload: false),
            ["/repo/tools/router_pf_failclosed.py", "unload"])
        XCTAssertEqual(RouterPFArmingScriptEffects.commandArguments(
            command: .status, config: config, confirmUnload: false),
            ["/repo/tools/router_pf_failclosed.py", "status"])
    }

    // MARK: - Recipe against the real script (generate + dry-run, no PF mutation)

    private var pythonPath: String { "/opt/homebrew/bin/python3" }

    private func writePlan(directory: String) throws -> String {
        let plan = """
        {"schemaVersion":1,"proxies":[],"rules":[{"id":"\(UUID().uuidString.lowercased())",\
        "selector":{"domain":{"kind":"exact","value":"anthropic.com"}},\
        "destination":{"kind":"block"}}],"defaultDestination":{"kind":"direct"}}
        """
        let path = directory + "/plan.json"
        try plan.write(toFile: path, atomically: true, encoding: .utf8)
        return path
    }

    func testPrepareGeneratesApplicableArtifactAndPassesDryRun() throws {
        let python = pythonPath
        guard FileManager.default.isExecutableFile(atPath: python) else { throw XCTSkip("python3 not present") }
        let directory = tempDir()
        let planPath = try writePlan(directory: directory)
        let recipe = RouterPFArmingScriptEffects.Recipe(
            python: python, pythonFlags: ["-S"],
            script: repoRoot + "/tools/router_pf_failclosed.py",
            planPath: planPath, planDigest: digest,
            addresses: ["2607:6bc0::10", "160.79.104.10"],
            outputDir: directory)
        let config = try recipe.prepare()
        XCTAssertEqual(config.planDigest, digest)
        XCTAssertEqual(config.artifactPath, directory + "/failclosed.artifact.json")
        let artifact = try JSONSerialization.jsonObject(
            with: Data(contentsOf: URL(fileURLWithPath: config.artifactPath))) as! [String: Any]
        XCTAssertEqual(artifact["applicable"] as? Bool, true)
        XCTAssertEqual(Set(artifact["addresses"] as? [String] ?? []),
                       ["160.79.104.10", "2607:6bc0::10"])
        XCTAssertTrue(FileManager.default.fileExists(atPath: directory + "/failclosed.pf.conf"))
    }

    func testPrepareRefusesEmptyAddresses() throws {
        let directory = tempDir()
        let planPath = try writePlan(directory: directory)
        let recipe = RouterPFArmingScriptEffects.Recipe(
            script: repoRoot + "/tools/router_pf_failclosed.py",
            planPath: planPath, planDigest: digest, addresses: [], outputDir: directory)
        XCTAssertThrowsError(try recipe.prepare()) { error in
            XCTAssertEqual(error as? RouterPFArmingScriptEffects.RecipeError, .addressesRequired)
        }
    }

    func testPrepareRefusesShortDigest() throws {
        let directory = tempDir()
        let planPath = try writePlan(directory: directory)
        let recipe = RouterPFArmingScriptEffects.Recipe(
            script: repoRoot + "/tools/router_pf_failclosed.py",
            planPath: planPath, planDigest: String(repeating: "6", count: 32),
            addresses: ["160.79.104.10"], outputDir: directory)
        XCTAssertThrowsError(try recipe.prepare()) { error in
            XCTAssertEqual(error as? RouterPFArmingScriptEffects.RecipeError, .digestShapeInvalid)
        }
    }
}
