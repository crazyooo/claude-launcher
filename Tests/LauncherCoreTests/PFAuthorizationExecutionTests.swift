import XCTest
import Darwin
@testable import LauncherCore

final class PFAuthorizationExecutionTests: XCTestCase {
    func request() throws -> PFRecoveryRequest {
        let values: [String: Any] = ["version": 1, "plan_id": String(repeating: "a", count: 32),
            "plan_sha256": String(repeating: "b", count: 64), "runtime_sha256": String(repeating: "c", count: 64),
            "service_instance": String(repeating: "d", count: 32), "receipt_revision": 0]
        let context = try JSONDecoder().decode(PFControlContext.self, from: JSONSerialization.data(withJSONObject: values))
        return .init(context: context, epoch: 14, now: Date())
    }
    func identity(_ id: UUID = UUID()) throws -> PFAuthorizationExecutionIdentity {
        try PFAuthorizationProcessIdentity.capture(pid: getpid(), executionID: id)
    }
    func object<T: Encodable>(_ value: T) throws -> [String: Any] {
        try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(value)) as? [String: Any])
    }

    func testStrictRoundTripPreservesRequestAndRejectsForgedIntent() throws {
        let initial = PFAuthorizationIntent(request: try request(), executionID: UUID())
        let armed = try initial.armed(with: identity(initial.executionID))
        for intent in [initial, armed] {
            XCTAssertEqual(try JSONDecoder().decode(PFAuthorizationIntent.self, from: JSONEncoder().encode(intent)), intent)
            var changed = try object(intent); changed["passed"] = true
            XCTAssertThrowsError(try JSONDecoder().decode(PFAuthorizationIntent.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
        for change: [String: Any] in [["version": true], ["startMayHaveBeenSent": false], ["identity": NSNull()],
                                      ["executionID": UUID().uuidString]] {
            var changed = try object(armed); changed.merge(change) { _, next in next }
            XCTAssertThrowsError(try JSONDecoder().decode(PFAuthorizationIntent.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
        for change: [String: Any] in [["id": "bad"], ["epoch": -1], ["epoch": true], ["createdAt": 1e300], ["secret": "bad"]] {
            var changed = try object(initial.request); changed.merge(change) { _, next in next }
            XCTAssertThrowsError(try JSONDecoder().decode(PFRecoveryRequest.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
        XCTAssertThrowsError(try armed.armed(with: identity(initial.executionID)))
    }

    func testUnknownIdentityNeverBecomesExitAndRealCurrentProcessIsAlive() throws {
        let saved = try identity()
        XCTAssertEqual(saved.observe(), .sameProcessAlive)
        func evaluate(_ boot: UUID?, _ sample: PFAuthorizationProcessIdentity.Sample) -> PFAuthorizationExecutionState {
            PFAuthorizationProcessIdentity.evaluate(saved, boot: boot, sample: { sample })
        }
        XCTAssertEqual(evaluate(nil, .absent), .unknown)
        XCTAssertEqual(evaluate(saved.bootUUID, .unknown), .unknown)
        XCTAssertEqual(evaluate(saved.bootUUID, .absent), .originalExited)
        XCTAssertEqual(evaluate(UUID(), .unknown), .originalExited)
        XCTAssertEqual(evaluate(saved.bootUUID, .process(pid: saved.pid, seconds: saved.startSeconds + 1, microseconds: 0)), .originalExited)
        XCTAssertEqual(evaluate(saved.bootUUID, .process(pid: saved.pid + 1, seconds: saved.startSeconds, microseconds: 0)), .unknown)
        XCTAssertEqual(evaluate(saved.bootUUID, .process(pid: saved.pid, seconds: 0, microseconds: 0)), .unknown)
        XCTAssertEqual(evaluate(saved.bootUUID, .process(pid: saved.pid, seconds: saved.startSeconds, microseconds: 1_000_000)), .unknown)
        XCTAssertThrowsError(try PFAuthorizationProcessIdentity.capture(pid: -1, executionID: UUID()))
    }

    func testKernelIdentitySurvivesRealHarmlessExecAndDetectsExit() throws {
        let child = Process(), input = Pipe()
        child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        child.arguments = ["-I", "-S", "-B", "-c", "import os,sys; sys.stdin.read(); os.execv('/bin/sleep',['sleep','0.3'])"]
        child.standardInput = input; child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
        try child.run()
        let before = try PFAuthorizationProcessIdentity.capture(pid: child.processIdentifier, executionID: UUID())
        try input.fileHandleForWriting.close()
        Thread.sleep(forTimeInterval: 0.15)
        let after = try PFAuthorizationProcessIdentity.capture(pid: child.processIdentifier, executionID: before.executionID)
        XCTAssertEqual(before, after); XCTAssertEqual(before.observe(), .sameProcessAlive)
        let deadline = connectorTime() + 3
        while child.isRunning && connectorTime() < deadline { Thread.sleep(forTimeInterval: 0.01) }
        if child.isRunning { child.terminate(); XCTFail("harmless fixture did not exit") }
        XCTAssertFalse(child.isRunning); XCTAssertEqual(before.observe(), .originalExited)
    }

    func testGateRequiresFullFrameEOFMatchingIdentityAndBoundedWait() throws {
        let saved = try identity(), frame = try JSONEncoder().encode(PFAuthorizationStart(execution: saved, request: request()))
        func read(_ data: Data, eof: Bool = true, expected: PFAuthorizationExecutionIdentity? = nil) throws -> PFAuthorizationStart {
            let pipe = Pipe()
            defer { try? pipe.fileHandleForReading.close(); if !eof { try? pipe.fileHandleForWriting.close() } }
            try pipe.fileHandleForWriting.write(contentsOf: data)
            if eof { try pipe.fileHandleForWriting.close() }
            return try PFAuthorizationGate.readStart(fd: pipe.fileHandleForReading.fileDescriptor,
                                                    expected: expected ?? saved, deadline: connectorTime() + 0.05)
        }
        XCTAssertEqual(try read(frame).execution, saved)
        for bad in [Data(), Data(frame.dropLast()), frame + Data("{}".utf8), Data(repeating: 65, count: 4097)] {
            XCTAssertThrowsError(try read(bad))
        }
        XCTAssertThrowsError(try read(frame, expected: identity()))
        let before = connectorTime()
        XCTAssertThrowsError(try read(frame, eof: false))
        XCTAssertLessThan(connectorTime() - before, 0.3)
    }

    private func run(_ intent: PFAuthorizationIntent, source: String? = nil, timeout: Double = 2,
                     permit: PFAuthorizationStartPermit = .init(),
                     persist: (PFAuthorizationIntent) throws -> Void) -> BoundedProcess.Capture {
        // A harmless Python wire peer. It never invokes osascript or root code.
        let normal = "import sys,json,os\nprint('PF_AUTH_READY_V1 '+sys.argv[1],flush=True)\na=json.load(sys.stdin)\nassert a['execution']['pid']==os.getpid()\nprint('fixture-started')"
        return GatedAuthorizationProcess.capture(executable: "/usr/bin/python3",
            arguments: ["-I", "-S", "-B", "-c", source ?? normal, intent.executionID.uuidString],
            intent: intent, timeout: timeout, permit: permit, persistBeforeStart: persist)
    }

    func testTransportSavesFullIdentityBeforeStartAndReturnsOnlyPostReadyResult() throws {
        let intent = PFAuthorizationIntent(request: try request(), executionID: UUID())
        var armed: PFAuthorizationIntent?, count = 0
        let result = run(intent) { record in
            count += 1; armed = record
            XCTAssertEqual(record.request, intent.request)
            XCTAssertEqual(record.executionID, intent.executionID)
            XCTAssertTrue(record.startMayHaveBeenSent)
            XCTAssertEqual(record.identity?.observe(), .sameProcessAlive)
        }
        XCTAssertEqual(count, 1); XCTAssertNotNil(armed)
        XCTAssertTrue(result.complete); XCTAssertTrue(result.settled)
        XCTAssertEqual(String(decoding: result.data, as: UTF8.self), "fixture-started\n")
        XCTAssertEqual(armed?.identity?.observe(), .originalExited)
        var replayed = false
        XCTAssertFalse(run(try XCTUnwrap(armed)) { _ in replayed = true }.complete)
        XCTAssertFalse(replayed)
    }

    func testPersistenceFailureAndExpiredBudgetDoNotSendStart() throws {
        let intent = PFAuthorizationIntent(request: try request(), executionID: UUID())
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("auth-marker-\(UUID().uuidString)")
        let marker = "import sys,json,pathlib\nprint('PF_AUTH_READY_V1 '+sys.argv[1],flush=True)\njson.load(sys.stdin)\npathlib.Path('\(url.path)').write_text('started')"
        var saved: PFAuthorizationIntent?
        let failure = run(intent, source: marker) { record in saved = record; throw PFAuthorizationGate.failure }
        XCTAssertFalse(failure.complete); XCTAssertTrue(failure.settled); XCTAssertNotNil(saved)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        let expired = run(intent, source: marker, timeout: 0.2) { _ in Thread.sleep(forTimeInterval: 0.25) }
        XCTAssertFalse(expired.complete); XCTAssertTrue(expired.settled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        let permit = PFAuthorizationStartPermit()
        let cancelled = run(intent, source: marker, permit: permit) { _ in permit.cancel() }
        XCTAssertFalse(cancelled.complete); XCTAssertTrue(cancelled.settled)
        XCTAssertFalse(FileManager.default.fileExists(atPath: url.path))
        XCTAssertThrowsError(try permit.send { XCTFail("cancelled permit sent START") })
    }

    func testBadReadyOverflowTimeoutAndHeldOutputAreBounded() throws {
        let intent = PFAuthorizationIntent(request: try request(), executionID: UUID())
        for script in ["print('PF_AUTH_READY_V1 wrong')", "print('x'*20000)", "import time; time.sleep(3)"] {
            var persisted = false
            let start = connectorTime(), result = run(intent, source: script, timeout: 0.15) { _ in persisted = true }
            XCTAssertFalse(result.complete); XCTAssertTrue(result.settled); XCTAssertFalse(persisted)
            XCTAssertLessThan(connectorTime() - start, 1.5)
        }
        let prefix = "import sys,json,os,time,signal\nprint('PF_AUTH_READY_V1 '+sys.argv[1],flush=True)\njson.load(sys.stdin)\n"
        for tail in ["print('x'*20000)", "signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(3)",
                     "if os.fork()==0: time.sleep(0.8)"] {
            let start = connectorTime(), result = run(intent, source: prefix + tail, timeout: 0.25) { _ in }
            XCTAssertFalse(result.complete); XCTAssertTrue(result.settled)
            XCTAssertLessThan(connectorTime() - start, 1.5)
        }
    }
}
