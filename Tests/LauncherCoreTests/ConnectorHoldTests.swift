import XCTest
import Darwin
@testable import LauncherCore

final class ConnectorHoldTests: XCTestCase {
    private let config = ConnectorConfiguration()
    private func directory() throws -> URL {
        let url = URL(fileURLWithPath: NSTemporaryDirectory()).resolvingSymlinksInPath().appendingPathComponent("hold-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        return url
    }
    private func selector() -> ConnectorPFBinding {
        .init(requestID: String(repeating: "a", count: 32), expectedRevision: 0, planID: String(repeating: "b", count: 32),
              planSHA256: String(repeating: "c", count: 64), runtimeSHA256: String(repeating: "d", count: 64),
              serviceInstance: String(repeating: "e", count: 32), generation: String(repeating: "f", count: 32), receivedNotBefore: 100)
    }
    private func model(_ pipe: ControlFixture, directory: URL) -> ConnectorSupervisor {
        let config = config
        return .init(config: config, transport: pipe, snapshot: pipe.snapshot, configuration: { config },
                     probe: { _, _, _ in .init(samples: Dictionary(uniqueKeysWithValues: ConnectorConfiguration.hosts.map { ($0, config.expectedIPv4) }), services: ["desktop": .init(status: 200), "api": .init(status: 401)], settled: true) },
                     holdDirectory: directory)
    }
    private func wait(_ model: ConnectorSupervisor, _ hold: ConnectorHoldBinding,
                      _ condition: (ConnectorHoldReply) -> Bool) throws -> ConnectorHoldReply {
        let end = connectorTime() + 3
        while connectorTime() < end {
            let reply = model.handle(ConnectorHoldRequest(action: .status, hold: hold))
            if condition(reply) { return reply }; Thread.sleep(forTimeInterval: 0.005)
        }
        throw NSError(domain: "hold_fixture_timeout", code: 1)
    }

    func testStrictActionSchemasRejectNullSelectorsUnknownFieldsAndIdentityChanges() throws {
        let pipe = ControlFixture(config: config, lifetime: .init(device: 1, inode: 2))
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let binding = try XCTUnwrap(ConnectorTransactionBinding(hold: hold, pf: selector()))
        for action: ConnectorHoldAction in [.hold, .status, .cancel, .leave, .prepare, .commit] {
            let request = ConnectorHoldRequest(action: action, hold: hold, binding: [.prepare, .commit].contains(action) ? binding : nil)
            let original = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any])
            XCTAssertTrue(try JSONDecoder().decode(ConnectorHoldRequest.self, from: JSONSerialization.data(withJSONObject: original)).valid)
            for key in ["token", "samples", "services", "passed", "unexpected"] {
                var changed = original; changed[key] = true
                XCTAssertThrowsError(try JSONDecoder().decode(ConnectorHoldRequest.self, from: JSONSerialization.data(withJSONObject: changed)))
            }
            var changed = original; changed["binding"] = NSNull()
            XCTAssertThrowsError(try JSONDecoder().decode(ConnectorHoldRequest.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
        var held = ConnectorHold(binding: hold, effectiveEpoch: 1)
        held.drained(); XCTAssertTrue(held.attach(binding)); held.interrupt()
        XCTAssertFalse(held.attach(binding)); XCTAssertTrue(held.fenced)
    }

    func testV2SocketDispatchAndReusedCommandIdentityCannotCancelHold() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let request = ConnectorHoldRequest(action: .hold, hold: hold)
        var pair: [Int32] = [0, 0]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        let client = pair[0], server = pair[1]; defer { close(client) }
        try ConnectorSocket.prepare(client)
        let done = expectation(description: "v2 peer served")
        DispatchQueue.global().async {
            defer { close(server); done.fulfill() }
            do {
                try ConnectorIPC.servePeer(server, acceptedAt: connectorTime(), legacy: { model.handle($0) },
                                          coordinated: { model.handle($0) }, held: { model.handle($0) })
            } catch { XCTFail("v2 fixture dispatch failed") }
        }
        try ConnectorSocket.write(client, JSONEncoder().encode(request) + Data([10]), limit: 8192, deadline: connectorTime() + 1)
        let reply = try JSONDecoder().decode(ConnectorHoldReply.self,
            from: ConnectorSocket.read(client, limit: 131072, deadline: connectorTime() + 1))
        XCTAssertEqual(reply.commandID, request.commandID); XCTAssertEqual(reply.holdID, hold.id); XCTAssertTrue(reply.accepted)
        wait(for: [done], timeout: 2)
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        var changed = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any])
        changed["action"] = "cancel"
        let collision = try JSONDecoder().decode(ConnectorHoldRequest.self, from: JSONSerialization.data(withJSONObject: changed))
        XCTAssertEqual(model.handle(collision).reason, "command_identity_changed")
        XCTAssertFalse(pipe.operations.contains(.cancelHold))
    }

    func testHoldIsDurableBeforePrivateSendAndFencesBothOldAPIs() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        pipe.before = { command in
            if command.operation == .hold {
                XCTAssertEqual(try? ConnectorHoldStore(directory: directory).load()?.hold, hold)
                entered.signal(); _ = release.wait(timeout: .now() + 3)
            }
        }
        defer { release.signal() }
        XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .hold, hold: hold)).accepted)
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        XCTAssertTrue(model.handle("status").trafficEnabled) // Queued is not an invented blocked observation.
        _ = model.handle("check")
        let binding = try XCTUnwrap(ConnectorTransactionBinding(hold: hold, pf: selector()))
        XCTAssertFalse(model.handle(ConnectorControlRequest(action: .prepare, binding: binding)).accepted)
        XCTAssertFalse(pipe.operations.contains(.beginProbe))
        release.signal()
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        XCTAssertTrue(lifetime.identity == pipe.snapshot.gatewayLifetime)
    }

    func testPreparePersistsAttachmentBeforeProbeAndRequiresSeparateCommit() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let binding = try XCTUnwrap(ConnectorTransactionBinding(hold: hold, pf: selector()))
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        pipe.before = { command in
            if command.operation == .attachTransaction {
                XCTAssertEqual(try? ConnectorHoldStore(directory: directory).load()?.attachment, binding)
            }
        }
        XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .prepare, hold: hold, binding: binding)).accepted)
        let prepared = try wait(model, hold) { $0.operation == "prepared" && !$0.localWorkPending }
        XCTAssertFalse(prepared.snapshot.trafficEnabled); XCTAssertFalse(pipe.operations.contains(.commitTransaction))
        XCTAssertFalse(model.handle(ConnectorControlRequest(action: .commit, binding: binding)).accepted)
        XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .commit, hold: hold, binding: binding)).accepted)
        let committed = try wait(model, hold) { $0.operation == "committed" && !$0.localWorkPending }
        XCTAssertFalse(committed.snapshot.launchAuthorized); XCTAssertFalse(StrictProtection.verified)
    }

    func testUnsupportedGatewayCannotCreateHoldOrWriteJournal() throws {
        for version: Int? in [nil, 1] {
            let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
            let pipe = ControlFixture(config: config, lifetime: lifetime.identity)
            let identity = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
            pipe.advertiseTransactionProtocol(version)
            XCTAssertNil(ConnectorHoldBinding(snapshot: pipe.snapshot))
            let model = model(pipe, directory: directory)
            let result = model.handle(ConnectorHoldRequest(action: .hold, hold: identity))
            XCTAssertFalse(result.accepted); XCTAssertFalse(result.localWorkPending)
            XCTAssertEqual(result.reason, "hold_not_available")
            XCTAssertTrue(pipe.operations.isEmpty)
            XCTAssertNil(try ConnectorHoldStore(directory: directory).load())
        }
    }

    func testCapabilityChangeBeforeAttachmentPreservesJournalAndAllowsCleanup() throws {
        for version: Int? in [nil, 1] {
            let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
            let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
            let identity = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
            let binding = try XCTUnwrap(ConnectorTransactionBinding(hold: identity, pf: selector()))
            // A subsequent Gateway observation changes the capability, not the operation identity.
            pipe.before = { command in
                if command.operation == .hold { pipe.advertiseTransactionProtocol(version) }
            }
            XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .hold, hold: identity)).accepted)
            _ = try wait(model, identity) { $0.operation == "held" && !$0.localWorkPending }
            let store = try ConnectorHoldStore(directory: directory), original = try XCTUnwrap(store.load())
            XCTAssertNil(original.attachment)
            let result = model.handle(ConnectorHoldRequest(action: .prepare, hold: identity, binding: binding))
            XCTAssertFalse(result.accepted); XCTAssertFalse(result.localWorkPending)
            XCTAssertEqual(result.reason, "transaction_protocol_unsupported")
            XCTAssertEqual(try store.load(), original)
            XCTAssertFalse(pipe.operations.contains(.attachTransaction))
            XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe))
            pipe.before = nil
            XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .status, hold: identity)).accepted)
            XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .cancel, hold: identity)).accepted)
            _ = try wait(model, identity) { $0.operation == "cancelled" && !$0.localWorkPending }
            XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .leave, hold: identity)).accepted)
            _ = try wait(model, identity) { $0.operation == "released" && !$0.localWorkPending }
            XCTAssertTrue(try XCTUnwrap(store.load()).released)
        }
    }

    func testInvalidateBeforeHoldArrivesUsesExitProofWithoutChangingOriginalEpoch() throws {
        let directory = try directory()
        var lifetime: ConnectorGatewayLifetime? = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: try XCTUnwrap(lifetime?.identity)), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        pipe.before = { command in
            if command.operation == .hold { entered.signal(); _ = release.wait(timeout: .now() + 3) }
        }
        defer { release.signal() }
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        _ = model.handle("block"); release.signal()
        _ = try wait(model, hold) { $0.operation == "interrupted" && !$0.localWorkPending }
        XCTAssertNil(pipe.snapshot.hold)
        _ = model.handle(ConnectorHoldRequest(action: .leave, hold: hold))
        _ = try wait(model, hold) { $0.reason == "old_gateway_exit_unconfirmed" && !$0.localWorkPending }
        XCTAssertFalse(pipe.isRunning)
        XCTAssertEqual(try ConnectorHoldStore(directory: directory).load()?.hold, hold)
        lifetime = nil
        _ = model.handle(ConnectorHoldRequest(action: .leave, hold: hold))
        _ = try wait(model, hold) { $0.operation == "released" && !$0.localWorkPending }
        XCTAssertEqual(pipe.operations.filter { $0 == .hold }.count, 1)
        XCTAssertFalse(pipe.operations.contains(.beginProbe))
    }

    func testCancelBeforeHoldACKCannotLoseFenceOrLeaveWhileWorkerRuns() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), lock = NSLock()
        var first = true
        pipe.before = { command in
            if command.operation == .hold {
                lock.lock(); let shouldWait = first; first = false; lock.unlock()
                if shouldWait { entered.signal(); _ = release.wait(timeout: .now() + 3) }
            }
        }
        defer { release.signal() }
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        _ = model.handle(ConnectorHoldRequest(action: .cancel, hold: hold))
        XCTAssertFalse(model.handle(ConnectorHoldRequest(action: .leave, hold: hold)).accepted)
        release.signal()
        _ = try wait(model, hold) { $0.operation == "cancelled" && !$0.localWorkPending }
        XCTAssertFalse(try XCTUnwrap(ConnectorHoldStore(directory: directory).load()).released)
        XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe)); XCTAssertFalse(pipe.operations.contains(.allow))
    }

    func testCancellationAndLostLeaveACKRetainBarrierUntilExplicitCompletion() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        _ = model.handle(ConnectorHoldRequest(action: .cancel, hold: hold))
        _ = try wait(model, hold) { $0.operation == "cancelled" && !$0.localWorkPending }
        pipe.drop = .leaveHold
        _ = model.handle(ConnectorHoldRequest(action: .leave, hold: hold))
        _ = try wait(model, hold) { $0.operation == "unknown" && !$0.localWorkPending }
        model.observe(pipe.snapshot)
        XCTAssertFalse(try XCTUnwrap(ConnectorHoldStore(directory: directory).load()).released)
        _ = model.handle("check"); XCTAssertFalse(pipe.operations.contains(.beginProbe))
        XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .leave, hold: hold)).accepted)
        _ = try wait(model, hold) { $0.operation == "released" && !$0.localWorkPending }
        XCTAssertTrue(try XCTUnwrap(ConnectorHoldStore(directory: directory).load()).released)
        XCTAssertFalse(model.handle(ConnectorHoldRequest(action: .prepare, hold: hold,
            binding: try XCTUnwrap(ConnectorTransactionBinding(hold: hold, pf: selector())))).accepted)
    }

    func testRestartDoesNotTouchTransportAndOrphanLeaveRequiresActualLifetimeRelease() throws {
        let directory = try directory()
        var lifetime: ConnectorGatewayLifetime? = try ConnectorGatewayLifetime(directory: directory)
        let identity = try XCTUnwrap(lifetime?.identity), pipe = ControlFixture(config: config, lifetime: identity)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot)), store = try ConnectorHoldStore(directory: directory)
        try store.save(.init(hold: hold, lifetime: identity), replacing: nil)
        let model = model(pipe, directory: directory); try model.restoreHoldBarrierForTesting()
        _ = model.handle("check"); XCTAssertTrue(pipe.operations.isEmpty)
        _ = model.handle(ConnectorHoldRequest(action: .leave, hold: hold))
        _ = try wait(model, hold) { $0.reason == "old_gateway_exit_unconfirmed" && !$0.localWorkPending }
        XCTAssertFalse(try XCTUnwrap(store.load()).released)
        lifetime = nil
        _ = model.handle(ConnectorHoldRequest(action: .leave, hold: hold))
        _ = try wait(model, hold) { $0.reason == "orphan_released_restart_required" && !$0.localWorkPending }
        XCTAssertTrue(try XCTUnwrap(store.load()).released)
        _ = model.handle("check"); XCTAssertTrue(pipe.operations.isEmpty)
    }

    func testCorruptJournalDuringAttachmentLatchesUnknownAndNeverDispatchesAttach() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        try Data("{}".utf8).write(to: directory.appendingPathComponent("connector-hold.json"))
        _ = model.handle(ConnectorHoldRequest(action: .prepare, hold: hold,
            binding: try XCTUnwrap(ConnectorTransactionBinding(hold: hold, pf: selector()))))
        _ = try wait(model, hold) { $0.reason == "hold_journal_unknown" && !$0.localWorkPending }
        XCTAssertFalse(pipe.operations.contains(.attachTransaction)); XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe))
        XCTAssertFalse(model.handle(ConnectorHoldRequest(action: .leave, hold: hold)).accepted)
        _ = model.handle("check"); XCTAssertFalse(pipe.operations.contains(.beginProbe))
    }

    func testGatewayExitsWhileHeldWithoutTerminalSnapshotCanStillBeExplicitlyReleased() throws {
        let directory = try directory()
        var lifetime: ConnectorGatewayLifetime? = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: try XCTUnwrap(lifetime?.identity)), model = model(pipe, directory: directory)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        _ = model.handle(ConnectorHoldRequest(action: .hold, hold: hold))
        _ = try wait(model, hold) { $0.operation == "held" && !$0.localWorkPending }
        pipe.terminate(); lifetime = nil
        XCTAssertTrue(model.handle(ConnectorHoldRequest(action: .leave, hold: hold)).accepted)
        _ = try wait(model, hold) { $0.operation == "released" && !$0.localWorkPending }
        XCTAssertTrue(try XCTUnwrap(ConnectorHoldStore(directory: directory).load()).released)
    }

    func testWriteAfterReplaceFailureStillRestoresAnUnreleasedBarrier() throws {
        let directory = try directory(), lifetime = try ConnectorGatewayLifetime(directory: directory)
        let pipe = ControlFixture(config: config, lifetime: lifetime.identity)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot))
        let record = ConnectorHoldIntent(hold: hold, lifetime: lifetime.identity)
        let store = try ConnectorHoldStore(directory: directory, afterReplace: { throw NSError(domain: "fsync_fixture", code: 1) })
        XCTAssertThrowsError(try store.save(record, replacing: nil))
        XCTAssertEqual(try ConnectorHoldStore(directory: directory).load(), record)
        let model = model(pipe, directory: directory); try model.restoreHoldBarrierForTesting()
        _ = model.handle("check"); XCTAssertTrue(pipe.operations.isEmpty)
        XCTAssertEqual(model.handle(ConnectorHoldRequest(action: .status, hold: hold)).operation, "interrupted")
    }

    func testStoreCASAndUnsafeFilesAndChangedLifetimeInodeAreRejected() throws {
        let directory = try directory()
        var lifetime: ConnectorGatewayLifetime? = try ConnectorGatewayLifetime(directory: directory)
        let identity = try XCTUnwrap(lifetime?.identity), pipe = ControlFixture(config: config, lifetime: identity)
        let hold = try XCTUnwrap(ConnectorHoldBinding(snapshot: pipe.snapshot)), store = try ConnectorHoldStore(directory: directory)
        let initial = ConnectorHoldIntent(hold: hold, lifetime: identity)
        try store.save(initial, replacing: nil)
        XCTAssertThrowsError(try store.save(initial, replacing: nil))
        let file = directory.appendingPathComponent("connector-hold.json")
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: file.path)
        XCTAssertThrowsError(try store.load())
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
        let archived = directory.appendingPathComponent("record-archived")
        try FileManager.default.moveItem(at: file, to: archived)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: archived)
        XCTAssertThrowsError(try store.load())
        lifetime = nil
        let lock = directory.appendingPathComponent("connector-gateway.lifetime")
        try FileManager.default.moveItem(at: lock, to: directory.appendingPathComponent("lock-archived"))
        let replacement = try ConnectorGatewayLifetime(directory: directory)
        XCTAssertNotEqual(replacement.identity, identity)
        XCTAssertThrowsError(try ConnectorGatewayLifetime(directory: directory, expected: identity))
    }
}
