import XCTest
import Darwin
@testable import LauncherCore

final class ControlFixture: ConnectorCommandTransport, @unchecked Sendable {
    private let lock = NSLock()
    private var value: ConnectorSnapshot
    private var calls: [ConnectorGatewayCommand] = []
    private var alive = true
    var before: ((ConnectorGatewayCommand) -> Void)?
    var after: ((ConnectorGatewayCommand) -> Void)?
    var drop: ConnectorOperation?
    init(config: ConnectorConfiguration, lifetime: ConnectorLifetimeIdentity? = nil) {
        value = ConnectorSnapshot(); value.state = "allowed"; value.reason = "manual_check_passed"
        value.port = 12345; value.transactionProtocol = 2; value.configDigest = config.digest
        value.gatewayLifetime = lifetime; value.holdProtocol = lifetime == nil ? nil : 1
    }
    var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return alive }
    var snapshot: ConnectorSnapshot { lock.lock(); defer { lock.unlock() }; return value }
    func advertiseTransactionProtocol(_ version: Int?) {
        lock.lock(); defer { lock.unlock() }
        value.transactionProtocol = version; value.sampledAt = Date()
    }
    var operations: [ConnectorOperation] { lock.lock(); defer { lock.unlock() }; return calls.map(\.operation) }
    func terminate() { lock.lock(); alive = false; lock.unlock() }
    func send(_ command: ConnectorGatewayCommand) -> Bool { request(command) != nil }
    func request(_ command: ConnectorGatewayCommand) -> ConnectorGatewayReply? {
        lock.lock(); calls.append(command); lock.unlock()
        before?(command)
        lock.lock()
        var accepted = true
        let phase = value.transaction?.phase
        func set(_ phase: String) {
            value.transaction = .init(id: command.transaction!.id, phase: phase, reason: "fixture_" + phase)
        }
        switch command.operation {
        case .hold:
            if value.hold == nil || value.hold?.phase == "released" {
                if command.hold?.initialEpoch == value.epoch {
                    value.epoch += 1; value.state = "blocked"
                    value.hold = .init(id: command.hold!.id, phase: "held")
                } else { accepted = false }
            } else { accepted = value.hold?.id == command.hold?.id && value.hold?.phase == "held" }
        case .attachTransaction:
            if value.hold?.id == command.hold?.id, value.hold?.phase == "held" {
                value.hold = .init(id: command.hold!.id, phase: "attached"); set("reserved")
            } else { accepted = false }
        case .cancelHold:
            if value.hold?.id == command.hold?.id {
                value.epoch += 1; value.state = "blocked"; value.hold = .init(id: command.hold!.id, phase: "cancelled")
                if let transaction = value.transaction { value.transaction = .init(id: transaction.id, phase: "cancelled", reason: "fixture") }
            } else { accepted = false }
        case .leaveHold:
            if value.hold?.id == command.hold?.id, ["cancelled", "interrupted", "released"].contains(value.hold?.phase ?? "") {
                value.hold = .init(id: command.hold!.id, phase: "released")
                if let transaction = value.transaction { value.transaction = .init(id: transaction.id, phase: "released", reason: "fixture") }
            } else { accepted = false }
        case .reserveTransaction:
            if value.transaction == nil || (phase == "released" && value.transaction?.id != command.transaction?.id) {
                value.epoch += 1; value.state = "blocked"; value.reason = "transaction_reserving"; set("reserved")
            } else { accepted = value.transaction?.id == command.transaction?.id }
        case .beginTransactionProbe: if phase == "reserved" { set("probing") } else { accepted = false }
        case .prepareTransaction: if phase == "probing" { set("prepared") } else { accepted = false }
        case .commitTransaction:
            if phase == "prepared" { set("committed"); value.state = "allowed"; value.reason = "transaction_committed" }
            else { accepted = phase == "committed" }
        case .cancelTransaction:
            if phase != "released", value.transaction?.id == command.transaction?.id {
                value.epoch += 1; value.state = "blocked"; set("cancelled")
            } else { accepted = false }
        case .leaveCoordinatedMode:
            if ["cancelled", "interrupted", "expired"].contains(phase ?? "") { value.epoch += 1; set("released") }
            else { accepted = phase == "released" }
        case .block:
            value.epoch += 1; value.state = "blocked"; value.reason = "manual_block"
            if let held = value.hold { value.hold = .init(id: held.id, phase: "interrupted") }
            if let transaction = value.transaction, transaction.phase != "released" {
                value.transaction = .init(id: transaction.id, phase: "interrupted", reason: "manual_block")
            }
        case .beginProbe: value.epoch += 1; value.state = "checking"
        case .allow, .renew: value.state = "allowed"
        default: break
        }
        value.sampledAt = Date()
        let response = ConnectorGatewayReply(commandID: command.id, accepted: accepted, snapshot: value)
        let dropped = drop == command.operation
        if dropped { drop = nil }
        lock.unlock()
        after?(command)
        return dropped ? nil : response
    }
}

private final class ControlConfiguration: @unchecked Sendable {
    private let lock = NSLock()
    private var value: ConnectorConfiguration?
    private var counter = 0
    init(_ value: ConnectorConfiguration) { self.value = value }
    func read() -> ConnectorConfiguration? { lock.lock(); defer { lock.unlock() }; return value }
    func clear() { lock.lock(); value = nil; lock.unlock() }
    func next() -> Int { lock.lock(); defer { lock.unlock() }; counter += 1; return counter }
}

final class ConnectorControlTests: XCTestCase {
    private let config = ConnectorConfiguration()
    private func binding(_ snapshot: ConnectorSnapshot) throws -> ConnectorTransactionBinding {
        let pf = ConnectorPFBinding(requestID: String(repeating: "a", count: 32), expectedRevision: 0,
            planID: String(repeating: "b", count: 32), planSHA256: String(repeating: "c", count: 64),
            runtimeSHA256: String(repeating: "d", count: 64), serviceInstance: String(repeating: "e", count: 32),
            generation: String(repeating: "f", count: 32), receivedNotBefore: Date().timeIntervalSince1970)
        return try XCTUnwrap(ConnectorTransactionBinding(snapshot: snapshot, pf: pf))
    }
    private func samples() -> ConnectorProbeResult {
        .init(samples: Dictionary(uniqueKeysWithValues: ConnectorConfiguration.hosts.map { ($0, config.expectedIPv4) }), services: ["desktop": .init(status: 200), "api": .init(status: 401)], settled: true)
    }
    private func awaitSignal(_ semaphore: DispatchSemaphore) async {
        await withCheckedContinuation { continuation in
            DispatchQueue.global().async { _ = semaphore.wait(timeout: .now() + 3); continuation.resume() }
        }
    }
    private func supervisor(_ pipe: ControlFixture,
                            probe: (@Sendable (UInt16, String, ConnectorProbeProfile) async -> ConnectorProbeResult)? = nil) -> ConnectorSupervisor {
        let config = config, result = samples()
        return ConnectorSupervisor(config: config, transport: pipe, snapshot: pipe.snapshot,
                                   configuration: { config }, probe: probe ?? { _, _, _ in result })
    }
    private func wait(_ model: ConnectorSupervisor, _ binding: ConnectorTransactionBinding,
                      until condition: (ConnectorControlReply) -> Bool) throws -> ConnectorControlReply {
        let deadline = connectorTime() + 3
        while connectorTime() < deadline {
            let result = model.handle(.init(action: .status, binding: binding))
            if condition(result) { return result }
            Thread.sleep(forTimeInterval: 0.005)
        }
        throw NSError(domain: "fixture_timeout", code: 1)
    }

    func testStrictEnvelopeRejectsPublicProofsUnknownFieldsAndInvalidVersions() throws {
        let request = ConnectorControlRequest(action: .prepare, binding: try binding(ControlFixture(config: config).snapshot))
        let data = try JSONEncoder().encode(request)
        XCTAssertEqual(try JSONDecoder().decode(ConnectorControlRequest.self, from: data).binding, request.binding)
        let original = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
        for (key, value): (String, Any) in [("version", 2), ("version", true), ("samples", [:]), ("services", [:]), ("token", "secret"), ("action", "allow")] {
            var changed = original; changed[key] = value
            XCTAssertThrowsError(try JSONDecoder().decode(ConnectorControlRequest.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
        for nested in [false, true] {
            var changed = original, transaction = original["binding"] as! [String: Any]
            if nested {
                var pf = transaction["pf"] as! [String: Any]; pf["passed"] = true; transaction["pf"] = pf
            } else { transaction["samples"] = [:] }
            changed["binding"] = transaction
            XCTAssertThrowsError(try JSONDecoder().decode(ConnectorControlRequest.self, from: JSONSerialization.data(withJSONObject: changed)))
        }
    }

    func testUnsupportedGatewayCannotQueueNewTransaction() throws {
        for version: Int? in [nil, 1] {
            let pipe = ControlFixture(config: config), binding = try binding(pipe.snapshot)
            pipe.advertiseTransactionProtocol(version)
            XCTAssertNil(ConnectorTransactionBinding(snapshot: pipe.snapshot, pf: binding.pf))
            let model = supervisor(pipe)
            let reply = model.handle(ConnectorControlRequest(action: .prepare, binding: binding))
            XCTAssertFalse(reply.accepted); XCTAssertFalse(reply.localWorkPending)
            XCTAssertEqual(reply.reason, "prepare_not_available")
            XCTAssertTrue(pipe.operations.isEmpty)
        }
    }

    func testQueuedPrepareDoesNotInventBlockAndEarlyCancelFencesLateReserve() throws {
        let pipe = ControlFixture(config: config), firstEntered = DispatchSemaphore(value: 0), releaseFirst = DispatchSemaphore(value: 0)
        let lock = NSLock(); var first = true
        pipe.before = { command in
            if command.operation == .reserveTransaction {
                lock.lock(); let hold = first; first = false; lock.unlock()
                if hold { firstEntered.signal(); _ = releaseFirst.wait(timeout: .now() + 3) }
            }
        }
        defer { releaseFirst.signal() }
        let model = supervisor(pipe), binding = try binding(pipe.snapshot)
        let queued = model.handle(.init(action: .prepare, binding: binding))
        XCTAssertEqual(queued.operation, "queued"); XCTAssertTrue(queued.snapshot.trafficEnabled)
        XCTAssertEqual(firstEntered.wait(timeout: .now() + 1), .success)
        let before = connectorTime()
        XCTAssertTrue(model.handle(.init(action: .cancel, binding: binding)).accepted)
        XCTAssertLessThan(connectorTime() - before, 0.2)
        _ = try wait(model, binding) { $0.operation == "cancelled" }
        for _ in 0..<10 { _ = model.handle(.init(action: .cancel, binding: binding)); _ = model.handle("check") }
        XCTAssertEqual(pipe.operations.filter { $0 == .cancelTransaction }.count, 1)
        XCTAssertFalse(model.handle(.init(action: .leave, binding: binding)).accepted)
        releaseFirst.signal()
        let settled = try wait(model, binding) { !$0.localWorkPending }
        XCTAssertEqual(settled.operation, "cancelled"); XCTAssertFalse(settled.snapshot.trafficEnabled)
        XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe)); XCTAssertFalse(pipe.operations.contains(.beginProbe))
        XCTAssertTrue(model.handle(.init(action: .leave, binding: binding)).accepted)
        _ = try wait(model, binding) { $0.operation == "released" && !$0.localWorkPending }
        _ = model.handle("check")
        _ = try wait(model, binding) { !$0.localWorkPending && $0.snapshot.trafficEnabled }
        XCTAssertTrue(pipe.operations.contains(.allow))
    }

    func testPrepareNeverAllowsAndCommitNeedsExplicitRequest() throws {
        let pipe = ControlFixture(config: config), model = supervisor(pipe), binding = try binding(pipe.snapshot)
        let initial = ConnectorControlRequest(action: .prepare, binding: binding)
        XCTAssertTrue(model.handle(initial).accepted)
        let prepared = try wait(model, binding) { $0.operation == "prepared" && !$0.localWorkPending }
        XCTAssertFalse(prepared.snapshot.trafficEnabled)
        _ = model.handle("check"); XCTAssertTrue(model.handle(initial).accepted)
        XCTAssertEqual(pipe.operations.filter { $0 == .beginTransactionProbe }.count, 1)
        XCTAssertFalse(pipe.operations.contains(.allow)); XCTAssertFalse(pipe.operations.contains(.commitTransaction))
        var changed = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(initial)) as? [String: Any])
        changed["action"] = "commit"
        let collision = try JSONDecoder().decode(ConnectorControlRequest.self, from: JSONSerialization.data(withJSONObject: changed))
        XCTAssertEqual(model.handle(collision).reason, "command_identity_changed")
        XCTAssertTrue(model.handle(.init(action: .commit, binding: binding)).accepted)
        let committed = try wait(model, binding) { $0.operation == "committed" && !$0.localWorkPending }
        XCTAssertTrue(committed.snapshot.trafficEnabled) // Transport fixture, not real PF approval.
        XCTAssertFalse(committed.snapshot.launchAuthorized); XCTAssertFalse(StrictProtection.verified)
        model.observe(prepared.snapshot)
        XCTAssertTrue(model.handle("status").trafficEnabled)
    }

    func testPriorReleasedSnapshotCannotSwallowCancellationOfNewQueuedTransaction() throws {
        let pipe = ControlFixture(config: config), old = try binding(pipe.snapshot)
        for operation: ConnectorOperation in [.reserveTransaction, .cancelTransaction, .leaveCoordinatedMode] {
            _ = pipe.request(.init(operation: operation, transaction: old))
        }
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        let lock = NSLock(); var first = true
        pipe.before = { command in
            if command.operation == .reserveTransaction {
                lock.lock(); let hold = first; first = false; lock.unlock()
                if hold { entered.signal(); _ = release.wait(timeout: .now() + 3) }
            }
        }
        defer { release.signal() }
        let model = supervisor(pipe), next = try binding(pipe.snapshot)
        XCTAssertTrue(model.handle(.init(action: .prepare, binding: next)).accepted)
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        XCTAssertEqual(model.handle(.init(action: .cancel, binding: next)).reason, "cancel_queued")
        let cancelled = try wait(model, next) { $0.operation == "cancelled" }
        XCTAssertEqual(cancelled.snapshot.transaction?.id, next.id)
        release.signal()
        _ = try wait(model, next) { !$0.localWorkPending }
        XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe))
    }

    func testMissingReserveACKCancelsWithoutStartingAnotherProbe() throws {
        let pipe = ControlFixture(config: config); pipe.drop = .reserveTransaction
        let model = supervisor(pipe), binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        let stopped = try wait(model, binding) { $0.operation == "cancelled" && !$0.localWorkPending }
        XCTAssertEqual(stopped.reason, "reserve_unconfirmed"); XCTAssertFalse(stopped.snapshot.trafficEnabled)
        XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe))
        _ = model.handle(.init(action: .prepare, binding: binding))
        XCTAssertFalse(pipe.operations.contains(.beginTransactionProbe))
    }

    func testCancelledLateProbeCannotPrepareOrReleaseNewCancelWorker() throws {
        let pipe = ControlFixture(config: config), probeEntered = DispatchSemaphore(value: 0), releaseProbe = DispatchSemaphore(value: 0)
        let cancelEntered = DispatchSemaphore(value: 0), releaseCancel = DispatchSemaphore(value: 0)
        let result = samples()
        let model = supervisor(pipe) { _, _, _ in
            probeEntered.signal(); await self.awaitSignal(releaseProbe); return result
        }
        pipe.before = { command in
            if command.operation == .cancelTransaction { cancelEntered.signal(); _ = releaseCancel.wait(timeout: .now() + 3) }
        }
        defer { releaseProbe.signal(); releaseCancel.signal() }
        let binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        XCTAssertEqual(probeEntered.wait(timeout: .now() + 1), .success)
        _ = model.handle(.init(action: .cancel, binding: binding))
        XCTAssertEqual(cancelEntered.wait(timeout: .now() + 1), .success)
        releaseProbe.signal(); Thread.sleep(forTimeInterval: 0.05)
        let waiting = model.handle(.init(action: .status, binding: binding))
        XCTAssertEqual(waiting.operation, "cancelling"); XCTAssertTrue(waiting.localWorkPending)
        _ = model.handle(.init(action: .cancel, binding: binding))
        XCTAssertEqual(pipe.operations.filter { $0 == .cancelTransaction }.count, 1)
        releaseCancel.signal()
        _ = try wait(model, binding) { $0.operation == "cancelled" && !$0.localWorkPending }
        XCTAssertFalse(pipe.operations.contains(.prepareTransaction)); XCTAssertFalse(pipe.operations.contains(.commitTransaction))
    }

    func testMismatchedProbeAutomaticallyCancelsAndNeverCommits() throws {
        let pipe = ControlFixture(config: config)
        let model = supervisor(pipe) { _, _, _ in .init(samples: ["claude.ai": "192.0.2.9"], settled: true) }
        let binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        let stopped = try wait(model, binding) { $0.operation == "cancelled" && !$0.localWorkPending }
        XCTAssertEqual(stopped.reason, "probe_failed")
        XCTAssertFalse(pipe.operations.contains(.prepareTransaction)); XCTAssertFalse(pipe.operations.contains(.commitTransaction))
    }

    func testMissingOrFailedServiceCancelsPreparationAfterMatchingTraces() throws {
        for statuses in [[:], ["desktop": 200], ["desktop": 200, "api": 429],
                         ["desktop": 500, "api": 401], ["desktop": 200, "api": 401, "other": 200]] {
            let pipe = ControlFixture(config: config), samples = samples().samples
            let model = supervisor(pipe) { _, _, profile in
                XCTAssertEqual(profile, .coordinatedRecovery)
                return .init(samples: samples, services: statuses.mapValues { .init(status: $0) }, settled: true)
            }
            let binding = try binding(pipe.snapshot)
            _ = model.handle(.init(action: .prepare, binding: binding))
            let stopped = try wait(model, binding) { $0.operation == "cancelled" && !$0.localWorkPending }
            XCTAssertEqual(stopped.reason, "service_failed")
            XCTAssertFalse(pipe.operations.contains(.prepareTransaction)); XCTAssertFalse(stopped.snapshot.trafficEnabled)
        }
    }

    func testLatePreparedAckCannotUndoManualBlock() throws {
        let pipe = ControlFixture(config: config), entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0)
        pipe.after = { command in
            if command.operation == .prepareTransaction { entered.signal(); _ = release.wait(timeout: .now() + 3) }
        }
        defer { release.signal() }
        let model = supervisor(pipe), binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        _ = model.handle("block")
        release.signal()
        let stopped = try wait(model, binding) { !$0.localWorkPending }
        XCTAssertEqual(stopped.operation, "interrupted"); XCTAssertFalse(stopped.snapshot.trafficEnabled)
        XCTAssertFalse(model.handle(.init(action: .commit, binding: binding)).accepted)
        XCTAssertFalse(pipe.operations.contains(.commitTransaction))
    }

    func testConfigurationChangeRejectsCommitButAllowsOriginalScopeCleanup() throws {
        let pipe = ControlFixture(config: config), settings = ControlConfiguration(config), result = samples()
        let model = ConnectorSupervisor(config: config, transport: pipe, snapshot: pipe.snapshot,
            configuration: { settings.read() }, probe: { _, _, _ in result })
        let binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        _ = try wait(model, binding) { $0.operation == "prepared" && !$0.localWorkPending }
        settings.clear()
        XCTAssertFalse(model.handle(.init(action: .commit, binding: binding)).accepted)
        XCTAssertTrue(model.handle(.init(action: .cancel, binding: binding)).accepted)
        _ = try wait(model, binding) { $0.operation == "cancelled" && !$0.localWorkPending }
        XCTAssertTrue(model.handle(.init(action: .leave, binding: binding)).accepted)
        _ = try wait(model, binding) { $0.operation == "released" && !$0.localWorkPending }
        _ = model.handle("check"); XCTAssertFalse(pipe.operations.contains(.beginProbe))
    }

    func testOldLegacyProbeCannotAllowAfterCoordinatedReservation() throws {
        let pipe = ControlFixture(config: config), counter = ControlConfiguration(config)
        let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), result = samples()
        let model = supervisor(pipe) { _, _, _ in
            if counter.next() == 1 { entered.signal(); await self.awaitSignal(release) }
            return result
        }
        defer { release.signal() }
        _ = model.handle("check")
        XCTAssertEqual(entered.wait(timeout: .now() + 1), .success)
        model.observe(pipe.snapshot)
        let binding = try binding(model.handle("status"))
        XCTAssertTrue(model.handle(.init(action: .prepare, binding: binding)).accepted)
        _ = try wait(model, binding) { $0.operation == "prepared" }
        XCTAssertFalse(model.handle(.init(action: .commit, binding: binding)).accepted)
        _ = model.handle(.init(action: .cancel, binding: binding))
        _ = try wait(model, binding) { $0.operation == "cancelled" }
        XCTAssertFalse(model.handle(.init(action: .leave, binding: binding)).accepted)
        release.signal(); _ = try wait(model, binding) { !$0.localWorkPending }
        XCTAssertFalse(pipe.operations.contains(.allow)); XCTAssertFalse(pipe.operations.contains(.renew))
        XCTAssertFalse(pipe.operations.contains(.revokeProbe))
    }

    func testUnsettledProbeStopsGatewayAndPreventsMoreWork() throws {
        let pipe = ControlFixture(config: config)
        let model = supervisor(pipe) { _, _, _ in .init(samples: [:], settled: false) }
        let binding = try binding(pipe.snapshot)
        _ = model.handle(.init(action: .prepare, binding: binding))
        let result = try wait(model, binding) { !$0.localWorkPending }
        XCTAssertFalse(pipe.isRunning); XCTAssertEqual(result.snapshot.state, "stopped")
        XCTAssertEqual(result.operation, "interrupted")
        XCTAssertFalse(model.handle(.init(action: .commit, binding: binding)).accepted)
        _ = model.handle("check"); XCTAssertFalse(pipe.operations.contains(.beginProbe))
    }

    func testCLIRequestReaderBoundsBeforeDecodeAndRejectsSymlinks() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("connector-request-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let file = directory.appendingPathComponent("request.json"), link = directory.appendingPathComponent("link.json")
        let request = ConnectorControlRequest(action: .status, binding: try binding(ControlFixture(config: config).snapshot))
        try JSONEncoder().encode(request).write(to: file)
        XCTAssertEqual(try ConnectorIPC.loadRequest(from: file.path).binding, request.binding)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: file)
        XCTAssertThrowsError(try ConnectorIPC.loadRequest(from: link.path))
        XCTAssertThrowsError(try ConnectorIPC.loadRequest(from: directory.path))
        try Data(repeating: 65, count: 8193).write(to: file)
        XCTAssertThrowsError(try ConnectorIPC.loadRequest(from: file.path))
    }

    private func sockets() throws -> (Int32, Int32) {
        var pair: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else { throw NSError(domain: "socketpair", code: 1) }
        try ConnectorSocket.prepare(pair[0]); try ConnectorSocket.prepare(pair[1]); return (pair[0], pair[1])
    }
    func testSocketTrickleCannotResetTotalDeadline() throws {
        let (reader, writer) = try sockets(); defer { close(reader) }
        let done = expectation(description: "trickle ended")
        DispatchQueue.global().async {
            defer { close(writer); done.fulfill() }
            for _ in 0..<20 {
                if (try? ConnectorSocket.write(writer, Data([65]), limit: 1, deadline: connectorTime() + 0.1)) == nil { break }
                Thread.sleep(forTimeInterval: 0.02)
            }
        }
        let started = connectorTime()
        XCTAssertThrowsError(try ConnectorSocket.read(reader, limit: 8192, deadline: started + 0.12))
        XCTAssertLessThan(connectorTime() - started, 0.4)
        wait(for: [done], timeout: 2)
    }
    func testSocketFramesRejectOverflowAndTrailingCommands() throws {
        for data in [Data(repeating: 65, count: 8193), Data("status\ncheck\n".utf8)] {
            let (reader, writer) = try sockets(); defer { close(reader) }
            let done = expectation(description: "frame sent")
            DispatchQueue.global().async {
                defer { close(writer); done.fulfill() }
                do { try ConnectorSocket.write(writer, data, limit: 9000, deadline: connectorTime() + 1) }
                catch { XCTFail("fixture writer: \(error)") }
            }
            XCTAssertThrowsError(try ConnectorSocket.read(reader, limit: 8192, deadline: connectorTime() + 1))
            wait(for: [done], timeout: 2)
        }
    }
    func testActualSocketPeerDispatchesTypedAndLegacyWithoutNetworkOrRoot() throws {
        let pipe = ControlFixture(config: config), binding = try binding(pipe.snapshot)
        let request = ConnectorControlRequest(action: .status, binding: binding)
        for typed in [true, false] {
            let (client, server) = try sockets(); defer { close(client) }
            let done = expectation(description: "peer served")
            DispatchQueue.global().async {
                defer { close(server); done.fulfill() }
                do {
                    try ConnectorIPC.servePeer(server, acceptedAt: connectorTime(), legacy: { _ in pipe.snapshot }, coordinated: { value in
                        .init(version: 1, commandID: value.commandID, transactionID: value.binding.id, accepted: true,
                              reason: "fixture", operation: "none", localWorkPending: false, snapshot: pipe.snapshot)
                    })
                } catch { XCTFail("peer failed: \(error)") }
            }
            let data = typed ? try JSONEncoder().encode(request) : Data("status".utf8)
            try ConnectorSocket.write(client, data + Data([10]), limit: 8192, deadline: connectorTime() + 1)
            let response = try ConnectorSocket.read(client, limit: 131072, deadline: connectorTime() + 1)
            if typed {
                let value = try JSONDecoder().decode(ConnectorControlReply.self, from: response)
                XCTAssertEqual(value.commandID, request.commandID); XCTAssertEqual(value.transactionID, binding.id)
            } else { XCTAssertEqual(try JSONDecoder().decode(ConnectorSnapshot.self, from: response).instanceID, pipe.snapshot.instanceID) }
            wait(for: [done], timeout: 2)
        }
    }
}
