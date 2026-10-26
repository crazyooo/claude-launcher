import XCTest
import CryptoKit
@testable import RoutingCore

final class RouterServiceTests: XCTestCase {
    func testConnectionsDiscardChangedConfigOrReceiptDuringHTTP() throws {
        for leaf in ["config.json", "receipt.json"] {
            let f = try fixture(); try active(f, phase: .running, identity: f.identity); try f.files.locked {}
            let path = f.root.appendingPathComponent(f.preview.id.uuidString.lowercased()).appendingPathComponent(leaf)
            let service = RouterLaunchdService(root: f.root, command: { _, _, _ in
                (.init(exitCode: 0, timedOut: false, settled: true), Data(f.job.utf8))
            }, observeProcess: { _ in .present(f.identity) }, verifyCore: { _ in },
            connectionBody: { _, _, _ in
                var object = try JSONSerialization.jsonObject(with: f.files.readPrivate(path)) as! [String: Any]
                if leaf == "config.json" { object["secret"] = String(repeating: "b", count: 64) }
                else { object["configurationDigest"] = String(repeating: "b", count: 64) }
                try f.files.replacePrivate(JSONSerialization.data(withJSONObject: object), at: path)
                return Data(#"{"connections":null,"uploadTotal":0,"downloadTotal":0}"#.utf8)
            }, connectionListener: { _, _, _ in .observed([.init(descriptor: 1, generation: 1)]) })
            XCTAssertThrowsError(try service.connections(request: UUID())) {
                XCTAssertEqual($0 as? RouterConnectionFailure, .identityChanged)
            }
        }
    }
    func testConnectionsReadDoesNotWriteJournalAndRefusesChangedGeneration() throws {
        for change in [false, true] {
            let f = try fixture()
            try active(f, phase: .running, identity: f.identity)
            try f.files.locked {}
            let original = try f.files.readPrivate(f.root.appendingPathComponent("active.json"))
            var commands: [String] = []
            let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
                commands.append(args[0])
                return (.init(exitCode: 0, timedOut: false, settled: true), Data(f.job.utf8))
            }, observeProcess: { _ in .present(f.identity) }, verifyCore: { _ in },
            connectionBody: { port, secret, _ in
                XCTAssertEqual(port, 19491); XCTAssertEqual(secret, String(repeating: "a", count: 64))
                if change { try self.active(f, phase: .stopped, identity: f.identity) }
                return Data(#"{"connections":null,"uploadTotal":100,"downloadTotal":200}"#.utf8)
            }, connectionListener: { _, _, _ in .observed([.init(descriptor: 9, generation: 3)]) })
            if change { XCTAssertThrowsError(try service.connections(request: UUID())) }
            else {
                let result = try service.connections(request: UUID(), instance: f.preview.id)
                XCTAssertEqual(result.uploadTotal, 100); XCTAssertEqual(result.totalConnections, 0)
                XCTAssertEqual(result.binding.mode, .userManaged)
                XCTAssertEqual(try f.files.readPrivate(f.root.appendingPathComponent("active.json")), original)
            }
            XCTAssertTrue(commands.allSatisfy { $0 == "print" })
        }
    }
    func testConnectionsNeverCreateRuntimeOrMissingObservationLock() throws {
        let f = try fixture()
        let absent = f.root.appendingPathComponent("absent")
        XCTAssertThrowsError(try RouterLaunchdService(root: absent).connections(request: UUID())) {
            XCTAssertEqual($0 as? RouterConnectionFailure, .noActiveInstance)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: absent.path))
        let before = try FileManager.default.contentsOfDirectory(atPath: f.root.path).sorted()
        XCTAssertThrowsError(try RouterLaunchdService(root: f.root).connections(request: UUID()))
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: f.root.path).sorted(), before)
    }
    func testConnectionsFailOnListenerReplacementAndUnavailableStates() throws {
        for phase in [RouterLaunchdService.Phase.running, .pendingStart, .pendingStop, .stopped] {
            let f = try fixture(); try active(f, phase: phase, identity: f.identity); try f.files.locked {}
            var listenerReads = 0, bodyReads = 0
            let service = RouterLaunchdService(root: f.root, command: { _, _, _ in
                (.init(exitCode: 0, timedOut: false, settled: true), Data(f.job.utf8))
            }, observeProcess: { _ in .present(f.identity) }, verifyCore: { _ in }, connectionBody: { _, _, _ in
                bodyReads += 1
                return Data(#"{"connections":null,"uploadTotal":0,"downloadTotal":0}"#.utf8)
            }, connectionListener: { _, _, _ in
                listenerReads += 1; return .observed([.init(descriptor: 9, generation: UInt64(listenerReads))])
            })
            XCTAssertThrowsError(try service.connections(request: UUID()))
            XCTAssertEqual(bodyReads, phase == .running ? 1 : 0)
        }
    }
    func testControlSandboxUsesAcceptedLocalhostSyntax() throws {
        let profile = try RouterLaunchdService.controlSandbox(port: 19491, execute: RouterRuntimeProcess.run)
        XCTAssertTrue(profile.contains("localhost:19491"))
        XCTAssertFalse(profile.contains("allow network-outbound"))
        for (result, error) in [
            (RouterProcessResult(exitCode: 65, timedOut: false, settled: true), RouterRuntimeError.configurationRejected),
            (.init(exitCode: 0, timedOut: true, settled: true), .processTimedOut),
            (.init(exitCode: -1, timedOut: true, settled: false), .processUnsettled)
        ] {
            XCTAssertThrowsError(try RouterLaunchdService.controlSandbox(port: 19491) { _, _, _ in result }) {
                XCTAssertEqual($0 as? RouterRuntimeError, error)
            }
        }
    }
    func testRetainedIdentityReadIsNonMutatingAndRejectsDamagedJournal() throws {
        let f = try fixture(); try active(f, phase: .pendingStop, identity: f.identity)
        let before = try f.files.readPrivate(f.root.appendingPathComponent("active.json"))
        let service = RouterLaunchdService(root: f.root, command: { _, _, _ in
            XCTFail("retained read must not execute launchctl"); throw RouterRuntimeError.operationFailed
        })
        XCTAssertEqual(try service.retainedOperation()?.id, f.preview.id)
        XCTAssertEqual(try service.retainedOperation()?.phase, "pendingStop")
        XCTAssertEqual(try f.files.readPrivate(f.root.appendingPathComponent("active.json")), before)
        let absent = f.root.appendingPathComponent("absent")
        XCTAssertNil(try RouterLaunchdService(root: absent).retainedOperation())
        XCTAssertFalse(FileManager.default.fileExists(atPath: absent.path))
        try f.files.replacePrivate(Data("{}".utf8), at: f.root.appendingPathComponent("active.json"))
        XCTAssertThrowsError(try service.retainedOperation())
    }
    struct Fixture {
        let root: URL
        let files: RouterRuntimeFiles
        let preview: RouterServicePreview
        let identity: RouterProcessIdentity
        let job: String
    }
    func fixture() throws -> Fixture {
        let root = URL(fileURLWithPath: RouterRuntimeFiles.physicalPath(FileManager.default.temporaryDirectory)!)
            .appendingPathComponent("router-service-test-" + UUID().uuidString)
        let files = RouterRuntimeFiles(root: root), directory = try files.createGeneration()
        let id = UUID(uuidString: directory.lastPathComponent)!
        let config = try RouterRuntimeCompiler.compile(.init(proxies: [], rules: [], defaultDestination: .block),
                                                       controllerPort: 19491, secret: String(repeating: "a", count: 64))
        let preview = RouterServicePreview(id: id, summary: config.summary, createdAt: Date(), expiresAt: Date().addingTimeInterval(600), effect: "test")
        let args = ["/usr/bin/sandbox-exec", "-p", "test-profile", directory.appendingPathComponent("mihomo").path]
        let plist = Data("test-plist".utf8)
        func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }
        try files.writeNew(config.privateJSON, to: directory.appendingPathComponent("config.json"))
        try files.writeNew(plist, to: directory.appendingPathComponent("agent.plist"))
        let receipt = RouterLaunchdService.Receipt(preview: preview, configurationDigest: hash(config.privateJSON), plistDigest: hash(plist), arguments: args)
        try files.writeNew(JSONEncoder().encode(receipt), to: directory.appendingPathComponent("receipt.json"))
        let identity = RouterProcessIdentity(pid: 4242, seconds: 100, microseconds: 20, executable: args.last!)
        let job = "path = \(directory.path)/agent.plist\nprogram = /usr/bin/sandbox-exec\narguments = {\n" + args.joined(separator: "\n") + "\n}\nstate = running\npid = 4242\n"
        return .init(root: root, files: files, preview: preview, identity: identity, job: job)
    }
    func active(_ f: Fixture, phase: RouterLaunchdService.Phase, identity: RouterProcessIdentity?) throws {
        try f.files.replacePrivate(JSONEncoder().encode(RouterLaunchdService.Active(id: f.preview.id, phase: phase, process: identity)), at: f.root.appendingPathComponent("active.json"))
    }
    func record(_ f: Fixture) throws -> RouterLaunchdService.Active {
        try JSONDecoder().decode(RouterLaunchdService.Active.self, from: f.files.readPrivate(f.root.appendingPathComponent("active.json")))
    }

    func testUnknownStartCannotBeOverwrittenAndLateJobCanBeStoppedUsingOriginalID() throws {
        let f = try fixture()
        var loaded = false, exited = false, bootstrapCount = 0
        let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
            switch args[0] {
            case "print": return (.init(exitCode: loaded ? 0 : 113, timedOut: false, settled: true), loaded ? Data(f.job.utf8) : Data())
            case "bootstrap": bootstrapCount += 1; return (.init(exitCode: -1, timedOut: true, settled: false), Data())
            case "bootout": loaded = false; exited = true; return (.init(exitCode: 0, timedOut: false, settled: true), Data())
            default: XCTFail(); throw RouterRuntimeError.operationFailed
            }
        }, observeProcess: { _ in exited ? .absent : .present(f.identity) }, verifyCore: { _ in })
        XCTAssertThrowsError(try service.start(f.preview.id))
        XCTAssertEqual(try record(f).phase, .pendingStart)
        XCTAssertThrowsError(try service.prepare(plan: .init(proxies: [], rules: [], defaultDestination: .block), core: URL(fileURLWithPath: "/unused")))
        XCTAssertThrowsError(try service.start(f.preview.id))
        XCTAssertEqual(bootstrapCount, 1); XCTAssertEqual(try record(f).id, f.preview.id)
        loaded = true
        XCTAssertEqual(try service.stop(f.preview.id).state, "stopped")
        XCTAssertEqual(try record(f).phase, .stopped)
    }

    func testJobAbsenceDoesNotProveProcessExit() async throws {
        let f = try fixture(); try active(f, phase: .pendingStop, identity: f.identity)
        let service = RouterLaunchdService(root: f.root, command: { _, _, _ in
            (.init(exitCode: 113, timedOut: false, settled: true), Data())
        }, observeProcess: { _ in .present(f.identity) })
        do { _ = try await service.status(); XCTFail("live old core cannot be stopped") }
        catch { XCTAssertEqual(error as? RouterRuntimeError, .ownershipUnknown) }
        XCTAssertEqual(try record(f).phase, .pendingStop)
    }

    func testRegisteredJobWithoutLiveOwnedProcessCannotBecomeHealthy() async throws {
        let f = try fixture(); try active(f, phase: .running, identity: f.identity)
        let service = RouterLaunchdService(root: f.root, command: { _, _, _ in
            (.init(exitCode: 0, timedOut: false, settled: true), Data(f.job.utf8))
        }, observeProcess: { _ in .absent })
        do { _ = try await service.status(); XCTFail("must fail before HTTP") }
        catch { XCTAssertEqual(error as? RouterRuntimeError, .ownershipUnknown) }
    }

    func testDifferentJobArgumentsRefuseStopWithoutBootout() throws {
        let f = try fixture(); try active(f, phase: .running, identity: f.identity)
        var commands: [String] = []
        let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
            commands.append(args[0])
            return (.init(exitCode: 0, timedOut: false, settled: true), Data(f.job.replacingOccurrences(of: "test-profile", with: "foreign-profile").utf8))
        }, observeProcess: { _ in .present(f.identity) })
        XCTAssertThrowsError(try service.stop(f.preview.id)); XCTAssertEqual(commands, ["print"])
    }

    func testPIDReuseProvesOldExitButUnknownObservationDoesNot() {
        let a = RouterProcessIdentity(pid: 123, seconds: 100, microseconds: 0, executable: "/core")
        let b = RouterProcessIdentity(pid: 123, seconds: 200, microseconds: 0, executable: "/another")
        XCTAssertTrue(RouterProcessObservation.present(b).provesExit(of: a))
        XCTAssertFalse(RouterProcessObservation.present(a).provesExit(of: a))
        XCTAssertFalse(RouterProcessObservation.unknown.provesExit(of: a))
    }
    func testPreExecCanTransitionOnlyToSameBirthPinnedCore() {
        let wrapper = RouterProcessIdentity(pid: 123, seconds: 100, microseconds: 10, executable: "/usr/bin/sandbox-exec")
        let core = RouterProcessIdentity(pid: 123, seconds: 100, microseconds: 10, executable: "/private/generation/mihomo")
        XCTAssertTrue(RouterLaunchdService.continues(wrapper, as: core, corePath: core.executable))
        XCTAssertTrue(RouterLaunchdService.continues(core, as: core, corePath: core.executable))
        XCTAssertFalse(RouterLaunchdService.continues(core, as: wrapper, corePath: core.executable))
        let reused = RouterProcessIdentity(pid: 123, seconds: 200, microseconds: 10, executable: core.executable)
        XCTAssertFalse(RouterLaunchdService.continues(wrapper, as: reused, corePath: core.executable))
    }

    func testMissingRuntimeStatusDoesNotCreateFiles() async throws {
        let f = try fixture(), absent = f.root.appendingPathComponent("absent")
        let service = RouterLaunchdService(root: absent, command: { _, _, _ in
            (.init(exitCode: 113, timedOut: false, settled: true), Data())
        })
        let status = try await service.status()
        XCTAssertEqual(status.state, "stopped"); XCTAssertFalse(FileManager.default.fileExists(atPath: absent.path))
    }

    func testPreExecIdentityCanBeStoppedWithoutClaimingCoreHealth() throws {
        let f = try fixture(); try active(f, phase: .pendingStart, identity: nil)
        var loaded = true
        let wrapper = RouterProcessIdentity(pid: f.identity.pid, seconds: f.identity.seconds, microseconds: f.identity.microseconds, executable: "/usr/bin/sandbox-exec")
        let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
            if args[0] == "bootout" { loaded = false }
            return (.init(exitCode: args[0] == "print" && !loaded ? 113 : 0, timedOut: false, settled: true), loaded ? Data(f.job.utf8) : Data())
        }, observeProcess: { _ in loaded ? .present(wrapper) : .absent })
        XCTAssertEqual(try service.stop(f.preview.id).state, "stopped")
        XCTAssertEqual(try record(f).process, wrapper)
    }

    func testUnknownProcessPreservesJobUntilIdentityBecomesAvailable() throws {
        let f = try fixture(); try active(f, phase: .pendingStart, identity: nil)
        var loaded = true, observable = false, removed = false
        let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
            if args[0] == "bootout" { loaded = false; removed = true }
            return (.init(exitCode: args[0] == "print" && !loaded ? 113 : 0, timedOut: false, settled: true), loaded ? Data(f.job.utf8) : Data())
        }, observeProcess: { _ in !loaded ? .absent : (observable ? .present(f.identity) : .unknown) })
        XCTAssertThrowsError(try service.stop(f.preview.id)); XCTAssertFalse(removed)
        observable = true
        XCTAssertEqual(try service.stop(f.preview.id).state, "stopped")
    }

    func testLaunchdTerminalEvidenceAllowsStoppingEarlyExitWithoutInventingPID() throws {
        let f = try fixture(); try active(f, phase: .pendingStart, identity: nil)
        var loaded = true
        let terminal = f.job.replacingOccurrences(of: "state = running\npid = 4242", with: "state = not running\nruns = 1\nlast exit code = 1")
        let service = RouterLaunchdService(root: f.root, command: { _, args, _ in
            if args[0] == "bootout" { loaded = false }
            return (.init(exitCode: args[0] == "print" && !loaded ? 113 : 0, timedOut: false, settled: true), loaded ? Data(terminal.utf8) : Data())
        }, observeProcess: { _ in XCTFail("no PID to query"); return .unknown })
        XCTAssertEqual(try service.stop(f.preview.id).state, "stopped")
        XCTAssertTrue(try record(f).exitConfirmed)
        XCTAssertFalse(RouterLaunchdService.jobProvesExit("state = not running\nruns = 0\nlast exit code = 0"))
    }
}
