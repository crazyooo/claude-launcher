import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallCoordinatorTests: XCTestCase {
    private final class Service: RouterSystemInstallService {
        var registered = false
        var node: RouterSystemInstallNode?
        var authorized: RouterSystemInstallNode?
        var removesNodeOnStop = false
        var onRegistration: (() throws -> Void)?
        func observedSocket() throws -> RouterSystemInstallNode? { node }
        func authorizeResidualReplacement(_ node: RouterSystemInstallNode?) throws { authorized = node }
        var quiesces = 0
        var registrations = 0
        var queries = 0
        var onQuery: ((Int) -> Void)?
        func job() throws -> RouterSystemInstallJob { queries += 1; onQuery?(queries); return .init(registered: registered, work: nil) }
        func quiesce(original: RouterSystemInstallJob) throws {
            guard node == nil || node == authorized else { throw RouterSystemError.conflict }
            quiesces += 1; registered = false
            if removesNodeOnStop { node = nil }
        }
        func register() throws {
            if !registered {
                guard node == nil || node == authorized else { throw RouterSystemError.conflict }
                registrations += 1; registered = true
                var created = stat(); created.st_dev = 1; created.st_ino = 999; created.st_birthtimespec.tv_sec = 1
                node = .init(created)
                try onRegistration?()
            }
        }
        func proof(identity: RouterSystemInstallationIdentity, retired: Bool) throws -> RouterSystemInstallServiceProof {
            guard registered == !retired else { throw RouterSystemError.conflict }
            var info = stat(); info.st_dev = 1; info.st_ino = 999; info.st_birthtimespec.tv_sec = 1
            var proof = RouterSystemInstallServiceProof(installation: identity, registered: registered, socketNode: registered ? .init(info) : nil)
            proof.residualSocketNode = retired ? node : nil
            return proof
        }
    }
    private struct Fixture {
        let url: URL
        let registry: RouterSystemDirectory
        let transaction: RouterSystemDirectory
        let destination: RouterSystemDirectory
        let launchd: RouterSystemDirectory
        let tree: RouterSystemInstallTree
        let candidate: RouterSystemInstallCandidate
        let installer: RouterSystemHostLease
        let operation: RouterSystemHostLease
        let service: Service
        func coordinator(_ boundary: @escaping (RouterSystemInstallCoordinator.Boundary) throws -> Void = { _ in }) -> RouterSystemInstallCoordinator {
            .init(registry: registry, transaction: transaction, destination: destination, launchDaemons: launchd, service: service, boundary: boundary)
        }
        func prepare() throws -> RouterSystemInstallPlan {
            try coordinator().prepare(candidate: candidate, payload: [:], initialJournal: nil, installerLease: installer, heldOperationLease: operation)
        }
        func apply(_ boundary: @escaping (RouterSystemInstallCoordinator.Boundary) throws -> Void = { _ in }) throws -> RouterSystemInstallCompletion {
            try coordinator(boundary).apply(confirmedCandidate: candidate.digest, installerLease: installer, heldOperationLease: operation)
        }
    }
    private func fixture(residual: RouterSystemInstallNode? = nil) throws -> Fixture {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-install-coordinator-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        let root = try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid())
        let registry = try root.createDirectory("registry"), destination = try root.createDirectory("destination"), launchd = try root.createDirectory("launchd")
        try FileManager.default.createDirectory(at: url.appendingPathComponent("destination/Claude Router"), withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
        let installed = try destination.installChild(.installedRoot)
        for kind in [RouterSystemDirectory.InstallChild.bin, .core, .run, .state] { _ = try installed.installChild(kind, create: true) }
        let tree = try RouterSystemInstallTree(parent: destination), id = UUID(), identity = RouterSystemInstallationIdentity(id: UUID(), ownerUID: 501)
        let transaction = try registry.createDirectory(RouterSystemInstallRetirement.transactionLeaf(id))
        var journal = RouterSystemJournal.empty(); journal.installation = identity
        try tree.state.create("journal.json", data: RouterSystemInstallEncoding.encode(journal))
        try tree.state.create("operation.lock", data: Data())
        for file in RouterSystemInstallFile.allCases {
            let directory = tree.target(file, launchDaemons: launchd)
            if file == .launchd {
                let path = url.appendingPathComponent("launchd/" + file.leaf)
                try Data(file.rawValue.utf8).write(to: path); XCTAssertEqual(chmod(path.path, file.mode), 0)
            } else { try directory.create(file.leaf, data: Data(file.rawValue.utf8), mode: file.mode) }
        }
        var candidate = RouterSystemInstallCandidate(version: 1, transaction: id, packageID: UUID(), action: .retire,
            installation: identity, helperDigest: String(repeating: "a", count: 64), destinationParent: try .directory(destination),
            launchDaemonsParent: try .directory(launchd), files: try RouterSystemInstallFile.allCases.map {
                .init(file: $0, before: try RouterSystemInstallEncoding.image($0.leaf, in: tree.target($0, launchDaemons: launchd),
                    maximum: $0.maximum, mode: $0.mode), afterDigest: nil, afterCount: nil)
            }, preserved: .init(installation: identity, parents: try tree.parents(), operationLock: try tree.operationImage(), journal: try tree.journalImage()),
            originalJob: .absent, retired: nil, retiredMarker: nil)
        candidate.priorSocket = residual
        let service = Service(); service.node = residual
        return .init(url: url, registry: registry, transaction: transaction, destination: destination, launchd: launchd,
            tree: tree, candidate: candidate, installer: try .acquire(in: registry, purpose: .installer),
            operation: try .acquire(in: tree.state, purpose: .operation), service: service)
    }
    func testRetirePreservesJournalAndOldCompletedCommandHasNoEffects() throws {
        let f = try fixture(), plan = try f.prepare(), result = try f.apply()
        XCTAssertEqual(result.active.action, .retire)
        try f.tree.verify(XCTUnwrap(plan.candidate.preserved), exactJournal: true)
        let ledger = RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd)
        XCTAssertEqual(try ledger.observe()?.preserved, plan.candidate.preserved)
        let calls = f.service.queries
        try f.registry.create("active.json", data: Data("new foreign transaction".utf8))
        XCTAssertEqual(try f.apply(), result)
        XCTAssertEqual(f.service.queries, calls)
        XCTAssertEqual(try f.registry.read("active.json", maximum: 100), Data("new foreign transaction".utf8))
    }
    func testEveryCoordinatorBoundaryResumesWithoutReplayingPublishedQuiesce() throws {
        for point in [RouterSystemInstallCoordinator.Boundary.claimed, .quiesced, .filesPublished, .serviceReady, .proofSaved] {
            let f = try fixture(); _ = try f.prepare()
            var reached = false
            XCTAssertThrowsError(try f.apply { if $0 == point { reached = true; throw RouterSystemError.operationUnsettled } })
            XCTAssertTrue(reached)
            let previous = f.service.quiesces
            _ = try f.apply()
            if [.filesPublished, .serviceReady, .proofSaved].contains(point) { XCTAssertEqual(f.service.quiesces, previous) }
            XCTAssertEqual(f.service.registrations, 0)
            try f.tree.verify(XCTUnwrap(f.candidate.preserved), exactJournal: true)
        }
    }
    func testPublishedRetryRejectsMissingOrReplacedArchiveWithoutServiceEffects() throws {
        for replaced in [false, true] {
            let f = try fixture(); _ = try f.prepare()
            XCTAssertThrowsError(try f.apply { if $0 == .filesPublished { throw RouterSystemError.operationUnsettled } })
            let path = f.url.appendingPathComponent("registry/" + RouterSystemInstallRetirement.transactionLeaf(f.candidate.transaction) + "/helper.retired")
            let bytes = try Data(contentsOf: path)
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("preserved"))
            if replaced { try bytes.write(to: path); XCTAssertEqual(chmod(path.path, 0o700), 0) }
            let calls = f.service.queries
            XCTAssertThrowsError(try f.apply())
            XCTAssertEqual(f.service.queries, calls)
        }
    }
    func testReplacementRetiredPointerAndCorruptClosedProofAreRejected() throws {
        for pointer in [false, true] {
            let f = try fixture(); _ = try f.prepare(); _ = try f.apply()
            let ledger = RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd)
            XCTAssertNotNil(try ledger.observe())
            let path = pointer ? f.url.appendingPathComponent("registry/retired.json") :
                f.url.appendingPathComponent("registry/" + RouterSystemInstallRetirement.transactionLeaf(f.candidate.transaction) + "/final-proof.json")
            let bytes = try Data(contentsOf: path)
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("preserved"))
            try (pointer ? bytes : Data("{}".utf8)).write(to: path); XCTAssertEqual(chmod(path.path, 0o600), 0)
            XCTAssertThrowsError(try ledger.observe())
        }
    }
    func testRetirementPublicationCrashKeepsOneMarkerAndResumes() throws {
        for point in [RouterSystemInstallRetirement.Boundary.published, .publicationSynced] {
            let f = try fixture(), plan = try f.prepare()
            XCTAssertThrowsError(try f.apply { if $0 == .filesPublished { throw RouterSystemError.operationUnsettled } })
            var reached = false
            let ledger = RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd, boundary: {
                if $0 == point { reached = true; throw RouterSystemError.operationUnsettled }
            })
            XCTAssertThrowsError(try ledger.publish(plan: plan, tree: f.tree)); XCTAssertTrue(reached)
            _ = try f.apply()
            XCTAssertNotNil(try ledger.observe())
        }
    }
    func testInitialPublicationHoldsOperationAndResumesAfterHostLock() throws {
        let f = try fixture()
        try FileManager.default.moveItem(at: f.url.appendingPathComponent("destination/Claude Router"), to: f.url.appendingPathComponent("preserved-old-root"))
        let id = UUID(), transaction = try f.registry.createDirectory(RouterSystemInstallRetirement.transactionLeaf(id))
        let payload = try payload()
        let candidate = RouterSystemInstallCandidate(version: 1, transaction: id, packageID: UUID(), action: .install,
            installation: .init(id: id, ownerUID: 501), helperDigest: RouterSystemObservation.hash(payload[.helper]!),
            destinationParent: f.candidate.destinationParent, launchDaemonsParent: f.candidate.launchDaemonsParent,
            files: RouterSystemInstallFile.allCases.map { .init(file: $0, before: nil, afterDigest: payload[$0].map(RouterSystemObservation.hash), afterCount: payload[$0]?.count) },
            preserved: nil, originalJob: .absent, retired: nil, retiredMarker: nil)
        // Move the old fixture plist aside: the first-install candidate requires an empty target.
        let plist = f.url.appendingPathComponent("launchd/" + RouterSystemInstallFile.launchd.leaf)
        try FileManager.default.moveItem(at: plist, to: plist.appendingPathExtension("preserved"))
        func coordinator(_ boundary: @escaping (RouterSystemInstallCoordinator.Boundary) throws -> Void = { _ in }) -> RouterSystemInstallCoordinator {
            .init(registry: f.registry, transaction: transaction, destination: f.destination, launchDaemons: f.launchd, service: f.service, boundary: boundary)
        }
        _ = try coordinator().prepare(candidate: candidate, payload: payload, initialJournal: candidate.initialJournalBytes(),
            installerLease: f.installer, heldOperationLease: nil)
        f.service.registered = true
        XCTAssertThrowsError(try coordinator().apply(confirmedCandidate: candidate.digest, installerLease: f.installer))
        XCTAssertFalse(FileManager.default.fileExists(atPath: f.url.appendingPathComponent("destination/Claude Router").path))
        f.service.registered = false
        var locked = false
        XCTAssertThrowsError(try coordinator { point in
            if point == .quiesced {
                let state = try f.destination.installChild(.installedRoot).installChild(.state)
                XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: state, purpose: .operation))
                locked = true; throw RouterSystemError.operationUnsettled
            }
        }.apply(confirmedCandidate: candidate.digest, installerLease: f.installer))
        XCTAssertTrue(locked)
        // A later bootstrap may legitimately advance the journal before installer completion.
        XCTAssertThrowsError(try coordinator { point in
            if point == .serviceReady {
                let state = try f.destination.installChild(.installedRoot).installChild(.state)
                var journal = try RouterSystemJournalDecoder.decode(XCTUnwrap(state.read("journal.json", maximum: 65536)))
                journal.revision = UUID()
                try RouterSystemInstallEncoding.encode(journal).write(to: f.url.appendingPathComponent("destination/Claude Router/state/journal.json"))
                throw RouterSystemError.operationUnsettled
            }
        }.apply(confirmedCandidate: candidate.digest, installerLease: f.installer))
        _ = try coordinator().apply(confirmedCandidate: candidate.digest, installerLease: f.installer)
        XCTAssertEqual(f.service.registrations, 1)
        XCTAssertEqual(f.service.quiesces, 0)
    }
    func testPartialUpgradePreservesArchivesAndSavedProofNeverReRegisters() throws {
        let f = try fixture(), payload = try payload()
        let candidate = RouterSystemInstallCandidate(version: 1, transaction: f.candidate.transaction,
            packageID: UUID(), action: .upgrade, installation: f.candidate.installation,
            helperDigest: RouterSystemObservation.hash(payload[.helper]!), destinationParent: f.candidate.destinationParent,
            launchDaemonsParent: f.candidate.launchDaemonsParent,
            files: f.candidate.files.map { .init(file: $0.file, before: $0.before, afterDigest: payload[$0.file].map(RouterSystemObservation.hash), afterCount: payload[$0.file]?.count) },
            preserved: f.candidate.preserved, originalJob: .absent, retired: nil, retiredMarker: nil)
        let plan = try f.coordinator().prepare(candidate: candidate, payload: payload, initialJournal: nil,
            installerLease: f.installer, heldOperationLease: f.operation)
        _ = try RouterSystemInstallRegistry(registry: f.registry, transaction: f.transaction).claim(plan.active(in: f.transaction))
        try RouterSystemInstallTransaction(directory: f.transaction, id: candidate.transaction).publish(plan.files[0], target: f.tree.bin)
        XCTAssertThrowsError(try f.coordinator { if $0 == .proofSaved { throw RouterSystemError.operationUnsettled } }
            .apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation))
        let quiesces = f.service.quiesces, registrations = f.service.registrations
        f.service.registered = false
        XCTAssertThrowsError(try f.coordinator().apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation))
        XCTAssertEqual(f.service.quiesces, quiesces)
        XCTAssertEqual(f.service.registrations, registrations)
        f.service.registered = true
        _ = try f.coordinator().apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation)
        try f.tree.verify(XCTUnwrap(candidate.preserved), exactJournal: true)
    }
    func testCandidatePreviewReadsCurrentInstallationWithoutCreatingTransactionOrLocks() throws {
        let f = try fixture(), raw = try payload(), packageID = UUID()
        let payload = RouterSystemInstallerPayload(helper: raw[.helper]!, core: raw[.core]!)
        let digest = RouterSystemObservation.hash(payload.helper)
        let files = try payload.files(packageID: packageID, identity: f.candidate.installation, helperSHA256: digest)
        for file in RouterSystemInstallFile.allCases {
            let relative: String
            switch file { case .helper: relative = "destination/Claude Router/bin/"; case .core: relative = "destination/Claude Router/core/"
            case .launchd: relative = "launchd/"; default: relative = "destination/Claude Router/" }
            try files[file]!.write(to: f.url.appendingPathComponent(relative + file.leaf))
        }
        let journal = try f.tree.journalImage(), operation = try f.tree.operationImage()
        let before = try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted()
        let request = RouterSystemInstallerRequest(verb: .preview, action: .upgrade, ownerUID: 501, id: UUID(), confirm: nil)
        let builder = RouterSystemInstallCandidateBuilder(request: request, packageID: packageID, helperSHA256: digest,
            payload: payload, destination: f.destination, launchDaemons: f.launchd, registry: f.registry, service: f.service)
        let candidate = try builder.collect().candidate
        XCTAssertEqual(try builder.collect().candidate, candidate)
        XCTAssertEqual(try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted(), before)
        XCTAssertEqual(try f.tree.journalImage(), journal); XCTAssertEqual(try f.tree.operationImage(), operation)
        XCTAssertNil(try f.registry.read("active.json", maximum: 8192))
        try Data("external replacement".utf8).write(to: f.url.appendingPathComponent("destination/Claude Router/bin/router-system-helper"))
        XCTAssertThrowsError(try builder.collect())
        XCTAssertEqual(try f.tree.journalImage(), journal)
    }
    func testSavedRequestCannotSelectAnotherActionOwnerPackageOrDirectory() throws {
        let f = try fixture(), plan = try f.prepare(), candidate = plan.candidate
        func request(id: UUID? = nil, action: RouterSystemInstallAction = .retire, uid: UInt32 = 501) -> RouterSystemInstallerRequest {
            .init(verb: .apply, action: action, ownerUID: uid, id: id ?? candidate.transaction, confirm: nil)
        }
        let node = try RouterSystemInstallNode.directory(f.transaction)
        try request().validateSaved(plan, packageID: candidate.packageID, helperSHA256: candidate.helperDigest, transactionDirectory: node)
        for invalid in [request(id: UUID()), request(action: .install), request(uid: 502)] {
            XCTAssertThrowsError(try invalid.validateSaved(plan, packageID: candidate.packageID, helperSHA256: candidate.helperDigest, transactionDirectory: node))
        }
        XCTAssertThrowsError(try request().validateSaved(plan, packageID: UUID(), helperSHA256: candidate.helperDigest, transactionDirectory: node))
        XCTAssertThrowsError(try request().validateSaved(plan, packageID: candidate.packageID, helperSHA256: String(repeating: "b", count: 64), transactionDirectory: node))
        XCTAssertThrowsError(try request().validateSaved(plan, packageID: candidate.packageID, helperSHA256: candidate.helperDigest, transactionDirectory: .directory(f.registry)))
    }
    func testFreshCandidateIsReadOnlyAndRejectsJobChangeOrActiveTransaction() throws {
        let f = try fixture(), raw = try payload(), packageID = UUID()
        try FileManager.default.moveItem(at: f.url.appendingPathComponent("destination/Claude Router"), to: f.url.appendingPathComponent("preserved-old-root"))
        let plist = f.url.appendingPathComponent("launchd/" + RouterSystemInstallFile.launchd.leaf)
        try FileManager.default.moveItem(at: plist, to: plist.appendingPathExtension("preserved"))
        let payload = RouterSystemInstallerPayload(helper: raw[.helper]!, core: raw[.core]!)
        let request = RouterSystemInstallerRequest(verb: .preview, action: .install, ownerUID: 501, id: UUID(), confirm: nil)
        let builder = RouterSystemInstallCandidateBuilder(request: request, packageID: packageID,
            helperSHA256: RouterSystemObservation.hash(payload.helper), payload: payload, destination: f.destination,
            launchDaemons: f.launchd, registry: f.registry, service: f.service)
        let before = try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted()
        let candidate = try builder.collect().candidate
        XCTAssertEqual(candidate.installation.id, request.id)
        XCTAssertNil(candidate.preserved)
        XCTAssertEqual(try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted(), before)
        let finalQuery = f.service.queries + 2
        f.service.onQuery = { if $0 == finalQuery { f.service.registered = true } }
        XCTAssertThrowsError(try builder.collect())
        f.service.onQuery = nil; f.service.registered = false
        try f.registry.create("active.json", data: Data("unknown transaction".utf8))
        XCTAssertThrowsError(try builder.collect())
    }
    private func payload() throws -> [RouterSystemInstallFile: Data] {
        let core = try Data(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent(".build/router-core/mihomo"))
        XCTAssertEqual(RouterSystemObservation.hash(core), RouterCoreRelease.executableSHA256)
        return [.helper: Data("new-helper".utf8), .core: core,
            .manifest: Data("new-manifest".utf8), .packageReceipt: Data("new-receipt".utf8), .launchd: try RouterSystemInstallPlist.bytes(ownerUID: 501)]
    }
    func testPartialReinstallConsumesOriginalMarkerAndReusesState() throws {
        let f = try fixture(); _ = try f.prepare(); _ = try f.apply()
        let history = try XCTUnwrap(RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd).observe())
        let id = UUID(), transaction = try f.registry.createDirectory(RouterSystemInstallRetirement.transactionLeaf(id))
        let payload = try payload()
        let candidate = RouterSystemInstallCandidate(version: 1, transaction: id, packageID: UUID(), action: .reinstall,
            installation: f.candidate.installation, helperDigest: RouterSystemObservation.hash(payload[.helper]!),
            destinationParent: f.candidate.destinationParent, launchDaemonsParent: f.candidate.launchDaemonsParent,
            files: RouterSystemInstallFile.allCases.map { .init(file: $0, before: nil, afterDigest: payload[$0].map(RouterSystemObservation.hash), afterCount: payload[$0]?.count) },
            preserved: history.preserved, originalJob: .absent, retired: history.pointer, retiredMarker: history.marker)
        func coordinator(_ fail: Bool = false) -> RouterSystemInstallCoordinator {
            .init(registry: f.registry, transaction: transaction, destination: f.destination, launchDaemons: f.launchd, service: f.service,
                boundary: { if fail && $0 == .serviceReady { throw RouterSystemError.operationUnsettled } })
        }
        let plan = try coordinator().prepare(candidate: candidate, payload: payload, initialJournal: nil,
            installerLease: f.installer, heldOperationLease: f.operation)
        _ = try RouterSystemInstallRegistry(registry: f.registry, transaction: transaction).claim(plan.active(in: transaction))
        let files = RouterSystemInstallTransaction(directory: transaction, id: id)
        try files.publish(plan.files[0], target: f.tree.bin)
        XCTAssertThrowsError(try coordinator(true).apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation))
        XCTAssertNil(try f.registry.read("retired.json", maximum: 8192))
        XCTAssertEqual(try RouterSystemInstallEncoding.image("retired.closed", in: transaction, maximum: 8192), history.marker)
        _ = try coordinator().apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation)
        XCTAssertEqual(f.service.registrations, 1)
        try f.tree.verify(history.preserved, exactJournal: true)
    }
    func testRetirementRecordsRetainedSocketWithoutClaimingListener() throws {
        var info = stat(); info.st_dev = 1; info.st_ino = 123; info.st_birthtimespec.tv_sec = 1
        let node = RouterSystemInstallNode(info)
        for removed in [false, true] {
            let f = try fixture(residual: node)
            f.service.removesNodeOnStop = removed
            _ = try f.prepare(); _ = try f.apply()
            let bytes = try XCTUnwrap(f.transaction.read("final-proof.json", maximum: 16384))
            let proof = try RouterSystemInstallEncoding.decode(RouterSystemInstallFinalProof.self, bytes)
            XCTAssertFalse(proof.service.registered); XCTAssertNil(proof.service.socketNode)
            XCTAssertEqual(proof.service.residualSocketNode, removed ? nil : node)
            XCTAssertNotNil(try RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd).observe())
        }
    }
    func testResidualReplacementOrUnconfirmedNodePreventsRetirement() throws {
        var info = stat(); info.st_dev = 1; info.st_ino = 123
        let original = RouterSystemInstallNode(info)
        for confirmed in [false, true] {
            let f = try fixture(residual: confirmed ? original : nil)
            _ = try f.prepare()
            info.st_ino = 456; f.service.node = .init(info)
            XCTAssertThrowsError(try f.apply())
            XCTAssertEqual(f.service.quiesces, 0)
            XCTAssertNil(try f.transaction.read("files-published.json", maximum: 16384))
        }
    }
    func testRetainedSocketAfterPublicationRemainsBoundOnRetry() throws {
        var info = stat(); info.st_dev = 1; info.st_ino = 123
        let node = RouterSystemInstallNode(info), f = try fixture(residual: node)
        _ = try f.prepare()
        XCTAssertThrowsError(try f.apply { if $0 == .filesPublished { throw RouterSystemError.operationUnsettled } })
        info.st_ino = 456; f.service.node = .init(info)
        XCTAssertThrowsError(try f.apply())
        f.service.node = node
        _ = try f.apply()
        XCTAssertEqual(f.service.quiesces, 1)
    }

    func testReinstallUsesRetirementResidualAndRejectsReplacement() throws {
        for scenario in 0..<3 {
            var info = stat(); info.st_dev = 1; info.st_ino = 123
            let old = RouterSystemInstallNode(info), f = try fixture(residual: old)
            _ = try f.prepare(); _ = try f.apply()
            let history = try XCTUnwrap(RouterSystemInstallRetirement(registry: f.registry, transaction: f.transaction, launchDaemons: f.launchd).observe())
            XCTAssertEqual(history.residualSocket, old)
            let id = UUID(), transaction = try f.registry.createDirectory(RouterSystemInstallRetirement.transactionLeaf(id))
            let files = try payload()
            var candidate = RouterSystemInstallCandidate(version: 1, transaction: id, packageID: UUID(), action: .reinstall,
                installation: f.candidate.installation, helperDigest: RouterSystemObservation.hash(files[.helper]!),
                destinationParent: f.candidate.destinationParent, launchDaemonsParent: f.candidate.launchDaemonsParent,
                files: RouterSystemInstallFile.allCases.map { .init(file: $0, before: nil, afterDigest: files[$0].map(RouterSystemObservation.hash), afterCount: files[$0]?.count) },
                preserved: history.preserved, originalJob: .absent, retired: history.pointer, retiredMarker: history.marker)
            candidate.priorSocket = old
            let coordinator = RouterSystemInstallCoordinator(registry: f.registry, transaction: transaction,
                destination: f.destination, launchDaemons: f.launchd, service: f.service)
            if scenario == 2 {
                info.st_ino = 456; candidate.priorSocket = .init(info); f.service.node = .init(info)
                XCTAssertThrowsError(try coordinator.prepare(candidate: candidate, payload: files, initialJournal: nil,
                    installerLease: f.installer, heldOperationLease: f.operation))
                XCTAssertEqual(f.service.registrations, 0)
                continue
            }
            _ = try coordinator.prepare(candidate: candidate, payload: files, initialJournal: nil,
                installerLease: f.installer, heldOperationLease: f.operation)
            if scenario == 1 {
                info.st_ino = 456; f.service.node = .init(info)
                XCTAssertThrowsError(try coordinator.apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation))
                XCTAssertEqual(f.service.registrations, 0)
                XCTAssertNil(try transaction.read("files-published.json", maximum: 16384))
            } else {
                _ = try coordinator.apply(confirmedCandidate: candidate.digest, installerLease: f.installer, heldOperationLease: f.operation)
                XCTAssertEqual(f.service.registrations, 1)
                XCTAssertNotEqual(f.service.node, old)
            }
        }
    }

    private func interruptedInstall() throws -> (Fixture, RouterSystemDirectory, RouterSystemInstallPlan, RouterSystemInstallResume) {
        let f = try fixture()
        try FileManager.default.moveItem(at: f.url.appendingPathComponent("destination/Claude Router"), to: f.url.appendingPathComponent("preserved-old-root"))
        let plist = f.url.appendingPathComponent("launchd/" + RouterSystemInstallFile.launchd.leaf)
        try FileManager.default.moveItem(at: plist, to: plist.appendingPathExtension("preserved"))
        let id = UUID(), transaction = try f.registry.createDirectory(RouterSystemInstallRetirement.transactionLeaf(id))
        let files = try payload()
        let candidate = RouterSystemInstallCandidate(version: 1, transaction: id, packageID: UUID(), action: .install,
            installation: .init(id: id, ownerUID: 501), helperDigest: RouterSystemObservation.hash(files[.helper]!),
            destinationParent: f.candidate.destinationParent, launchDaemonsParent: f.candidate.launchDaemonsParent,
            files: RouterSystemInstallFile.allCases.map { .init(file: $0, before: nil, afterDigest: files[$0].map(RouterSystemObservation.hash), afterCount: files[$0]?.count) },
            preserved: nil, originalJob: .absent, retired: nil, retiredMarker: nil)
        let coordinator = RouterSystemInstallCoordinator(registry: f.registry, transaction: transaction,
            destination: f.destination, launchDaemons: f.launchd, service: f.service,
            boundary: { if $0 == .filesPublished { throw RouterSystemError.operationUnsettled } })
        let plan = try coordinator.prepare(candidate: candidate, payload: files, initialJournal: candidate.initialJournalBytes(),
            installerLease: f.installer, heldOperationLease: nil)
        XCTAssertThrowsError(try coordinator.apply(confirmedCandidate: candidate.digest, installerLease: f.installer))
        var info = stat(); info.st_dev = 1; info.st_ino = 123
        f.service.node = .init(info) // Left behind by the failed initial registration.
        return (f, transaction, plan, .init(registry: f.registry, transaction: transaction,
            destination: f.destination, launchDaemons: f.launchd, service: f.service))
    }
    func testResumePreviewIsReadonlyAndApplyPreservesSealedPlan() throws {
        let (f, transaction, plan, resume) = try interruptedInstall()
        let before = try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted()
        let original = try XCTUnwrap(transaction.read("plan.json", maximum: 1024 * 1024))
        let observation = try resume.preview(plan)
        XCTAssertEqual(try FileManager.default.subpathsOfDirectory(atPath: f.url.path).sorted(), before)
        XCTAssertEqual(f.service.registrations, 0); XCTAssertEqual(f.service.quiesces, 0)
        let state = try f.destination.installChild(.installedRoot).installChild(.state)
        f.service.onRegistration = {
            // The newly activated host must be able to acquire its lease but not dispatch work.
            let host = try RouterSystemHostLease.acquire(in: state, purpose: .host)
            try host.verify()
            XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: state, purpose: .operation))
        }
        let completion = try resume.apply(plan, confirm: observation.digest, installer: f.installer)
        XCTAssertEqual(f.service.registrations, 1)
        XCTAssertEqual(try transaction.read("plan.json", maximum: 1024 * 1024), original)
        XCTAssertNotNil(try transaction.read("resume-" + observation.digest + ".json", maximum: 65536))
        let calls = f.service.queries
        try f.registry.create("active.json", data: Data("new unrelated transaction".utf8))
        XCTAssertEqual(try resume.apply(plan, confirm: observation.digest, installer: f.installer), completion)
        XCTAssertEqual(f.service.queries, calls)
    }
    func testResumeUnknownBootstrapWithLiveHostOnlyObservesOnRetry() throws {
        let (f, _, plan, resume) = try interruptedInstall()
        let observation = try resume.preview(plan)
        f.service.onRegistration = { throw RouterSystemError.operationUnsettled }
        XCTAssertThrowsError(try resume.apply(plan, confirm: observation.digest, installer: f.installer))
        XCTAssertEqual(f.service.registrations, 1); XCTAssertTrue(f.service.registered)
        let state = try f.destination.installChild(.installedRoot).installChild(.state)
        let liveHost = try RouterSystemHostLease.acquire(in: state, purpose: .host)
        _ = try withExtendedLifetime(liveHost) { try resume.apply(plan, confirm: observation.digest, installer: f.installer) }
        XCTAssertEqual(f.service.registrations, 1)
    }
    func testResumeNewAbsentSocketRequiresNewPreviewAndPreservesOldReceipt() throws {
        let (f, transaction, plan, resume) = try interruptedInstall()
        let original = try resume.preview(plan)
        f.service.onRegistration = { throw RouterSystemError.operationUnsettled }
        XCTAssertThrowsError(try resume.apply(plan, confirm: original.digest, installer: f.installer))
        f.service.registered = false; f.service.onRegistration = nil
        XCTAssertThrowsError(try resume.apply(plan, confirm: original.digest, installer: f.installer))
        XCTAssertEqual(f.service.registrations, 1)
        let current = try resume.preview(plan)
        XCTAssertNotEqual(try current.digest, try original.digest)
        _ = try resume.apply(plan, confirm: current.digest, installer: f.installer)
        XCTAssertEqual(f.service.registrations, 2)
        for observation in [original, current] {
            XCTAssertNotNil(try transaction.read("resume-" + observation.digest + ".json", maximum: 65536))
        }
    }
    func testResumeRejectsSameBytesReplacementAndChangedIdleJournal() throws {
        for changeJournal in [false, true] {
            let (f, _, plan, resume) = try interruptedInstall()
            let observation = try resume.preview(plan)
            let leaf = changeJournal ? "state/journal.json" : "bin/router-system-helper"
            let url = f.url.appendingPathComponent("destination/Claude Router/" + leaf)
            var bytes = try Data(contentsOf: url)
            if changeJournal {
                var journal = try RouterSystemJournalDecoder.decode(bytes); journal.revision = UUID()
                bytes = try RouterSystemInstallEncoding.encode(journal)
            }
            try FileManager.default.moveItem(at: url, to: url.appendingPathExtension("preserved"))
            try bytes.write(to: url); XCTAssertEqual(chmod(url.path, changeJournal ? 0o600 : 0o700), 0)
            XCTAssertThrowsError(try resume.preview(plan))
            XCTAssertThrowsError(try resume.apply(plan, confirm: observation.digest, installer: f.installer))
            XCTAssertEqual(f.service.registrations, 0)
        }
    }

}
