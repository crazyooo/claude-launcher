import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallRootTests: XCTestCase {
    private struct Fixture {
        let url: URL
        let transaction: RouterSystemDirectory
        let destination: RouterSystemDirectory
        let id: UUID
        let journal: Data
        var publisher: RouterSystemInstallRoot { .init(transaction: transaction, destination: destination, id: id) }
        var files: [RouterSystemInstallFile: Data] {
            [.helper: Data("helper".utf8), .core: Data("core".utf8), .manifest: Data("manifest".utf8), .packageReceipt: Data("receipt".utf8)]
        }
        func stage() throws -> RouterSystemInstallRoot.Receipt { try publisher.stage(files: files, initialJournal: journal) }
    }
    private func fixture() throws -> Fixture {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-install-root-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        let root = try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid())
        var journal = RouterSystemJournal.empty()
        journal.installation = .init(id: UUID(), ownerUID: 501)
        return .init(url: url, transaction: try root.createDirectory("transaction"), destination: try root.createDirectory("destination"),
                     id: UUID(), journal: try JSONEncoder().encode(journal))
    }
    func testPublishCompleteTreeAndResumePreserveStateIdentity() throws {
        let f = try fixture(), receipt = try f.stage()
        let previous = try f.transaction.installChild(.stagedRoot)
        XCTAssertEqual(try f.publisher.position(receipt), .staged)
        try f.publisher.publish(receipt)
        XCTAssertEqual(try f.publisher.position(receipt), .published)
        XCTAssertThrowsError(try previous.validate())
        let root = try f.destination.installChild(.installedRoot), state = try root.installChild(.state)
        XCTAssertEqual(try RouterSystemInstallNode.directory(state), receipt.tree.state)
        XCTAssertEqual(try state.read("journal.json", maximum: 65536), f.journal)
        try f.publisher.publish(receipt)
        XCTAssertEqual(try state.read("operation.lock", maximum: 1), Data())
    }
    func testHostLeaseDoesNotInvalidateInitialTreeOnRetry() throws {
        let f = try fixture(), receipt = try f.stage()
        try f.publisher.publish(receipt)
        let state = try f.destination.installChild(.installedRoot).installChild(.state)
        let host = try RouterSystemHostLease.acquire(in: state)
        try host.verify(in: state, purpose: .host)
        XCTAssertThrowsError(try host.verify(in: state, purpose: .operation))
        XCTAssertThrowsError(try host.verify(in: f.transaction, purpose: .host))
        try host.verify(in: f.destination.installChild(.installedRoot).installChild(.state), purpose: .host)
        try f.publisher.publish(receipt)
        withExtendedLifetime(host) {}
    }
    func testOperationLeaseRemainsExclusiveAcrossRootRenameAndRebinding() throws {
        let f = try fixture(), receipt = try f.stage()
        let staged = try f.transaction.installChild(.stagedRoot).installChild(.state)
        let operation = try RouterSystemHostLease.acquire(in: staged, purpose: .operation)
        func childCannotLock(_ state: RouterSystemDirectory) throws {
            try state.validate()
            let child = Process()
            child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            child.arguments = ["-I", "-B", "-c", "import os,sys,fcntl,errno\nf=os.open(sys.argv[1],os.O_RDWR|os.O_NOFOLLOW)\ntry:\n fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept OSError as e:\n sys.exit(0 if e.errno in (errno.EAGAIN,errno.EWOULDBLOCK) else 2)\nsys.exit(3)",
                f.url.appendingPathComponent("destination/Claude Router/state/operation.lock").path]
            child.standardInput = FileHandle.nullDevice; child.standardOutput = FileHandle.nullDevice; child.standardError = FileHandle.nullDevice
            try child.run(); child.waitUntilExit()
            XCTAssertEqual(child.terminationStatus, 0)
        }
        let publisher = RouterSystemInstallRoot(transaction: f.transaction, destination: f.destination, id: f.id, boundary: {
            if $0 == .renamed {
                try childCannotLock(f.destination.installChild(.installedRoot).installChild(.state))
            }
        })
        try publisher.publish(receipt)
        let installed = try f.destination.installChild(.installedRoot).installChild(.state)
        try operation.rebindOperation(to: installed)
        try operation.verify(in: installed, purpose: .operation)
        try childCannotLock(installed)
        XCTAssertThrowsError(try operation.rebindOperation(to: f.transaction))
        let host = try RouterSystemHostLease.acquire(in: installed, purpose: .host)
        XCTAssertThrowsError(try host.rebindOperation(to: installed))
        let lock = f.url.appendingPathComponent("destination/Claude Router/state/operation.lock")
        try FileManager.default.moveItem(at: lock, to: lock.appendingPathExtension("preserved"))
        try installed.create("operation.lock", data: Data())
        XCTAssertThrowsError(try operation.rebindOperation(to: installed))
        withExtendedLifetime((host, operation)) {}
    }
    func testPublicationBoundaryInterruptionsResumeFromSameRootInode() throws {
        for point in RouterSystemInstallRoot.Boundary.allCases where ![.treeSealed, .receiptSealed].contains(point) {
            let f = try fixture(), receipt = try f.stage()
            var reached = false
            let faulty = RouterSystemInstallRoot(transaction: f.transaction, destination: f.destination, id: f.id, boundary: {
                if $0 == point { reached = true; throw RouterSystemError.operationUnsettled }
            })
            XCTAssertThrowsError(try faulty.publish(receipt)); XCTAssertTrue(reached)
            try f.publisher.publish(receipt)
            XCTAssertEqual(try f.publisher.position(receipt), .published)
        }
    }
    func testEveryPublicationSyncFailureIsRecoverable() throws {
        let sample = try fixture(), sampleReceipt = try sample.stage()
        var total = 0
        try RouterSystemInstallRoot(transaction: sample.transaction, destination: sample.destination, id: sample.id, synchronize: {
            total += 1; return fsync($0)
        }).publish(sampleReceipt)
        XCTAssertGreaterThan(total, 0)
        for failAt in 1...total {
            let f = try fixture(), receipt = try f.stage()
            var count = 0
            let faulty = RouterSystemInstallRoot(transaction: f.transaction, destination: f.destination, id: f.id, synchronize: {
                count += 1; return count == failAt ? -1 : fsync($0)
            })
            XCTAssertThrowsError(try faulty.publish(receipt)); XCTAssertEqual(count, failAt)
            try f.publisher.publish(receipt)
            XCTAssertEqual(try f.publisher.position(receipt), .published)
        }
    }
    func testPrivateStagingCrashPreservedAndSealedReceiptCanResume() throws {
        for point in [RouterSystemInstallRoot.Boundary.treeSealed, .receiptSealed] {
            let f = try fixture()
            let faulty = RouterSystemInstallRoot(transaction: f.transaction, destination: f.destination, id: f.id, boundary: {
                if $0 == point { throw RouterSystemError.operationUnsettled }
            })
            XCTAssertThrowsError(try faulty.stage(files: f.files, initialJournal: f.journal))
            XCTAssertThrowsError(try f.stage())
            if point == .treeSealed { XCTAssertThrowsError(try f.publisher.load()) }
            else { try f.publisher.publish(f.publisher.load()) }
        }
    }
    func testForeignDestinationAndLateAppearanceAreNeverMergedOrOverwritten() throws {
        for late in [false, true] {
            let f = try fixture(), receipt = try f.stage()
            let path = f.url.appendingPathComponent("destination/Claude Router")
            func insert() throws {
                try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o755])
                try Data("foreign".utf8).write(to: path.appendingPathComponent("keep"))
            }
            if !late { try insert() }
            let faulty = RouterSystemInstallRoot(transaction: f.transaction, destination: f.destination, id: f.id, boundary: {
                if late && $0 == .beforeRename { try insert() }
            })
            XCTAssertThrowsError(try faulty.publish(receipt))
            XCTAssertEqual(try Data(contentsOf: path.appendingPathComponent("keep")), Data("foreign".utf8))
            XCTAssertNotNil(try f.transaction.installChild(.stagedRoot))
        }
    }
    func testUnexpectedEntriesAndSameBytesFileReplacementRejectPublication() throws {
        for replacement in [false, true] {
            let f = try fixture(), receipt = try f.stage()
            let root = f.url.appendingPathComponent("transaction/root.publish")
            if replacement {
                let file = root.appendingPathComponent("state/journal.json"), bytes = try Data(contentsOf: file)
                try FileManager.default.moveItem(at: file, to: f.url.appendingPathComponent("preserved-journal"))
                try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
            } else { try Data().write(to: root.appendingPathComponent("unexpected")) }
            XCTAssertThrowsError(try f.publisher.publish(receipt))
            XCTAssertEqual(try f.publisher.position(receipt), .staged)
        }
    }
    func testPublishedTreeDoesNotAcceptDifferentDirectoryOrChangedJournal() throws {
        for replaceRoot in [false, true] {
            let f = try fixture(), receipt = try f.stage()
            try f.publisher.publish(receipt)
            let root = f.url.appendingPathComponent("destination/Claude Router")
            if replaceRoot {
                try FileManager.default.moveItem(at: root, to: f.url.appendingPathComponent("preserved-root"))
                try FileManager.default.copyItem(at: f.url.appendingPathComponent("preserved-root"), to: root)
            } else {
                try Data("later journal".utf8).write(to: root.appendingPathComponent("state/journal.json"))
            }
            XCTAssertThrowsError(try f.publisher.publish(receipt))
        }
    }
    func testEveryInitialFileAndDirectoryIdentityMustRemainOwned() throws {
        for leaf in ["bin/router-system-helper", "core/mihomo", "install-manifest.json", "package-receipt.json",
                     "state/journal.json", "state/journal.lock", "state/operation.lock", "bin", "core", "run", "state"] {
            let f = try fixture(), receipt = try f.stage()
            let path = f.url.appendingPathComponent("transaction/root.publish/" + leaf)
            let preserved = f.url.appendingPathComponent("preserved")
            try FileManager.default.moveItem(at: path, to: preserved)
            try FileManager.default.copyItem(at: preserved, to: path)
            XCTAssertThrowsError(try f.publisher.publish(receipt), leaf)
            XCTAssertEqual(try f.publisher.position(receipt), .staged)
        }
    }
    func testUnknownRunEntryChangedHostLockAndPermissionChangesAreNotInitialTree() throws {
        for leaf in ["run/foreign", "state/host.lock", "state/operation.lock"] {
            let f = try fixture(), receipt = try f.stage()
            try f.publisher.publish(receipt)
            let path = f.url.appendingPathComponent("destination/Claude Router/" + leaf)
            if leaf.hasSuffix("operation.lock") { XCTAssertEqual(chmod(path.path, 0o644), 0) }
            else { try Data("changed".utf8).write(to: path) }
            XCTAssertThrowsError(try f.publisher.publish(receipt))
        }
    }
}
