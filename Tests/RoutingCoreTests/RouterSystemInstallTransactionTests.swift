import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallTransactionTests: XCTestCase {
    private let old = Data("old payload".utf8), new = Data("new payload".utf8)
    private func fixture() throws -> (URL, RouterSystemDirectory, RouterSystemDirectory) {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-install-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        let root = try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid())
        return (url, try root.createDirectory("transaction"), try root.createDirectory("target"))
    }
    func testAllFiveFilesInstallUpgradeRetirePreserveOldInodeAndReplay() throws {
        for file in RouterSystemInstallFile.allCases {
            for previous: Data? in [nil, old, new] {
                for next: Data? in [nil, new] where previous != nil || next != nil {
                    let (url, transaction, target) = try fixture()
                    if let previous {
                        try previous.write(to: url.appendingPathComponent("target/" + file.leaf))
                        XCTAssertEqual(chmod(url.appendingPathComponent("target/" + file.leaf).path, file.mode), 0)
                    }
                    let id = UUID(), installer = RouterSystemInstallTransaction(directory: transaction, id: id)
                    let receipt = try installer.stage(file, new: next, target: target)
                    try installer.publish(receipt, target: target)
                    let reopened = RouterSystemInstallTransaction(directory: transaction, id: id)
                    XCTAssertEqual(try reopened.load(file, target: target), receipt)
                    try reopened.publish(receipt, target: target)
                    XCTAssertEqual(try target.read(file.leaf, maximum: 100, mode: file.mode), next)
                    XCTAssertEqual(try transaction.read(file.receiptLeaf("retired"), maximum: 100, mode: file.mode), previous)
                    XCTAssertNil(try transaction.read(file.receiptLeaf("publish"), maximum: 100, mode: file.mode))
                }
            }
        }
    }
    func testEveryPublicationBoundaryIsResumableForInstallUpgradeAndRetire() throws {
        for point in RouterSystemInstallTransaction.Boundary.allCases where [.beforeArchive, .archived, .archiveSynced, .beforePublish, .published, .publicationSynced].contains(point) {
            for (before, after): (Data?, Data?) in [(nil, new), (old, new), (old, nil)] {
                let (_, directory, target) = try fixture()
                if let before { try target.create("install-manifest.json", data: before) }
                let id = UUID(), stable = RouterSystemInstallTransaction(directory: directory, id: id)
                let receipt = try stable.stage(.manifest, new: after, target: target)
                var reached = false
                let interrupted = RouterSystemInstallTransaction(directory: directory, id: id, boundary: {
                    if $0 == point { reached = true; throw RouterSystemError.operationUnsettled }
                })
                let applies = point == .publicationSynced ||
                    (before != nil && [.beforeArchive, .archived, .archiveSynced].contains(point)) ||
                    (after != nil && [.beforePublish, .published].contains(point))
                if applies { XCTAssertThrowsError(try interrupted.publish(receipt, target: target)) }
                else { XCTAssertNoThrow(try interrupted.publish(receipt, target: target)) }
                XCTAssertEqual(reached, applies)
                let resumed = RouterSystemInstallTransaction(directory: directory, id: id)
                try resumed.publish(receipt, target: target)
                XCTAssertEqual(try target.read("install-manifest.json", maximum: 100), after)
            }
        }
    }
    func testAllFsyncFailuresAfterStageCanResumeWithoutLosingHistory() throws {
        // Sweep every synchronization call, including evidence re-syncs and both rename parents.
        let (_, sampleDirectory, sampleTarget) = try fixture(), sampleID = UUID()
        try sampleTarget.create("install-manifest.json", data: old)
        let sample = RouterSystemInstallTransaction(directory: sampleDirectory, id: sampleID)
        let sampleReceipt = try sample.stage(.manifest, new: new, target: sampleTarget)
        var total = 0
        try RouterSystemInstallTransaction(directory: sampleDirectory, id: sampleID, synchronize: {
            total += 1; return fsync($0)
        }).publish(sampleReceipt, target: sampleTarget)
        XCTAssertGreaterThan(total, 0)
        for failAt in 1...total {
            let (_, directory, target) = try fixture(), id = UUID()
            try target.create("install-manifest.json", data: old)
            let stable = RouterSystemInstallTransaction(directory: directory, id: id)
            let receipt = try stable.stage(.manifest, new: new, target: target)
            var count = 0
            let faulty = RouterSystemInstallTransaction(directory: directory, id: id, synchronize: {
                count += 1; return count == failAt ? -1 : fsync($0)
            })
            XCTAssertThrowsError(try faulty.publish(receipt, target: target))
            XCTAssertEqual(count, failAt)
            try stable.publish(receipt, target: target)
            XCTAssertEqual(try target.read("install-manifest.json", maximum: 100), new)
            XCTAssertEqual(try directory.read("manifest.retired", maximum: 100), old)
        }
    }
    func testPartialStagingIsPreservedAndCannotBeAdopted() throws {
        for point in [RouterSystemInstallTransaction.Boundary.beforeCopySaved, .afterCopySaved, .stagedFileSaved] {
            let (_, directory, target) = try fixture(), id = UUID()
            try target.create("install-manifest.json", data: old)
            let faulty = RouterSystemInstallTransaction(directory: directory, id: id, boundary: {
                if $0 == point { throw RouterSystemError.operationUnsettled }
            })
            XCTAssertThrowsError(try faulty.stage(.manifest, new: new, target: target))
            let stable = RouterSystemInstallTransaction(directory: directory, id: id)
            XCTAssertThrowsError(try stable.stage(.manifest, new: new, target: target))
            XCTAssertThrowsError(try stable.load(.manifest, target: target))
            XCTAssertEqual(try target.read("install-manifest.json", maximum: 100), old)
            XCTAssertEqual(try directory.read("manifest.before", maximum: 100), old)
        }
    }
    func testReceiptWriteBeforeReportedSuccessIsRecoverable() throws {
        let (_, directory, target) = try fixture(), id = UUID()
        let faulty = RouterSystemInstallTransaction(directory: directory, id: id, boundary: {
            if $0 == .receiptSaved { throw RouterSystemError.operationUnsettled }
        })
        XCTAssertThrowsError(try faulty.stage(.manifest, new: new, target: target))
        let stable = RouterSystemInstallTransaction(directory: directory, id: id)
        try stable.publish(stable.load(.manifest, target: target), target: target)
        XCTAssertEqual(try target.read("install-manifest.json", maximum: 100), new)
    }
    func testSameBytesForeignTargetStagedOrArchiveInodeRejected() throws {
        for leaf in ["target/install-manifest.json", "transaction/manifest.publish", "transaction/manifest.retired"] {
            let (url, directory, target) = try fixture(), id = UUID()
            try target.create("install-manifest.json", data: old)
            let stable = RouterSystemInstallTransaction(directory: directory, id: id)
            let receipt = try stable.stage(.manifest, new: new, target: target)
            if leaf.hasSuffix("retired") { try stable.publish(receipt, target: target) }
            let file = url.appendingPathComponent(leaf), bytes = try Data(contentsOf: file)
            try FileManager.default.moveItem(at: file, to: file.appendingPathExtension("preserved"))
            try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
            XCTAssertThrowsError(try stable.publish(receipt, target: target))
            XCTAssertEqual(try Data(contentsOf: file), bytes)
        }
    }
    func testPublishedSameBytesReplacementAndForeignDestinationArePreserved() throws {
        let (url, directory, target) = try fixture(), id = UUID()
        let stable = RouterSystemInstallTransaction(directory: directory, id: id)
        let receipt = try stable.stage(.manifest, new: new, target: target)
        try stable.publish(receipt, target: target)
        let file = url.appendingPathComponent("target/install-manifest.json")
        try FileManager.default.moveItem(at: file, to: file.appendingPathExtension("owned"))
        try target.create("install-manifest.json", data: new)
        XCTAssertThrowsError(try stable.publish(receipt, target: target))
        XCTAssertEqual(try Data(contentsOf: file.appendingPathExtension("owned")), new)
    }
    func testLateDestinationAndArchiveConflictsNeverOverwrite() throws {
        for point in [RouterSystemInstallTransaction.Boundary.beforeArchive, .beforePublish] {
            let (_, directory, target) = try fixture(), id = UUID()
            try target.create("install-manifest.json", data: old)
            let stable = RouterSystemInstallTransaction(directory: directory, id: id)
            let receipt = try stable.stage(.manifest, new: new, target: target)
            let conflicting = RouterSystemInstallTransaction(directory: directory, id: id, boundary: {
                if $0 == point {
                    if point == .beforeArchive { try directory.create("manifest.retired", data: Data("foreign".utf8)) }
                    else { try target.create("install-manifest.json", data: Data("foreign".utf8)) }
                }
            })
            XCTAssertThrowsError(try conflicting.publish(receipt, target: target))
            let actual = point == .beforeArchive ? try directory.read("manifest.retired", maximum: 100) : try target.read("install-manifest.json", maximum: 100)
            XCTAssertEqual(actual, Data("foreign".utf8))
        }
    }
    func testTransactionTargetAndReceiptBindingsRejectForeignInputs() throws {
        let (_, directory, target) = try fixture(), id = UUID()
        let stable = RouterSystemInstallTransaction(directory: directory, id: id)
        let receipt = try stable.stage(.manifest, new: new, target: target)
        XCTAssertThrowsError(try RouterSystemInstallTransaction(directory: directory, id: UUID()).publish(receipt, target: target))
        let (_, _, other) = try fixture()
        XCTAssertThrowsError(try stable.publish(receipt, target: other))
        let bytes = try receipt.encoded()
        XCTAssertThrowsError(try RouterSystemInstallFileReceipt.decode(bytes + Data([10])))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        object["extra"] = true
        XCTAssertThrowsError(try RouterSystemInstallFileReceipt.decode(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])))
        XCTAssertThrowsError(try directory.create("ordinary-public", data: new, mode: 0o644))
    }
    func testStagingCannotAdoptSameBytesReplacementBeforeReceipt() throws {
        let (url, directory, target) = try fixture()
        let payload = new
        let installer = RouterSystemInstallTransaction(directory: directory, id: UUID(), boundary: {
            if $0 == .stagedFileSaved {
                let file = url.appendingPathComponent("transaction/manifest.publish")
                try FileManager.default.moveItem(at: file, to: file.appendingPathExtension("preserved"))
                try directory.create("manifest.publish", data: payload)
            }
        })
        XCTAssertThrowsError(try installer.stage(.manifest, new: new, target: target))
        XCTAssertNil(try directory.read("manifest.receipt", maximum: 8192))
        XCTAssertNil(try target.read("install-manifest.json", maximum: 100))
    }
    func testReplacedDirectoriesAndTamperedReceiptEvidenceRejectResume() throws {
        for name in ["target", "transaction"] {
            let (url, directory, target) = try fixture(), id = UUID()
            let installer = RouterSystemInstallTransaction(directory: directory, id: id)
            let receipt = try installer.stage(.manifest, new: new, target: target)
            let path = url.appendingPathComponent(name)
            try FileManager.default.moveItem(at: path, to: path.appendingPathExtension("preserved"))
            try FileManager.default.createDirectory(at: path, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
            XCTAssertThrowsError(try installer.publish(receipt, target: target))
        }
        let (url, directory, target) = try fixture(), id = UUID()
        let installer = RouterSystemInstallTransaction(directory: directory, id: id)
        let receipt = try installer.stage(.manifest, new: new, target: target)
        try old.write(to: url.appendingPathComponent("transaction/manifest.after"))
        XCTAssertThrowsError(try installer.publish(receipt, target: target))
        XCTAssertNil(try target.read("install-manifest.json", maximum: 100))
    }
}
