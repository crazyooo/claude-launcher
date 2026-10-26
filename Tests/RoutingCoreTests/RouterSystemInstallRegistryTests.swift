import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallRegistryTests: XCTestCase {
    private struct Fixture {
        let url: URL
        let root: RouterSystemDirectory
        let transaction: RouterSystemDirectory
        let active: RouterSystemInstallActive
        var registry: RouterSystemInstallRegistry { .init(registry: root, transaction: transaction) }
        var completion: RouterSystemInstallCompletion {
            .init(version: 1, active: active, proofDigest: String(repeating: "c", count: 64))
        }
    }
    private func fixture() throws -> Fixture {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("router-install-registry-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        let root = try RouterSystemDirectory.fixture(directoryFD: fd, owner: getuid())
        return try make(root: root, url: url, name: "transaction")
    }
    private func make(root: RouterSystemDirectory, url: URL, name: String) throws -> Fixture {
        let transaction = try root.createDirectory(name), plan = Data(#"{"version":1,"fixture":true}"#.utf8)
        try transaction.create("plan.json", data: plan)
        let active = RouterSystemInstallActive(version: 1, transaction: UUID(), action: .install,
            planDigest: RouterSystemObservation.hash(plan), packageID: UUID(), helperDigest: String(repeating: "a", count: 64),
            installationID: UUID(), ownerUID: 501, transactionDirectory: try .directory(transaction))
        return .init(url: url, root: root, transaction: transaction, active: active)
    }
    func testClaimResumeCompleteAndNewTransactionDoNotReplayOldWork() throws {
        let f = try fixture(), registry = f.registry
        try registry.prepare(f.active)
        XCTAssertEqual(try registry.inspect(f.active), .prepared)
        XCTAssertEqual(try registry.claim(f.active), .active)
        XCTAssertEqual(try f.registry.claim(f.active), .active)
        try registry.finish(f.completion)
        XCTAssertEqual(try registry.inspect(f.active), .closed(f.completion))
        let next = try make(root: f.root, url: f.url, name: "next")
        try next.registry.prepare(next.active)
        XCTAssertEqual(try next.registry.claim(next.active), .active)
        let marker = try f.root.read("active.json", maximum: 8192)
        XCTAssertEqual(try registry.claim(f.active), .closed(f.completion))
        try registry.finish(f.completion)
        XCTAssertEqual(try f.root.read("active.json", maximum: 8192), marker)
    }
    func testDifferentTransactionCannotClaimAbandonedActiveMarker() throws {
        let f = try fixture()
        try f.registry.prepare(f.active)
        _ = try f.registry.claim(f.active)
        let next = try make(root: f.root, url: f.url, name: "next")
        XCTAssertThrowsError(try next.registry.prepare(next.active))
        XCTAssertEqual(try f.registry.inspect(f.active), .active)
        XCTAssertNil(try next.transaction.read("active.publish", maximum: 8192))
    }
    func testEveryDurableBoundaryHasExplicitResumeOrPreservedPartialState() throws {
        for point in RouterSystemInstallRegistry.Boundary.allCases {
            let f = try fixture()
            var reached = false
            let faulty = RouterSystemInstallRegistry(registry: f.root, transaction: f.transaction, boundary: {
                if $0 == point { reached = true; throw RouterSystemError.operationUnsettled }
            })
            if [.staged, .sealed].contains(point) {
                XCTAssertThrowsError(try faulty.prepare(f.active))
                if point == .staged {
                    XCTAssertThrowsError(try f.registry.prepare(f.active))
                    XCTAssertThrowsError(try f.registry.claim(f.active))
                    XCTAssertNil(try f.root.read("active.json", maximum: 8192))
                } else { XCTAssertEqual(try f.registry.claim(f.active), .active) }
            } else {
                try f.registry.prepare(f.active)
                if point == .claimed { XCTAssertThrowsError(try faulty.claim(f.active)) }
                else {
                    _ = try f.registry.claim(f.active)
                    XCTAssertThrowsError(try faulty.finish(f.completion))
                }
                XCTAssertNotEqual(try f.registry.claim(f.active), .prepared)
                try f.registry.finish(f.completion)
                XCTAssertEqual(try f.registry.inspect(f.active), .closed(f.completion))
            }
            XCTAssertTrue(reached)
        }
    }
    func testClaimAndCompletionSynchronizationFailuresCanResume() throws {
        for finishing in [false, true] {
            let sample = try fixture()
            try sample.registry.prepare(sample.active)
            if finishing { _ = try sample.registry.claim(sample.active) }
            var total = 0
            let counting = RouterSystemInstallRegistry(registry: sample.root, transaction: sample.transaction, synchronize: {
                total += 1; return fsync($0)
            })
            if finishing { try counting.finish(sample.completion) } else { _ = try counting.claim(sample.active) }
            XCTAssertGreaterThan(total, 0)
            for failAt in 1...total {
                let f = try fixture()
                try f.registry.prepare(f.active)
                if finishing { _ = try f.registry.claim(f.active) }
                var count = 0
                let faulty = RouterSystemInstallRegistry(registry: f.root, transaction: f.transaction, synchronize: {
                    count += 1; return count == failAt ? -1 : fsync($0)
                })
                if finishing { XCTAssertThrowsError(try faulty.finish(f.completion)) }
                else { XCTAssertThrowsError(try faulty.claim(f.active)) }
                XCTAssertEqual(count, failAt)
                _ = try f.registry.claim(f.active)
                try f.registry.finish(f.completion)
                XCTAssertEqual(try f.registry.inspect(f.active), .closed(f.completion))
            }
        }
    }
    func testSameBytesReplacedMarkerIsNotOwnedBeforeOrAfterClaim() throws {
        for claimed in [false, true] {
            let f = try fixture()
            try f.registry.prepare(f.active)
            if claimed { _ = try f.registry.claim(f.active) }
            let leaf = claimed ? "active.json" : "transaction/active.publish"
            let file = f.url.appendingPathComponent(leaf), bytes = try Data(contentsOf: file)
            try FileManager.default.moveItem(at: file, to: file.appendingPathExtension("preserved"))
            try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o600), 0)
            XCTAssertThrowsError(try f.registry.claim(f.active))
            XCTAssertThrowsError(try f.registry.finish(f.completion))
        }
    }
    func testPreSealStagedReplacementAndChangedPlanAreRejected() throws {
        let f = try fixture()
        let faulty = RouterSystemInstallRegistry(registry: f.root, transaction: f.transaction, boundary: {
            if $0 == .staged {
                let file = f.url.appendingPathComponent("transaction/active.publish"), bytes = try Data(contentsOf: file)
                try FileManager.default.moveItem(at: file, to: file.appendingPathExtension("preserved"))
                try f.transaction.create("active.publish", data: bytes)
            }
        })
        XCTAssertThrowsError(try faulty.prepare(f.active))
        XCTAssertNil(try f.transaction.read("active.receipt", maximum: 16384))
        let other = try fixture()
        try other.registry.prepare(other.active)
        try Data("changed".utf8).write(to: other.url.appendingPathComponent("transaction/plan.json"))
        XCTAssertThrowsError(try other.registry.claim(other.active))
    }
    func testClosedRequiresValidCompletionAndCannotAcceptChangedProof() throws {
        let f = try fixture()
        try f.registry.prepare(f.active)
        XCTAssertThrowsError(try f.registry.finish(f.completion))
        _ = try f.registry.claim(f.active)
        try f.registry.finish(f.completion)
        let changed = RouterSystemInstallCompletion(version: 1, active: f.active, proofDigest: String(repeating: "d", count: 64))
        XCTAssertThrowsError(try f.registry.finish(changed))
        try Data("corrupt".utf8).write(to: f.url.appendingPathComponent("transaction/complete.json"))
        XCTAssertThrowsError(try f.registry.inspect(f.active))
        XCTAssertThrowsError(try f.registry.claim(f.active))
    }
    func testForeignMarkerAndUnknownRecordFieldsArePreserved() throws {
        let f = try fixture()
        try f.root.create("active.json", data: Data("partial".utf8))
        XCTAssertThrowsError(try f.registry.prepare(f.active))
        XCTAssertEqual(try f.root.read("active.json", maximum: 100), Data("partial".utf8))
        let bytes = try f.active.encoded()
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: bytes) as? [String: Any])
        for (key, value): (String, Any) in [("unexpected", true), ("ownerUID", 0), ("version", true)] {
            var invalid = object; invalid[key] = value
            XCTAssertThrowsError(try RouterSystemInstallActive.decode(JSONSerialization.data(withJSONObject: invalid, options: [.sortedKeys])))
        }
        object["planDigest"] = NSNull()
        XCTAssertThrowsError(try RouterSystemInstallActive.decode(JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])))
    }
    func testPendingCompletionIsReadableAndKeepsOriginalProofOnResume() throws {
        let f = try fixture()
        try f.registry.prepare(f.active)
        XCTAssertNil(try f.registry.pendingCompletion(f.active))
        _ = try f.registry.claim(f.active)
        let interrupted = RouterSystemInstallRegistry(registry: f.root, transaction: f.transaction, boundary: {
            if $0 == .completed { throw RouterSystemError.operationUnsettled }
        })
        XCTAssertThrowsError(try interrupted.finish(f.completion))
        XCTAssertEqual(try f.registry.pendingCompletion(f.active), f.completion)
        let different = RouterSystemInstallCompletion(version: 1, active: f.active, proofDigest: String(repeating: "d", count: 64))
        XCTAssertThrowsError(try f.registry.finish(different))
        XCTAssertEqual(try f.registry.inspect(f.active), .active)
        try f.registry.finish(XCTUnwrap(f.registry.pendingCompletion(f.active)))
        XCTAssertEqual(try f.registry.pendingCompletion(f.active), f.completion)
    }
}
