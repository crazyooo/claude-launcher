import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemInstallerEntryTests: XCTestCase {
    func testRequestOnlyAcceptsExactBoundedVerbsAndFields() throws {
        let id = UUID().uuidString.lowercased()
        let args = ["preview", "--action", "install", "--uid", "501", "--id", id]
        let request = try RouterSystemInstallerRequest.parse(args)
        XCTAssertEqual(request.id.uuidString.lowercased(), id)
        XCTAssertEqual(request.action, .install); XCTAssertNil(request.confirm)
        XCTAssertEqual(try RouterSystemInstallerRequest.parse(["resume-preview"] + args.dropFirst()).verb, .resumePreview)
        XCTAssertEqual(try RouterSystemInstallerRequest.parse(["resume-apply"] + args.dropFirst() + ["--confirm", String(repeating: "a", count: 64)]).verb, .resumeApply)
        XCTAssertThrowsError(try RouterSystemInstallerRequest.parse(["resume-apply"] + args.dropFirst()))
        XCTAssertEqual(try RouterSystemInstallerRequest.parse(["apply"] + args.dropFirst() + ["--confirm", String(repeating: "a", count: 64)]).verb, .apply)
        for invalid in [Array(args.dropLast()), args + ["--config", "/tmp/anything"], args + ["--uid", "501"],
                        ["apply"] + args.dropFirst(), ["delete"] + args.dropFirst(),
                        args.map { $0 == "501" ? "0501" : $0 }, args.map { $0 == "501" ? "0" : $0 },
                        args.map { $0 == id ? "../" + id : $0 }, args.map { $0 == "install" ? "install\0" : $0 }] {
            XCTAssertThrowsError(try RouterSystemInstallerRequest.parse(invalid))
        }
    }
    func testNativeEntryCannotRunWithoutRoot() throws {
        XCTAssertNotEqual(geteuid(), 0)
        XCTAssertThrowsError(try RouterSystemInstaller.run(arguments: [], packageID: UUID(), helperSHA256: String(repeating: "a", count: 64)))
    }
    func testPayloadReaderRejectsChangedBytesModesLinksAndUnexpectedNames() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("router-package-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let file = folder.appendingPathComponent("router-system-helper"), bytes = Data("fixed helper bytes".utf8)
        try bytes.write(to: file); XCTAssertEqual(chmod(file.path, 0o755), 0)
        let fd = open(folder.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        let digest = RouterSystemObservation.hash(bytes)
        func read(_ name: String = "router-system-helper") throws -> Data {
            try RouterSystemInstallerPayload.file(name, directoryFD: fd, ownerUID: getuid(), digest: digest)
        }
        XCTAssertEqual(try read(), bytes)
        XCTAssertThrowsError(try read("../router-system-helper"))
        XCTAssertThrowsError(try RouterSystemInstallerPayload.file("router-system-helper", directoryFD: fd, ownerUID: getuid(), digest: String(repeating: "b", count: 64)))
        XCTAssertEqual(chmod(file.path, 0o777), 0); XCTAssertThrowsError(try read())
        XCTAssertEqual(chmod(file.path, 0o755), 0)
        let hardlink = folder.appendingPathComponent("hardlink")
        XCTAssertEqual(link(file.path, hardlink.path), 0); XCTAssertThrowsError(try read())
        // Preserve both original hardlinks and replace the expected name by a symlink.
        try FileManager.default.moveItem(at: file, to: folder.appendingPathComponent("preserved-helper"))
        XCTAssertEqual(symlink(hardlink.path, file.path), 0); XCTAssertThrowsError(try read())
    }
    func testPackageReceiptRequiresTheLockProtocolAndExactManifest() throws {
        let manifest = RouterSystemInstallManifest(version: 1, installationID: UUID(), ownerUID: 501,
            helperSHA256: String(repeating: "a", count: 64), coreVersion: RouterCoreRelease.version, coreSHA256: RouterCoreRelease.executableSHA256)
        func receipt(_ protocolVersion: Int, owner: UInt32 = 501) -> RouterSystemInstallPackageReceipt {
            .init(version: 1, packageID: UUID(), installationID: manifest.installationID, ownerUID: owner,
                helperSHA256: manifest.helperSHA256, coreVersion: manifest.coreVersion, coreSHA256: manifest.coreSHA256, operationLockProtocol: protocolVersion)
        }
        XCTAssertTrue(receipt(1).matches(manifest))
        XCTAssertFalse(receipt(0).matches(manifest))
        XCTAssertFalse(receipt(1, owner: 502).matches(manifest))
    }
}
