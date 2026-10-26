import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemHostResourceTests: XCTestCase {
    private func directory() throws -> (URL, RouterSystemDirectory) {
        let url = URL(fileURLWithPath: "/private/tmp/clr-" + UUID().uuidString.lowercased())
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        // /private/tmp inherits wheel; make this user fixture's group explicit.
        guard chown(url.path, uid_t.max, getgid()) == 0 else { throw RouterSystemError.ownershipUnknown }
        let fd = open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(fd) }
        return (url, try .fixture(directoryFD: fd, owner: getuid()))
    }

    private func listener(at path: URL, listening: Bool = true) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw RouterSystemError.operationUnsettled }
        do {
            let bytes = Array(path.path.utf8) + [UInt8(0)]
            var address = sockaddr_un()
            guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw RouterSystemError.invalidRequest }
            address.sun_family = sa_family_t(AF_UNIX)
            address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
            withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
            let bound = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
                }
            }
            guard bound == 0, chown(path.path, uid_t.max, getgid()) == 0, chmod(path.path, 0o600) == 0,
                  !listening || listen(fd, 2) == 0 else { throw RouterSystemError.operationUnsettled }
            return fd
        } catch { close(fd); throw error }
    }

    private func declaration() throws -> (URL, RouterSystemDirectory) {
        let (url, directory) = try directory()
        let path = url.appendingPathComponent(RouterSystemInstallFile.launchd.leaf)
        try RouterSystemInstallPlist.bytes(ownerUID: getuid()).write(to: path)
        guard chmod(path.path, 0o644) == 0 else { throw RouterSystemError.ownershipUnknown }
        return (path, directory)
    }

    func testPublicationMayBeInitiallyAbsentOrReplacedDuringActivation() throws {
        for retained in [false, true] {
            let (url, directory) = try directory(), (_, declarations) = try declaration()
            let path = url.appendingPathComponent("control.sock")
            var old = stat()
            if retained {
                close(try listener(at: path))
                XCTAssertEqual(lstat(path.path, &old), 0)
            } else { XCTAssertFalse(FileManager.default.fileExists(atPath: path.path)) }
            var owned: Int32 = -1, activations = 0
            try RouterSystemActivatedSocket.fixturePublication(directory: directory, declarations: declarations, activate: {
                activations += 1
                if retained {
                    try FileManager.default.moveItem(at: path, to: url.appendingPathComponent("residual.preserved"))
                }
                owned = try self.listener(at: path)
                return owned
            })
            XCTAssertEqual(activations, 1)
            errno = 0
            XCTAssertEqual(fcntl(owned, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
            var current = stat()
            XCTAssertEqual(lstat(path.path, &current), 0)
            if retained {
                XCTAssertNotEqual(current.st_ino, old.st_ino)
                XCTAssertTrue(FileManager.default.fileExists(atPath: url.appendingPathComponent("residual.preserved").path))
            }
        }
    }

    func testPublicationStillRejectsNodeReplacementAfterItsFirstSnapshot() throws {
        let (url, directory) = try directory(), (_, declarations) = try declaration()
        let path = url.appendingPathComponent("control.sock")
        var owned: Int32 = -1, replacement: Int32 = -1
        defer { if replacement >= 0 { close(replacement) } }
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixturePublication(
            directory: directory, declarations: declarations, activate: {
                owned = try self.listener(at: path); return owned
            }, afterSnapshot: {
                try FileManager.default.moveItem(at: path, to: url.appendingPathComponent("active.preserved"))
                replacement = try self.listener(at: path)
            })) { XCTAssertEqual($0 as? RouterSystemError, .ownershipUnknown) }
        errno = 0
        XCTAssertEqual(fcntl(owned, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
    }

    func testPublicationRejectsInvalidPostActivationNodesAndClosesDescriptor() throws {
        for kind in ["missing", "mode", "symlink", "regular", "not_listening"] {
            let (url, directory) = try directory(), (_, declarations) = try declaration()
            let path = url.appendingPathComponent("control.sock")
            var owned: Int32 = -1
            XCTAssertThrowsError(try RouterSystemActivatedSocket.fixturePublication(
                directory: directory, declarations: declarations, activate: {
                    let fd = try self.listener(at: path, listening: kind != "not_listening")
                    do {
                        if kind == "mode" { guard chmod(path.path, 0o666) == 0 else { throw RouterSystemError.ownershipUnknown } }
                        if ["missing", "symlink", "regular"].contains(kind) {
                            let preserved = url.appendingPathComponent("node.preserved")
                            try FileManager.default.moveItem(at: path, to: preserved)
                            if kind == "symlink" { try FileManager.default.createSymbolicLink(at: path, withDestinationURL: preserved) }
                            if kind == "regular" { try Data().write(to: path) }
                        }
                        owned = fd; return fd
                    } catch { close(fd); throw error }
                }))
            XCTAssertGreaterThanOrEqual(owned, 0)
            errno = 0
            XCTAssertEqual(fcntl(owned, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
        }
    }

    func testPublicationRejectsDeclarationChangesBeforeAndAfterActivation() throws {
        for phase in ["before", "activation", "after_snapshot"] {
            let (url, directory) = try directory(), (plist, declarations) = try declaration()
            let canonical = try Data(contentsOf: plist)
            var activations = 0, owned: Int32 = -1
            if phase == "before" { try Data("invalid".utf8).write(to: plist) }
            XCTAssertThrowsError(try RouterSystemActivatedSocket.fixturePublication(
                directory: directory, declarations: declarations, activate: {
                    activations += 1
                    if phase == "activation" {
                        try RouterSystemInstallPlist.bytes(ownerUID: getuid() + 1).write(to: plist)
                    }
                    owned = try self.listener(at: url.appendingPathComponent("control.sock")); return owned
                }, afterSnapshot: {
                    if phase == "after_snapshot" {
                        // Equal contents on a different inode must still be rejected.
                        try FileManager.default.moveItem(at: plist, to: plist.appendingPathExtension("preserved"))
                        try canonical.write(to: plist); XCTAssertEqual(chmod(plist.path, 0o644), 0)
                    }
                }))
            XCTAssertEqual(activations, phase == "before" ? 0 : 1)
            if owned >= 0 {
                errno = 0
                XCTAssertEqual(fcntl(owned, F_GETFD), -1); XCTAssertEqual(errno, EBADF)
            }
        }
    }

    func testPublicationDoesNotRetryFailedActivation() throws {
        let (_, directory) = try directory(), (_, declarations) = try declaration()
        let original = NSError(domain: "fixture", code: 7)
        var activations = 0, observations = 0
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixturePublication(
            directory: directory, declarations: declarations, activate: {
                activations += 1; throw original
            }, afterSnapshot: { observations += 1 })) {
                XCTAssertTrue(($0 as NSError) === original)
            }
        XCTAssertEqual(activations, 1); XCTAssertEqual(observations, 0)
    }
    func testLeaseExclusiveUntilReleasedAndNeverDeletesItsFile() throws {
        let (url, directory) = try directory()
        var first: RouterSystemHostLease? = try .acquire(in: directory)
        try first?.verify()
        XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: directory))
        first = nil
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.appendingPathComponent("host.lock").path))
        let next = try RouterSystemHostLease.acquire(in: directory)
        try next.verify()
        let moved = url.appendingPathComponent("old-host.lock")
        try FileManager.default.moveItem(at: url.appendingPathComponent("host.lock"), to: moved)
        XCTAssertThrowsError(try next.verify())
    }
    func testDistinctLeasePurposesDoNotAliasAndMaintenanceFilesRemain() throws {
        let (url, directory) = try directory()
        let host = try RouterSystemHostLease.acquire(in: directory)
        let installer = try RouterSystemHostLease.acquire(in: directory, purpose: .installer)
        let operation = try RouterSystemHostLease.acquire(in: directory, purpose: .operation)
        try host.verify(); try installer.verify(); try operation.verify()
        XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: directory, purpose: .installer))
        XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: directory, purpose: .operation))
        for name in ["host.lock", "installer.lock", "operation.lock"] {
            XCTAssertTrue(FileManager.default.fileExists(atPath: url.appendingPathComponent(name).path))
        }
    }

    func testOperationLeaseExcludesAnotherProcessAndReleasesWithoutDeleting() throws {
        let (url, directory) = try directory()
        func attemptFromChild() throws -> Int32 {
            let child = Process()
            child.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            child.arguments = ["-I", "-B", "-c", "import os,sys,fcntl\nf=os.open(sys.argv[1],os.O_RDWR)\ntry: fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)\nexcept BlockingIOError: sys.exit(23)\nos.close(f)",
                url.appendingPathComponent("operation.lock").path]
            child.standardInput = FileHandle.nullDevice; child.standardOutput = FileHandle.nullDevice
            child.standardError = FileHandle.nullDevice
            try child.run(); child.waitUntilExit()
            return child.terminationStatus
        }
        var held: RouterSystemHostLease? = try .acquire(in: directory, purpose: .operation)
        XCTAssertEqual(try withExtendedLifetime(held) { try attemptFromChild() }, 23)
        held = nil
        XCTAssertEqual(try attemptFromChild(), 0)
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.appendingPathComponent("operation.lock").path))
    }

    func testLeaseRejectsSymlinkContentsAndPermissions() throws {
        for kind in 0..<3 {
            let (url, directory) = try directory(), path = url.appendingPathComponent("host.lock")
            if kind == 0 { try FileManager.default.createSymbolicLink(at: path, withDestinationURL: URL(fileURLWithPath: "/dev/null")) }
            else {
                XCTAssertTrue(FileManager.default.createFile(atPath: path.path, contents: kind == 1 ? Data("unknown".utf8) : Data(),
                    attributes: [.posixPermissions: kind == 1 ? 0o600 : 0o644]))
            }
            XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: directory))
        }
    }
    func testActivatedSocketValidationUsesLiveUnixListenerAndOwnedNode() throws {
        let (url, directory) = try directory(), path = url.appendingPathComponent("control.sock").path
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return XCTFail("socket failed") }; defer { close(fd) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        XCTAssertEqual(withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }, 0)
        XCTAssertEqual(chmod(path, 0o600), 0)
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: path))
        XCTAssertEqual(listen(fd, 1), 0)
        XCTAssertNoThrow(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: path))
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: path + "x"))
        XCTAssertEqual(chmod(path, 0o666), 0)
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: path))
        XCTAssertEqual(chmod(path, 0o600), 0)
        try FileManager.default.moveItem(atPath: path, toPath: path + ".old")
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: path))
    }
    func testPublishedListenerAcceptsRenameButRequiresDeclarationAndOwnedNode() throws {
        let (url, directory) = try directory()
        let (declarationsURL, declarations) = try self.directory()
        let plistURL = declarationsURL.appendingPathComponent(RouterSystemInstallFile.launchd.leaf)
        let canonical = try RouterSystemInstallPlist.bytes(ownerUID: getuid())
        try canonical.write(to: plistURL); XCTAssertEqual(chmod(plistURL.path, 0o644), 0)
        let initial = url.appendingPathComponent("bound.sock").path
        let published = url.appendingPathComponent("control.sock").path
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return XCTFail("socket failed") }; defer { close(fd) }
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array(initial.utf8) + [0]) }
        XCTAssertEqual(withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }, 0)
        XCTAssertEqual(chmod(initial, 0o600), 0)
        try FileManager.default.moveItem(atPath: initial, toPath: published)
        func validate() throws {
            try RouterSystemActivatedSocket.fixtureVerifyPublishedListener(fd, directory: directory, declarations: declarations)
        }
        XCTAssertThrowsError(try validate()) // Bound but not listening.
        XCTAssertEqual(listen(fd, 1), 0)
        XCTAssertThrowsError(try RouterSystemActivatedSocket.fixtureVerify(fd, directory: directory, path: published))
        XCTAssertNoThrow(try validate()) // The kernel still reports bound.sock after rename.
        try RouterSystemInstallPlist.bytes(ownerUID: getuid() + 1).write(to: plistURL)
        XCTAssertThrowsError(try validate())
        try canonical.write(to: plistURL)
        XCTAssertEqual(chmod(plistURL.path, 0o666), 0); XCTAssertThrowsError(try validate())
        XCTAssertEqual(chmod(plistURL.path, 0o644), 0); XCTAssertNoThrow(try validate())
        XCTAssertEqual(chmod(published, 0o666), 0); XCTAssertThrowsError(try validate())
        XCTAssertEqual(chmod(published, 0o600), 0)
        try FileManager.default.moveItem(atPath: published, toPath: published + ".preserved")
        XCTAssertThrowsError(try validate())
        try FileManager.default.createSymbolicLink(atPath: published, withDestinationPath: published + ".preserved")
        XCTAssertThrowsError(try validate())
    }

    func testBoundAddressDoesNotReadTerminatorBeyondKernelLength() throws {
        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: Array("/test".utf8) + [0]) }
        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        XCTAssertEqual(try RouterSystemActivatedSocket.boundAddress(address, size: size), "/test")
        address.sun_len = 7
        XCTAssertEqual(try RouterSystemActivatedSocket.boundAddress(address, size: 7), "/test")
        address.sun_len = 6
        XCTAssertEqual(try RouterSystemActivatedSocket.boundAddress(address, size: 6), "/tes")
        address.sun_len = 8
        XCTAssertEqual(try RouterSystemActivatedSocket.boundAddress(address, size: 8), "/test")
        address.sun_len = 9
        XCTAssertThrowsError(try RouterSystemActivatedSocket.boundAddress(address, size: 8))
        address.sun_len = UInt8(size); address.sun_family = sa_family_t(AF_INET)
        XCTAssertThrowsError(try RouterSystemActivatedSocket.boundAddress(address, size: size))
        address.sun_family = sa_family_t(AF_UNIX)
        XCTAssertThrowsError(try RouterSystemActivatedSocket.boundAddress(address, size: size + 1))
        withUnsafeMutableBytes(of: &address.sun_path) { $0.initializeMemory(as: UInt8.self, repeating: 65) }
        XCTAssertThrowsError(try RouterSystemActivatedSocket.boundAddress(address, size: size))
    }

    func testExplicitLeaseReleaseIsIdempotentAndDoesNotCloseReusedDescriptor() throws {
        let (_, directory) = try directory()
        let old = try RouterSystemHostLease.acquire(in: directory)
        old.release(); old.release(); XCTAssertThrowsError(try old.verify())
        let current = try RouterSystemHostLease.acquire(in: directory)
        old.release(); try current.verify()
        XCTAssertThrowsError(try RouterSystemHostLease.acquire(in: directory))
    }

}
