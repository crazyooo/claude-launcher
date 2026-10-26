import Foundation
import Darwin

/// One host for the lifetime of this descriptor. Never removed or inherited by a child.
final class RouterSystemHostLease {
    enum Purpose: String {
        case host = "host.lock"
        case operation = "operation.lock"
        case installer = "installer.lock"
    }
    private var directory: RouterSystemDirectory
    private var descriptor: Int32
    private let purpose: Purpose
    private init(directory: RouterSystemDirectory, descriptor: Int32, purpose: Purpose) {
        self.directory = directory; self.descriptor = descriptor; self.purpose = purpose
    }
    deinit { release() }
    /// Idempotent explicit release before demand activation; never deletes the lock file.
    func release() {
        if descriptor >= 0 { let held = descriptor; descriptor = -1; close(held) }
    }

    /// Read-only collection cannot create a missing lock or synchronize private state.
    static func acquireExisting(in directory: RouterSystemDirectory, purpose: Purpose) throws -> RouterSystemHostLease {
        try directory.validate()
        let fd = openat(directory.fd, purpose.rawValue, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { throw RouterConnectionFailure.identityChanged }
        do {
            try verify(fd, in: directory, purpose: purpose)
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw RouterConnectionFailure.busy }
            try verify(fd, in: directory, purpose: purpose)
            return .init(directory: directory, descriptor: fd, purpose: purpose)
        } catch { close(fd); throw error }
    }

    static func acquire(in directory: RouterSystemDirectory, purpose: Purpose = .host) throws -> RouterSystemHostLease {
        try directory.validate()
        var fd = openat(directory.fd, purpose.rawValue, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        if fd < 0 {
            guard errno == EEXIST else { throw RouterSystemError.ownershipUnknown }
            fd = openat(directory.fd, purpose.rawValue, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        }
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
        var transferred = false
        defer { if !transferred { close(fd) } }
        try verify(fd, in: directory, purpose: purpose)
        guard flock(fd, LOCK_EX | LOCK_NB) == 0 else { throw RouterSystemError.operationUnsettled }
        try verify(fd, in: directory, purpose: purpose)
        guard fsync(fd) == 0, fsync(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try verify(fd, in: directory, purpose: purpose)
        let lease = RouterSystemHostLease(directory: directory, descriptor: fd, purpose: purpose)
        transferred = true
        return lease
    }
    func verify() throws { try Self.verify(descriptor, in: directory, purpose: purpose) }
    func verify(in expectedDirectory: RouterSystemDirectory, purpose expectedPurpose: Purpose) throws {
        guard purpose == expectedPurpose, directory.owner == expectedDirectory.owner,
              try RouterSystemInstallNode.directory(directory) == RouterSystemInstallNode.directory(expectedDirectory) else {
            throw RouterSystemError.ownershipUnknown
        }
        try verify()
    }
    /// First installation renames the whole tree while holding this same lock descriptor. Only the
    /// parent-bound capability changes; never close/reacquire the lock across that publication gap.
    func rebindOperation(to target: RouterSystemDirectory) throws {
        guard purpose == .operation, directory.owner == target.owner else { throw RouterSystemError.ownershipUnknown }
        try RouterSystemDirectory.validateDirectory(directory.fd, owner: directory.owner, privateLeaf: true)
        try target.validate()
        var before = stat(), after = stat()
        guard fstat(directory.fd, &before) == 0, fstat(target.fd, &after) == 0,
              RouterSystemInstallNode(before) == RouterSystemInstallNode(after) else { throw RouterSystemError.ownershipUnknown }
        try Self.verify(descriptor, in: target, purpose: .operation)
        directory = target
        try verify(in: target, purpose: .operation)
    }
    private static func verify(_ fd: Int32, in directory: RouterSystemDirectory, purpose: Purpose) throws {
        try directory.validate()
        let held = try directory.regular(fd, mode: 0o600)
        var linked = stat()
        guard held.st_size == 0, fstatat(directory.fd, purpose.rawValue, &linked, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(held, linked) else { throw RouterSystemError.ownershipUnknown }
    }
}
