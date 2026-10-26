import Foundation
import Darwin

/// One App owner and an immutable request/execution record. Completion does not erase uncertainty.
public final class PFAuthorizationJournal: @unchecked Sendable {
    private let directory: PrivateRecoveryDirectory
    private let lifecycleFD: Int32
    private let directoryURL: URL
    private let ioLock = NSLock()
    private var uncertain = false
    private let afterReplace: (() throws -> Void)?
    static let failure = LauncherError.message("授权恢复记录不可用或已由另一应用实例占用；保留原记录并停止新的授权。")

    public convenience init() throws { try self.init(directory: Paths.root) }
    init(directory url: URL, afterReplace: (() throws -> Void)? = nil) throws {
        directoryURL = url; self.afterReplace = afterReplace
        directory = try PrivateRecoveryDirectory(url)
        lifecycleFD = openat(directory.fd, "pf-authorization-app.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lifecycleFD >= 0 else { throw Self.failure }
        do {
            _ = try directory.validate(lifecycleFD)
            guard flock(lifecycleFD, LOCK_EX | LOCK_NB) == 0 else { throw Self.failure }
            try validateOwnership()
        } catch { close(lifecycleFD); throw Self.failure }
    }
    deinit { close(lifecycleFD) }

    private func validateOwnership() throws {
        let lock = try directory.validate(lifecycleFD)
        var linked = stat(), pinned = stat(), path = stat()
        guard fstatat(directory.fd, "pf-authorization-app.lock", &linked, AT_SYMLINK_NOFOLLOW) == 0,
              linked.st_dev == lock.st_dev, linked.st_ino == lock.st_ino, linked.st_nlink == 1,
              fstat(directory.fd, &pinned) == 0, lstat(directoryURL.path, &path) == 0,
              pinned.st_dev == path.st_dev, pinned.st_ino == path.st_ino,
              path.st_mode & S_IFMT == S_IFDIR, path.st_uid == geteuid(), path.st_mode & 0o777 == 0o700 else {
            throw Self.failure
        }
    }
    private func readState() throws -> PFAuthorizationState? {
        try validateOwnership()
        guard let bytes = try directory.read("pf-authorization.json") else { return nil }
        return try JSONDecoder().decode(PFAuthorizationState.self, from: bytes)
    }
    public func load() throws -> PFAuthorizationIntent? {
        try loadState()?.authorization
    }
    public func loadState() throws -> PFAuthorizationState? {
        ioLock.lock(); defer { ioLock.unlock() }
        guard !uncertain else { throw Self.failure }
        do { return try readState() } catch { uncertain = true; throw Self.failure }
    }
    private func validateAuthorization(_ next: PFAuthorizationIntent, replacing expected: PFAuthorizationIntent?) throws {
        if let expected {
            if next.executionID == expected.executionID {
                guard next == expected || (!expected.startMayHaveBeenSent && next.startMayHaveBeenSent &&
                                           next.request == expected.request) else { throw Self.failure }
            } else {
                guard !next.startMayHaveBeenSent,
                      !expected.startMayHaveBeenSent || expected.identity?.observe() == .originalExited else { throw Self.failure }
            }
        } else if next.startMayHaveBeenSent { throw Self.failure }
    }
    private func writeState(_ next: PFAuthorizationState) throws {
        let data = try JSONEncoder().encode(next)
        _ = try JSONDecoder().decode(PFAuthorizationState.self, from: data)
        try directory.write(data, to: "pf-authorization.json", afterReplace: afterReplace)
        try validateOwnership()
    }
    public func save(_ next: PFAuthorizationIntent, replacing expected: PFAuthorizationIntent?) throws {
        ioLock.lock(); defer { ioLock.unlock() }
        guard !uncertain else { throw Self.failure }
        do {
            let state = try readState()
            guard state?.authorization == expected else { throw Self.failure }
            try validateAuthorization(next, replacing: expected)
            if let recovery = state?.recovery, recovery.active {
                // An active hold cannot acquire an unrelated standalone authorization.
                guard recovery.request == next.request, recovery.executionID == next.executionID else { throw Self.failure }
            }
            try writeState(.init(authorization: next, recovery: state?.recovery))
        } catch {
            // Even after rename, fsync can fail. No alternate identity or automatic retry in this App.
            uncertain = true; throw Self.failure
        }
    }
    public func saveRecovery(_ next: RecoveryOperationIntent, replacing expected: RecoveryOperationIntent?) throws {
        ioLock.lock(); defer { ioLock.unlock() }
        guard !uncertain else { throw Self.failure }
        do {
            let state = try readState()
            guard state?.recovery == expected else { throw Self.failure }
            if let expected, next.hold.id == expected.hold.id {
                guard next.follows(expected), next.request == expected.request,
                      next.executionID == expected.executionID else { throw Self.failure }
            } else {
                guard expected?.active != true, next.checkpoint == .hold,
                      state?.authorization?.startMayHaveBeenSent != true ||
                        state?.authorization?.identity?.observe() == .originalExited else { throw Self.failure }
            }
            try writeState(.init(authorization: state?.authorization, recovery: next))
        } catch { uncertain = true; throw Self.failure }
    }
    /// The only operation that associates a PF execution with an active hold.
    public func associateAuthorization(_ next: PFAuthorizationIntent, recovery: RecoveryOperationIntent,
                                       replacing expected: PFAuthorizationState) throws {
        ioLock.lock(); defer { ioLock.unlock() }
        guard !uncertain else { throw Self.failure }
        do {
            guard try readState() == expected, let old = expected.recovery,
                  recovery.follows(old), recovery.checkpoint == .authorization,
                  recovery.request == next.request, recovery.executionID == next.executionID,
                  !next.startMayHaveBeenSent else { throw Self.failure }
            try validateAuthorization(next, replacing: expected.authorization)
            try writeState(.init(authorization: next, recovery: recovery))
        } catch { uncertain = true; throw Self.failure }
    }
}
