import Foundation
import Darwin
import launch

/// Owns launchd's named capability. The kernel's bind address can differ from the
/// published socket path after launchd renames it; neither path text nor fd inode
/// establishes the mapping. The installation, declaration and published node are
/// verified separately. This object never binds, replaces or unlinks a socket.
final class RouterSystemActivatedSocket {
    private typealias Diagnostic = RouterSystemHostDiagnostic
    let fd: Int32
    private let directory: RouterSystemDirectory

    init(installation: RouterSystemInstallation) throws {
        try Diagnostic.socketStep(.code) { try installation.verifyCode() }
        let (declarations, runDirectory) = try Diagnostic.socketStep(.directories) {
            (try RouterSystemDirectory.installed(RouterSystemLayout.launchDaemons, privateLeaf: false),
             try RouterSystemDirectory.installed(RouterSystemLayout.root + "/run", privateLeaf: false))
        }
        directory = runDirectory
        let expected = try Diagnostic.socketStep(.declarationBefore) {
            try Self.declaration(installation, in: declarations)
        }
        // launchd publishes (or replaces a retained node at) the configured path
        // during activation. A preactivation inode cannot identify that publication.
        // The SDK imports the out-pointer as nonoptional. launchd supplies malloc storage.
        let sentinel = UnsafeMutablePointer<Int32>.allocate(capacity: 1)
        defer { sentinel.deallocate() }
        var sockets = sentinel, count = 0
        let activation = launch_activate_socket("Control", &sockets, &count)
        try Diagnostic.socketStep(.activation, value: Int(activation)) {
            guard activation == 0, sockets != sentinel else { throw RouterSystemError.ownershipUnknown }
        }
        defer { free(sockets) }
        try Diagnostic.socketStep(.descriptorCount, value: count) {
            guard count == 1 else {
                for index in 0..<max(0, count) { close(sockets[index]) }
                throw RouterSystemError.ownershipUnknown
            }
        }
        let descriptor = sockets[0]
        do {
            try Self.validatePublication(descriptor, directory: runDirectory,
                                         owner: installation.manifest.ownerUID, group: 0) {
                guard try Self.declaration(installation, in: declarations) == expected else {
                    throw RouterSystemError.ownershipUnknown
                }
            }
            fd = descriptor
        } catch { close(descriptor); throw error }
    }
    deinit { close(fd) }

    /// Both pathname snapshots are taken after the named capability has been acquired.
    /// The caller retains descriptor ownership, including on validation failure.
    private static func validatePublication(_ descriptor: Int32, directory: RouterSystemDirectory,
                                            owner: UInt32, group: UInt32,
                                            recheckDeclaration: () throws -> Void) throws {
        let published = try Diagnostic.socketStep(.nodeBefore) {
            try publishedNode(directory, owner: owner, group: group)
        }
        _ = try listenerAddress(descriptor)
        try Diagnostic.socketStep(.descriptorFlags) {
            let flags = fcntl(descriptor, F_GETFL)
            guard flags >= 0, fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                  fcntl(descriptor, F_SETFL, flags & ~O_NONBLOCK) == 0 else { throw RouterSystemError.operationUnsettled }
        }
        try Diagnostic.socketStep(.declarationAfter, perform: recheckDeclaration)
        try Diagnostic.socketStep(.nodeAfter) {
            guard RouterSystemDirectory.unchanged(published,
                try publishedNode(directory, owner: owner, group: group)) else {
                throw RouterSystemError.ownershipUnknown
            }
        }
    }

    /// Exercises publication timing with real user-owned sockets. Successful
    /// activation transfers descriptor ownership to this fixture; no root/IPC caller.
    static func fixturePublication(directory: RouterSystemDirectory, declarations: RouterSystemDirectory,
                                   activate: () throws -> Int32,
                                   afterSnapshot: () throws -> Void = {}) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterSystemError.ownershipUnknown }
        let expected = try canonicalDeclaration(in: declarations, owner: getuid())
        let descriptor = try activate()
        guard descriptor >= 0 else { throw RouterSystemError.ownershipUnknown }
        defer { close(descriptor) }
        try validatePublication(descriptor, directory: directory, owner: getuid(), group: getgid()) {
            try afterSnapshot()
            guard try canonicalDeclaration(in: declarations, owner: getuid()) == expected else {
                throw RouterSystemError.ownershipUnknown
            }
        }
    }

    private struct Declaration: Equatable {
        let manifest: RouterSystemInstallImage
        let plist: RouterSystemInstallImage
    }
    private static func declaration(_ installation: RouterSystemInstallation,
                                    in directory: RouterSystemDirectory) throws -> Declaration {
        let manifest = try Diagnostic.socketStep(.manifest) {
            guard let manifest = try RouterSystemInstallEncoding.image("install-manifest.json", in: installation.root, maximum: 4096),
              let bytes = try installation.root.read("install-manifest.json", maximum: 4096),
              RouterSystemObservation.hash(bytes) == manifest.digest,
              try RouterSystemInstallManifest.decode(bytes) == installation.manifest else { throw RouterSystemError.ownershipUnknown }
            return manifest
        }
        let plist = try Diagnostic.socketStep(.plist) {
            try canonicalDeclaration(in: directory, owner: installation.manifest.ownerUID)
        }
        return .init(manifest: manifest, plist: plist)
    }
    private static func canonicalDeclaration(in directory: RouterSystemDirectory, owner: UInt32) throws -> RouterSystemInstallImage {
        let expected = try RouterSystemInstallPlist.bytes(ownerUID: owner)
        guard let image = try RouterSystemInstallEncoding.image(RouterSystemInstallFile.launchd.leaf,
                in: directory, maximum: 65536, mode: 0o644),
              image.count == expected.count, image.digest == RouterSystemObservation.hash(expected) else {
            throw RouterSystemError.ownershipUnknown
        }
        return image
    }

    /// A directly bound, unprivileged test listener still requires its exact bind path.
    static func fixtureVerify(_ fd: Int32, directory: RouterSystemDirectory, path: String) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterSystemError.ownershipUnknown }
        guard try listenerAddress(fd) == path else { throw RouterSystemError.ownershipUnknown }
        _ = try publishedNode(directory, owner: getuid(), group: getgid())
    }
    /// Exercises the shared checks after a real bind/rename. It cannot construct an
    /// activation capability, run as root, or alter the production trust source.
    static func fixtureVerifyPublishedListener(_ fd: Int32, directory: RouterSystemDirectory,
                                              declarations: RouterSystemDirectory) throws {
        guard getuid() != 0, geteuid() == getuid() else { throw RouterSystemError.ownershipUnknown }
        let declaration = try canonicalDeclaration(in: declarations, owner: getuid())
        let node = try publishedNode(directory, owner: getuid(), group: getgid())
        _ = try listenerAddress(fd)
        guard try canonicalDeclaration(in: declarations, owner: getuid()) == declaration,
              RouterSystemDirectory.unchanged(node, try publishedNode(directory, owner: getuid(), group: getgid())) else {
            throw RouterSystemError.ownershipUnknown
        }
    }
    private static func listenerAddress(_ fd: Int32) throws -> String {
        // Darwin AF_UNIX does not support getsockopt(SO_ACCEPTCONN).
        var evidence = socket_fdinfo()
        let bytes = proc_pidfdinfo(getpid(), fd, PROC_PIDFDSOCKETINFO, &evidence, Int32(MemoryLayout<socket_fdinfo>.stride))
        try Diagnostic.requireSocket(bytes == MemoryLayout<socket_fdinfo>.stride, at: .listenerRead)
        try Diagnostic.requireSocket(evidence.psi.soi_family == AF_UNIX, at: .listenerFamily)
        try Diagnostic.requireSocket(evidence.psi.soi_type == SOCK_STREAM, at: .listenerType)
        try Diagnostic.requireSocket(evidence.psi.soi_kind == SOCKINFO_UN, at: .listenerKind)
        try Diagnostic.requireSocket(evidence.psi.soi_options & Int16(SO_ACCEPTCONN) != 0, at: .listenerAccept)
        var address = sockaddr_un(), size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let result = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) }
        }
        try Diagnostic.requireSocket(result == 0, at: .nameRead)
        return try Diagnostic.socketStep(.addressParse) { try boundAddress(address, size: size) }
    }
    /// Only parses bytes the kernel reports having returned, not zeroed buffer padding.
    static func boundAddress(_ address: sockaddr_un, size: socklen_t) throws -> String {
        let offset = MemoryLayout<sockaddr_un>.offset(of: \.sun_path)!
        guard address.sun_family == sa_family_t(AF_UNIX), Int(size) > offset,
              Int(size) <= MemoryLayout<sockaddr_un>.size,
              Int(address.sun_len) > offset, address.sun_len <= size else { throw RouterSystemError.ownershipUnknown }
        let path = withUnsafeBytes(of: address.sun_path) { bytes -> String? in
            let available = bytes.prefix(min(Int(size), Int(address.sun_len)) - offset)
            // Darwin may report the exact path byte length without a NUL.
            // Decode that bounded slice directly; never read buffer padding.
            let end = available.firstIndex(of: 0) ?? available.endIndex
            guard end > 0 else { return nil }
            return String(bytes: available.prefix(end), encoding: .utf8)
        }
        guard let path, path.hasPrefix("/"), !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw RouterSystemError.ownershipUnknown
        }
        return path
    }
    private static func publishedNode(_ directory: RouterSystemDirectory, owner: UInt32, group: UInt32) throws -> stat {
        try Diagnostic.socketStep(.nodeDirectory) { try directory.validate() }
        var first = stat(), last = stat()
        try Diagnostic.requireSocket(fstatat(directory.fd, "control.sock", &first, AT_SYMLINK_NOFOLLOW) == 0, at: .nodeRead)
        try Diagnostic.requireSocket(first.st_mode & S_IFMT == S_IFSOCK, at: .nodeType)
        try Diagnostic.requireSocket(first.st_uid == owner, at: .nodeOwner)
        try Diagnostic.requireSocket(first.st_gid == group, at: .nodeGroup)
        try Diagnostic.requireSocket(first.st_mode & 0o7777 == 0o600, at: .nodeMode)
        try Diagnostic.requireSocket(first.st_nlink == 1, at: .nodeLinks)
        try Diagnostic.requireSocket(fstatat(directory.fd, "control.sock", &last, AT_SYMLINK_NOFOLLOW) == 0, at: .nodeReread)
        try Diagnostic.requireSocket(RouterSystemDirectory.unchanged(first, last), at: .nodeStable)
        try Diagnostic.socketStep(.nodeDirectory) { try directory.validate() }
        return last
    }
}
