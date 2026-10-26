import Foundation
import Darwin

struct RouterSystemInstallPackageReceipt: Codable, Equatable {
    let version: Int
    let packageID: UUID
    let installationID: UUID
    let ownerUID: UInt32
    let helperSHA256: String
    let coreVersion: String
    let coreSHA256: String
    let operationLockProtocol: Int
    func matches(_ manifest: RouterSystemInstallManifest) -> Bool {
        version == 1 && operationLockProtocol == 1 && installationID == manifest.installationID &&
        ownerUID == manifest.ownerUID && helperSHA256 == manifest.helperSHA256 &&
        coreVersion == manifest.coreVersion && coreSHA256 == manifest.coreSHA256
    }
}

/// The package is user-owned. Only fixed, digest-verified bytes cross into root-owned staging;
/// nothing in this directory is executed by the root installer.
struct RouterSystemInstallerPayload {
    let helper: Data
    let core: Data

    static func besideSelf(ownerUID: UInt32, helperSHA256: String) throws -> Self {
        var buffer = [CChar](repeating: 0, count: 4096)
        let size = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
        guard size > 0, size < buffer.count, buffer.contains(0) else { throw RouterSystemError.ownershipUnknown }
        let executable = URL(fileURLWithPath: String(cString: buffer))
        guard executable.lastPathComponent == "router-system-installer" else { throw RouterSystemError.ownershipUnknown }
        let components = executable.deletingLastPathComponent().path.split(separator: "/").map(String.init) + ["payload"]
        var opened: [Int32] = []
        defer { for fd in opened.reversed() { close(fd) } }
        let root = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard root >= 0 else { throw RouterSystemError.ownershipUnknown }; opened.append(root)
        var parent = root, links: [(Int32, String, Int32)] = []
        for component in components {
            guard component != ".", component != "..", !component.isEmpty else { throw RouterSystemError.ownershipUnknown }
            let fd = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }
            opened.append(fd); links.append((parent, component, fd)); parent = fd
        }
        func verify() throws {
            for fd in opened { try directory(fd, ownerUID: ownerUID) }
            for (parent, name, fd) in links {
                var held = stat(), linked = stat()
                guard fstat(fd, &held) == 0, fstatat(parent, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
                      RouterSystemDirectory.unchanged(held, linked) else { throw RouterSystemError.conflict }
            }
        }
        try verify()
        let helper = try file("router-system-helper", directoryFD: parent, ownerUID: ownerUID, digest: helperSHA256)
        let core = try file("mihomo", directoryFD: parent, ownerUID: ownerUID, digest: RouterCoreRelease.executableSHA256)
        try verify()
        return .init(helper: helper, core: core)
    }

    // Internal descriptor entry also permits offline fixture tests; there is no CLI path parameter.
    static func file(_ name: String, directoryFD: Int32, ownerUID: UInt32, digest: String) throws -> Data {
        guard ["router-system-helper", "mihomo"].contains(name), RouterSystemProvider.validDigest(digest) else {
            throw RouterSystemError.invalidRequest
        }
        try directory(directoryFD, ownerUID: ownerUID)
        let fd = openat(directoryFD, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { throw RouterSystemError.ownershipUnknown }; defer { close(fd) }
        var before = stat(), after = stat(), linked = stat()
        guard fstat(fd, &before) == 0, before.st_mode & S_IFMT == S_IFREG, before.st_mode & 0o7777 == 0o755,
              before.st_nlink == 1, before.st_uid == 0 || before.st_uid == ownerUID,
              before.st_size > 0, before.st_size <= 128 * 1024 * 1024 else { throw RouterSystemError.ownershipUnknown }
        try RouterSystemDirectory.rejectACL(fd)
        var bytes = Data(), chunk = [UInt8](repeating: 0, count: 65536)
        while bytes.count <= before.st_size {
            let count = Darwin.read(fd, &chunk, min(chunk.count, Int(before.st_size) + 1 - bytes.count))
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw RouterSystemError.ownershipUnknown }
            if count == 0 { break }
            bytes.append(contentsOf: chunk.prefix(count))
        }
        guard fstat(fd, &after) == 0, fstatat(directoryFD, name, &linked, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(before, after), RouterSystemDirectory.unchanged(after, linked),
              bytes.count == before.st_size, RouterSystemObservation.hash(bytes) == digest else { throw RouterSystemError.conflict }
        try RouterSystemDirectory.rejectACL(fd); try directory(directoryFD, ownerUID: ownerUID)
        return bytes
    }
    private static func directory(_ fd: Int32, ownerUID: UInt32) throws {
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFDIR,
              info.st_uid == 0 || info.st_uid == ownerUID, info.st_mode & 0o022 == 0 else { throw RouterSystemError.ownershipUnknown }
        // Ancestors can carry macOS home-directory ACLs. File pins and no-follow stable reads are
        // the authority; only the two executable payload files require an empty extended ACL.
    }
    func files(packageID: UUID, identity: RouterSystemInstallationIdentity, helperSHA256: String) throws -> [RouterSystemInstallFile: Data] {
        guard identity.isValid, RouterSystemObservation.hash(helper) == helperSHA256,
              RouterSystemObservation.hash(core) == RouterCoreRelease.executableSHA256 else { throw RouterSystemError.conflict }
        let manifest = RouterSystemInstallManifest(version: 1, installationID: identity.id, ownerUID: identity.ownerUID,
            helperSHA256: helperSHA256, coreVersion: RouterCoreRelease.version, coreSHA256: RouterCoreRelease.executableSHA256)
        let receipt = RouterSystemInstallPackageReceipt(version: 1, packageID: packageID, installationID: identity.id,
            ownerUID: identity.ownerUID, helperSHA256: helperSHA256, coreVersion: RouterCoreRelease.version,
            coreSHA256: RouterCoreRelease.executableSHA256, operationLockProtocol: 1)
        return [.helper: helper, .core: core, .manifest: try RouterSystemInstallEncoding.encode(manifest),
            .packageReceipt: try RouterSystemInstallEncoding.encode(receipt), .launchd: try RouterSystemInstallPlist.bytes(ownerUID: identity.ownerUID)]
    }
}
