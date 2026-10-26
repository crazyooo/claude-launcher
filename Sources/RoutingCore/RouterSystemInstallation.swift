import Foundation
import Darwin

struct RouterSystemInstallManifest: Codable, Equatable {
    let version: Int
    let installationID: UUID
    let ownerUID: UInt32
    let helperSHA256: String
    let coreVersion: String
    let coreSHA256: String
    var identity: RouterSystemInstallationIdentity { .init(id: installationID, ownerUID: ownerUID) }

    static func decode(_ data: Data) throws -> Self {
        do {
            let object = try RouterStrictJSON.object(data, maximumBytes: 4096, maximumValues: 32)
            guard Set(object.keys) == ["version", "installationID", "ownerUID", "helperSHA256", "coreVersion", "coreSHA256"] else {
                throw RouterSystemError.ownershipUnknown
            }
            let value = try JSONDecoder().decode(Self.self, from: data)
            guard value.version == 1, value.identity.isValid,
                  RouterSystemProvider.validDigest(value.helperSHA256), value.coreVersion == RouterCoreRelease.version,
                  value.coreSHA256 == RouterCoreRelease.executableSHA256 else { throw RouterSystemError.ownershipUnknown }
            return value
        } catch { throw RouterSystemError.ownershipUnknown }
    }
}

/// Fixed root-owned code and metadata; no manifest field can select a pathname or executable.
struct RouterSystemInstallation {
    let manifest: RouterSystemInstallManifest
    let root: RouterSystemDirectory
    let state: RouterSystemDirectory
    let binaries: RouterSystemDirectory
    let cores: RouterSystemDirectory
    static func verify() throws -> Self {
        guard getuid() == 0, geteuid() == 0 else { throw RouterSystemError.ownershipUnknown }
        let root = try RouterSystemDirectory.installed(RouterSystemLayout.root, privateLeaf: false)
        guard let data = try root.read("install-manifest.json", maximum: 4096) else { throw RouterSystemError.ownershipUnknown }
        let manifest = try RouterSystemInstallManifest.decode(data)
        let result = Self(manifest: manifest, root: root,
            state: try .installed(RouterSystemLayout.state, privateLeaf: true),
            binaries: try .installed(RouterSystemLayout.root + "/bin", privateLeaf: false),
            cores: try .installed(RouterSystemLayout.root + "/core", privateLeaf: false))
        try result.verifyCode()
        return result
    }
    func verifyCode() throws {
        var path = [CChar](repeating: 0, count: 4096)
        guard proc_pidpath(getpid(), &path, UInt32(path.count)) > 0,
              String(cString: path) == RouterSystemLayout.helper,
              let helper = try binaries.read("router-system-helper", maximum: 128 * 1024 * 1024, mode: 0o700),
              RouterSystemObservation.hash(helper) == manifest.helperSHA256,
              let core = try cores.read("mihomo", maximum: 128 * 1024 * 1024, mode: 0o700),
              RouterSystemObservation.hash(core) == RouterCoreRelease.executableSHA256,
              let current = try root.read("install-manifest.json", maximum: 4096),
              try RouterSystemInstallManifest.decode(current) == manifest else { throw RouterSystemError.ownershipUnknown }
    }
}
