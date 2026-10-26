import Foundation
import Darwin

/// No locking, synchronization or creation: this observation can be displayed before any change.
struct RouterSystemInstallCandidateBuilder {
    let request: RouterSystemInstallerRequest
    let packageID: UUID
    let helperSHA256: String
    let payload: RouterSystemInstallerPayload?
    let destination: RouterSystemDirectory
    let launchDaemons: RouterSystemDirectory
    let registry: RouterSystemDirectory?
    let service: RouterSystemInstallService

    func collect() throws -> (candidate: RouterSystemInstallCandidate, files: [RouterSystemInstallFile: Data]) {
        try requireNoActive()
        let originalJob = try service.job()
        let exists = try RouterSystemInstallerPaths.rootExists(destination)
        let tree = try exists ? RouterSystemInstallTree(parent: destination) : nil
        let priorSocket = try tree == nil ? nil : service.observedSocket()
        let retired = try retirement()
        let identity: RouterSystemInstallationIdentity
        let preserved: RouterSystemInstallPreserved?
        var verifiedBytes: [RouterSystemInstallFile: Data] = [:]
        switch request.action {
        case .install:
            guard tree == nil, retired == nil, originalJob == .absent,
                  try before(.launchd, tree: nil) == nil else { throw RouterSystemError.conflict }
            identity = .init(id: request.id, ownerUID: request.ownerUID); preserved = nil
        case .upgrade, .retire:
            guard let tree, retired == nil else { throw RouterSystemError.conflict }
            for file in RouterSystemInstallFile.allCases {
                guard let bytes = try tree.target(file, launchDaemons: launchDaemons).read(file.leaf, maximum: file.maximum, mode: file.mode) else {
                    throw RouterSystemError.ownershipUnknown
                }
                verifiedBytes[file] = bytes
            }
            guard let manifestBytes = verifiedBytes[.manifest], let receiptBytes = verifiedBytes[.packageReceipt] else { throw RouterSystemError.conflict }
            let manifest = try RouterSystemInstallManifest.decode(manifestBytes)
            let receipt = try RouterSystemInstallEncoding.decode(RouterSystemInstallPackageReceipt.self, receiptBytes)
            guard receipt.matches(manifest), manifest.ownerUID == request.ownerUID,
                  verifiedBytes[.helper].map(RouterSystemObservation.hash) == manifest.helperSHA256,
                  verifiedBytes[.core].map(RouterSystemObservation.hash) == RouterCoreRelease.executableSHA256,
                  verifiedBytes[.launchd] == (try RouterSystemInstallPlist.bytes(ownerUID: request.ownerUID)) else { throw RouterSystemError.conflict }
            identity = manifest.identity
            let snapshot = RouterSystemInstallPreserved(installation: identity, parents: try tree.parents(),
                operationLock: try tree.operationImage(), journal: try tree.journalImage())
            try tree.verify(snapshot, exactJournal: true); preserved = snapshot
            _ = try service.proof(identity: identity, retired: !originalJob.registered)
        case .reinstall:
            guard let tree, let retired, originalJob == .absent,
                  retired.preserved.installation.ownerUID == request.ownerUID,
                  priorSocket == nil || priorSocket == retired.residualSocket else { throw RouterSystemError.conflict }
            identity = retired.preserved.installation; preserved = retired.preserved
            try tree.verify(retired.preserved, exactJournal: true)
            for file in RouterSystemInstallFile.allCases {
                guard try before(file, tree: tree) == nil else { throw RouterSystemError.conflict }
            }
            _ = try service.proof(identity: identity, retired: true)
        }
        let files: [RouterSystemInstallFile: Data]
        if request.action == .retire { files = [:] }
        else {
            guard let payload else { throw RouterSystemError.invalidRequest }
            files = try payload.files(packageID: packageID, identity: identity, helperSHA256: helperSHA256)
        }
        let images = try RouterSystemInstallFile.allCases.map { file -> RouterSystemInstallCandidateFile in
            let image = try before(file, tree: tree)
            if request.action == .upgrade || request.action == .retire {
                guard image?.digest == verifiedBytes[file].map(RouterSystemObservation.hash), image?.count == verifiedBytes[file]?.count else {
                    throw RouterSystemError.conflict
                }
            }
            return .init(file: file, before: image, afterDigest: files[file].map(RouterSystemObservation.hash), afterCount: files[file]?.count)
        }
        var candidate = RouterSystemInstallCandidate(version: 1, transaction: request.id, packageID: packageID,
            action: request.action, installation: identity, helperDigest: helperSHA256,
            destinationParent: try .directory(destination), launchDaemonsParent: try .directory(launchDaemons),
            files: images, preserved: preserved, originalJob: originalJob, retired: retired?.pointer, retiredMarker: retired?.marker)
        candidate.priorSocket = priorSocket
        try candidate.validate()
        guard try (tree == nil ? nil : service.observedSocket()) == priorSocket else { throw RouterSystemError.conflict }
        if let tree, let preserved { try tree.verify(preserved, exactJournal: true) }
        guard try service.job() == originalJob, try RouterSystemInstallerPaths.rootExists(destination) == exists else { throw RouterSystemError.conflict }
        for image in images { guard try before(image.file, tree: tree) == image.before else { throw RouterSystemError.conflict } }
        try requireNoActive()
        let last = try retirement()
        guard last?.pointer == retired?.pointer, last?.marker == retired?.marker else { throw RouterSystemError.conflict }
        return (candidate, files)
    }
    private func before(_ file: RouterSystemInstallFile, tree: RouterSystemInstallTree?) throws -> RouterSystemInstallImage? {
        if let tree {
            return try RouterSystemInstallEncoding.image(file.leaf, in: tree.target(file, launchDaemons: launchDaemons),
                maximum: file.maximum, mode: file.mode)
        }
        return file == .launchd ? try RouterSystemInstallEncoding.image(file.leaf, in: launchDaemons, maximum: file.maximum, mode: file.mode) : nil
    }
    private func requireNoActive() throws {
        if let registry {
            guard try registry.read("active.json", maximum: 8192) == nil else { throw RouterSystemError.operationUnsettled }
        }
    }
    private func retirement() throws -> RouterSystemInstallRetirement.Observation? {
        guard let registry else { return nil }
        // observe() only reads the shared pointer and its historical transaction, not this slot.
        return try RouterSystemInstallRetirement(registry: registry, transaction: registry, launchDaemons: launchDaemons).observe()
    }
}

enum RouterSystemInstallerPaths {
    static func rootExists(_ parent: RouterSystemDirectory) throws -> Bool { try exists("Claude Router", parent: parent) }
    static func registry(_ parent: RouterSystemDirectory, create: Bool) throws -> RouterSystemDirectory? {
        let name = "Claude Router Installer"
        if try !exists(name, parent: parent) {
            guard create else { return nil }
            guard mkdirat(parent.fd, name, 0o700) == 0 || errno == EEXIST else { throw RouterSystemError.ownershipUnknown }
            guard fsync(parent.fd) == 0 else { throw RouterSystemError.journalUnknown }
        }
        return try .installed(RouterSystemLayout.installerRoot, privateLeaf: true)
    }
    private static func exists(_ name: String, parent: RouterSystemDirectory) throws -> Bool {
        try parent.validate()
        var value = stat()
        if fstatat(parent.fd, name, &value, AT_SYMLINK_NOFOLLOW) == 0 { return true }
        guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return false
    }
}
