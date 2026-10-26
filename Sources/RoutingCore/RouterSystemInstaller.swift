import Foundation
import Darwin

struct RouterSystemInstallerRequest {
    enum Verb: String {
        case preview, apply
        case resumePreview = "resume-preview", resumeApply = "resume-apply"
        var isPreview: Bool { self == .preview || self == .resumePreview }
        var isResume: Bool { self == .resumePreview || self == .resumeApply }
    }
    let verb: Verb
    let action: RouterSystemInstallAction
    let ownerUID: UInt32
    let id: UUID
    let confirm: String?
    func validateSaved(_ plan: RouterSystemInstallPlan, packageID: UUID, helperSHA256: String,
                       transactionDirectory: RouterSystemInstallNode) throws {
        try plan.validate()
        let candidate = plan.candidate
        guard candidate.transaction == id, candidate.action == action, candidate.installation.ownerUID == ownerUID,
              candidate.packageID == packageID, candidate.helperDigest == helperSHA256,
              plan.files.allSatisfy({ $0.transactionDirectory == transactionDirectory }) else { throw RouterSystemError.conflict }
    }
    static func parse(_ arguments: [String]) throws -> Self {
        guard let first = arguments.first, let verb = Verb(rawValue: first), arguments.count % 2 == 1,
              arguments.count <= 9, arguments.allSatisfy({ $0.utf8.count <= 128 && !$0.utf8.contains(0) }) else { throw RouterSystemError.invalidRequest }
        var values: [String: String] = [:]
        for index in stride(from: 1, to: arguments.count, by: 2) {
            guard values.updateValue(arguments[index + 1], forKey: arguments[index]) == nil else { throw RouterSystemError.invalidRequest }
        }
        let keys: Set<String> = verb.isPreview ? ["--action", "--uid", "--id"] : ["--action", "--uid", "--id", "--confirm"]
        guard Set(values.keys) == keys, let action = values["--action"].flatMap(RouterSystemInstallAction.init(rawValue:)),
              let uid = values["--uid"].flatMap(UInt32.init), uid >= 501, uid < UInt32.max, values["--uid"] == String(uid),
              let id = values["--id"].flatMap(UUID.init(uuidString:)), values["--id"]?.lowercased() == id.uuidString.lowercased() else {
            throw RouterSystemError.invalidRequest
        }
        if let digest = values["--confirm"] { guard RouterSystemProvider.validDigest(digest) else { throw RouterSystemError.invalidRequest } }
        return .init(verb: verb, action: action, ownerUID: uid, id: id, confirm: values["--confirm"])
    }
}

/// Called by a generated, signed native entry containing its literal package UUID/helper digest.
/// Installation never runs a user-writable Python script, accepts a raw config, or enables the TUN.
public enum RouterSystemInstaller {
    public static func run(arguments: [String], packageID: UUID, helperSHA256: String, requireExisting: Bool = false) throws {
        guard getuid() == 0, geteuid() == 0, RouterSystemProvider.validDigest(helperSHA256) else { throw RouterSystemError.ownershipUnknown }
        let request = try RouterSystemInstallerRequest.parse(arguments)
        guard getpwuid(request.ownerUID) != nil else { throw RouterSystemError.invalidRequest }
        let destination = try RouterSystemDirectory.installed(RouterSystemLayout.applicationSupport, privateLeaf: false)
        let launchDaemons = try RouterSystemDirectory.installed(RouterSystemLayout.launchDaemons, privateLeaf: false)
        let existing = try RouterSystemInstallerPaths.registry(destination, create: false)
        let leaf = RouterSystemInstallRetirement.transactionLeaf(request.id)
        let service = try RouterSystemInstallNativeService(ownerUID: request.ownerUID, destination: destination, launchDaemons: launchDaemons)
        if let registry = existing, let transaction = try registry.childIfPresent(leaf) {
            guard let bytes = try transaction.read("plan.json", maximum: 1024 * 1024) else { throw RouterSystemError.journalUnknown }
            let plan = try RouterSystemInstallPlan.decode(bytes), candidate = plan.candidate
            let node = try RouterSystemInstallNode.directory(transaction)
            try request.validateSaved(plan, packageID: packageID, helperSHA256: helperSHA256, transactionDirectory: node)
            if request.verb.isResume {
                try RouterSystemInstallResume(registry: registry, transaction: transaction, destination: destination,
                    launchDaemons: launchDaemons, service: service).run(request: request, plan: plan)
                return
            }
            if request.verb == .preview { try preview(candidate, saved: true); return }
            guard let confirm = request.confirm, try candidate.digest == confirm else { throw RouterSystemError.conflict }
            let lease = try RouterSystemHostLease.acquire(in: registry, purpose: .installer)
            defer { withExtendedLifetime(lease) {} }
            let coordinator = RouterSystemInstallCoordinator(registry: registry, transaction: transaction, destination: destination,
                launchDaemons: launchDaemons, service: service)
            try complete(coordinator.apply(confirmedCandidate: confirm, installerLease: lease))
            return
        }
        guard !requireExisting, !request.verb.isResume else { throw RouterSystemError.conflict }
        let payload = try request.action == .retire ? nil : RouterSystemInstallerPayload.besideSelf(ownerUID: request.ownerUID, helperSHA256: helperSHA256)
        func collect(_ registry: RouterSystemDirectory?) throws -> (candidate: RouterSystemInstallCandidate, files: [RouterSystemInstallFile: Data]) {
            try RouterSystemInstallCandidateBuilder(request: request, packageID: packageID, helperSHA256: helperSHA256,
                payload: payload, destination: destination, launchDaemons: launchDaemons, registry: registry, service: service).collect()
        }
        let before = try collect(existing)
        if request.verb == .preview { try preview(before.candidate, saved: false); return }
        guard let confirm = request.confirm, try before.candidate.digest == confirm else { throw RouterSystemError.conflict }
        // Only a matching read-only preview can create the registry and process lock.
        guard let registry = try RouterSystemInstallerPaths.registry(destination, create: true) else { throw RouterSystemError.ownershipUnknown }
        let installer = try RouterSystemHostLease.acquire(in: registry, purpose: .installer)
        defer { withExtendedLifetime(installer) {} }
        guard try registry.childIfPresent(leaf) == nil else { throw RouterSystemError.conflict }
        let locked = try collect(registry)
        guard try locked.candidate.digest == confirm else { throw RouterSystemError.conflict }
        var operation: RouterSystemHostLease?
        if let preserved = locked.candidate.preserved {
            let tree = try RouterSystemInstallTree(parent: destination)
            guard try tree.operationImage() == preserved.operationLock else { throw RouterSystemError.conflict }
            operation = try RouterSystemHostLease.acquire(in: tree.state, purpose: .operation)
            try operation?.verify(in: tree.state, purpose: .operation)
            guard try tree.operationImage() == preserved.operationLock else { throw RouterSystemError.conflict }
        }
        defer { withExtendedLifetime(operation) {} }
        let confirmed = try collect(registry)
        guard try confirmed.candidate.digest == confirm else { throw RouterSystemError.conflict }
        let transaction = try registry.createDirectory(leaf)
        let coordinator = RouterSystemInstallCoordinator(registry: registry, transaction: transaction, destination: destination,
            launchDaemons: launchDaemons, service: service)
        _ = try coordinator.prepare(candidate: confirmed.candidate, payload: confirmed.files,
            initialJournal: request.action == .install ? confirmed.candidate.initialJournalBytes() : nil,
            installerLease: installer, heldOperationLease: operation)
        try complete(coordinator.apply(confirmedCandidate: confirm, installerLease: installer, heldOperationLease: operation))
    }
    private static func preview(_ candidate: RouterSystemInstallCandidate, saved: Bool) throws {
        let digest = try candidate.digest
        try output(["version": 1, "status": saved ? "saved_transaction_preview" : "readonly_preview",
            "candidate": JSONSerialization.jsonObject(with: RouterSystemInstallEncoding.encode(candidate)), "confirm": digest,
            "apply_arguments": ["apply", "--action", candidate.action.rawValue, "--uid", String(candidate.installation.ownerUID),
                "--id", candidate.transaction.uuidString.lowercased(), "--confirm", digest],
            "installation_modified": false, "network_modified": false, "routing_verified": false,
            "protection_verified": false, "launch_authorized": false])
    }
    static func complete(_ completion: RouterSystemInstallCompletion) throws {
        try output(["version": 1, "status": "transaction_complete", "action": completion.active.action.rawValue,
            "transaction": completion.active.transaction.uuidString.lowercased(), "proof_digest": completion.proofDigest,
            "routing_verified": false, "protection_verified": false, "launch_authorized": false])
    }
    static func output(_ object: [String: Any]) throws {
        let data = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
        FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
    }
}
