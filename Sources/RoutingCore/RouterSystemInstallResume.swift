import Foundation

/// New, explicit authorization of the current state; never rewrites the sealed install plan.
struct RouterSystemInstallResumeObservation: Codable, Equatable {
    let version: Int
    let planDigest: String
    let records: [RouterSystemInstallImage]
    let parents: RouterSystemInstallParents
    let stateFiles: [RouterSystemInstallImage]
    let socket: RouterSystemInstallNode?
    let registered: Bool
    var digest: String { get throws { RouterSystemObservation.hash(try RouterSystemInstallEncoding.encode(self)) } }

    func accepts(_ current: Self) -> Bool {
        guard version == 1, current.version == 1, planDigest == current.planDigest,
              records == current.records, parents == current.parents, stateFiles == current.stateFiles else { return false }
        // A prior bootstrap may have succeeded before the result was recorded. A registered
        // continuation is observation-only; an absent job may use only this approved residue.
        if current.registered { return current.socket != nil }
        return current.socket == nil || current.socket == socket
    }
}

struct RouterSystemInstallResume {
    private struct ActiveReceipt: Codable {
        let version: Int
        let active: RouterSystemInstallActive
        let registry: RouterSystemInstallNode
        let image: RouterSystemInstallImage
    }
    let registry: RouterSystemDirectory
    let transaction: RouterSystemDirectory
    let destination: RouterSystemDirectory
    let launchDaemons: RouterSystemDirectory
    let service: RouterSystemInstallService

    /// Two complete read-only collections, not a claim of an atomic OS snapshot.
    func preview(_ plan: RouterSystemInstallPlan) throws -> RouterSystemInstallResumeObservation {
        let first = try collect(plan)
        guard try collect(plan) == first else { throw RouterSystemError.conflict }
        return first
    }
    func run(request: RouterSystemInstallerRequest, plan: RouterSystemInstallPlan) throws {
        guard request.action == .install, request.verb.isResume else { throw RouterSystemError.invalidRequest }
        if request.verb == .resumePreview {
            let observation = try preview(plan)
            // Once already registered, ordinary same-plan continuation needs no residual grant.
            let verb = observation.registered ? "apply" : "resume-apply"
            let confirm = try observation.registered ? plan.candidate.digest : observation.digest
            try RouterSystemInstaller.output(["version": 1, "status": "readonly_resume_preview",
                "transaction": request.id.uuidString.lowercased(), "registration_observed": observation.registered,
                "host_health_verified": false, "confirm": confirm,
                "evidence": JSONSerialization.jsonObject(with: RouterSystemInstallEncoding.encode(observation)),
                "apply_arguments": [verb, "--action", "install", "--uid", String(request.ownerUID),
                    "--id", request.id.uuidString.lowercased(), "--confirm", confirm],
                "installation_modified": false, "network_modified": false,
                "routing_verified": false, "protection_verified": false, "launch_authorized": false])
            return
        }
        guard let confirm = request.confirm else { throw RouterSystemError.invalidRequest }
        let lease = try RouterSystemHostLease.acquire(in: registry, purpose: .installer)
        defer { withExtendedLifetime(lease) {} }
        try RouterSystemInstaller.complete(apply(plan, confirm: confirm, installer: lease))
    }

    func apply(_ plan: RouterSystemInstallPlan, confirm: String,
               installer: RouterSystemHostLease) throws -> RouterSystemInstallCompletion {
        try installer.verify(in: registry, purpose: .installer)
        guard RouterSystemProvider.validDigest(confirm), plan.candidate.action == .install else { throw RouterSystemError.invalidRequest }
        let leaf = "resume-" + confirm + ".json"
        let saved = try transaction.read(leaf, maximum: 65536).map {
            try RouterSystemInstallEncoding.decode(RouterSystemInstallResumeObservation.self, $0)
        }
        if let saved {
            guard saved.version == 1, !saved.registered, try saved.digest == confirm,
                  saved.planDigest == (try plan.digest) else { throw RouterSystemError.conflict }
            if try transaction.read("final-proof.json", maximum: 16384) != nil ||
                transaction.read("complete.json", maximum: 16384) != nil {
                // A completed old UUID must remain historical, including when a newer job exists.
                return try coordinator(service).apply(confirmedCandidate: plan.candidate.digest, installerLease: installer)
            }
        }
        let current = try preview(plan)
        let authorization = saved ?? current
        guard !authorization.registered, try authorization.digest == confirm,
              authorization.accepts(current) else { throw RouterSystemError.conflict }
        let tree = try RouterSystemInstallTree(parent: destination)
        // The read-only collection checked that these original lock inodes exist.
        let operation = try RouterSystemHostLease.acquire(in: tree.state, purpose: .operation)
        defer { withExtendedLifetime(operation) {} }
        let locked = try preview(plan)
        guard authorization.accepts(locked) else { throw RouterSystemError.conflict }
        if locked.registered {
            guard saved != nil else { throw RouterSystemError.conflict }
            // A healthy host owns host.lock. Observation-only continuation must not compete
            // for it, and must refuse if the registration disappears instead of replaying it.
            return try coordinator(ResumeRegistration(base: service, approved: authorization.socket, observingOnly: true))
                .apply(confirmedCandidate: plan.candidate.digest, installerLease: installer, heldOperationLease: operation)
        }
        let host = try RouterSystemHostLease.acquire(in: tree.state, purpose: .host)
        defer { host.release() }
        guard authorization.accepts(try preview(plan)) else { throw RouterSystemError.conflict }
        try RouterSystemInstallEncoding.save(RouterSystemInstallEncoding.encode(authorization), as: leaf, in: transaction)
        guard authorization.accepts(try preview(plan)) else { throw RouterSystemError.conflict }
        // A host can start during bootstrap. Let it acquire its own lease; the operation lease
        // remains held until installation completes, so no managed work may be dispatched.
        host.release()
        let authorized = ResumeRegistration(base: service, approved: authorization.socket)
        return try coordinator(authorized).apply(confirmedCandidate: plan.candidate.digest,
            installerLease: installer, heldOperationLease: operation)
    }
    private func coordinator(_ service: RouterSystemInstallService) -> RouterSystemInstallCoordinator {
        .init(registry: registry, transaction: transaction, destination: destination, launchDaemons: launchDaemons, service: service)
    }
    private struct ResumeRegistration: RouterSystemInstallService {
        let base: RouterSystemInstallService
        let approved: RouterSystemInstallNode?
        var observingOnly = false
        func job() throws -> RouterSystemInstallJob { try base.job() }
        func registrationObserved() throws -> Bool { try base.registrationObserved() }
        func observedSocket() throws -> RouterSystemInstallNode? { try base.observedSocket() }
        func authorizeResidualReplacement(_ node: RouterSystemInstallNode?) throws {
            guard node == nil else { throw RouterSystemError.conflict } // Original first-install plan.
            try base.authorizeResidualReplacement(approved)
        }
        func quiesce(original: RouterSystemInstallJob) throws { throw RouterSystemError.conflict }
        func register() throws {
            if observingOnly {
                guard try base.registrationObserved() else { throw RouterSystemError.operationUnsettled }
            } else { try base.register() }
        }
        func proof(identity: RouterSystemInstallationIdentity, retired: Bool) throws -> RouterSystemInstallServiceProof {
            guard !retired else { throw RouterSystemError.conflict }
            return try base.proof(identity: identity, retired: false)
        }
    }

    private func collect(_ plan: RouterSystemInstallPlan) throws -> RouterSystemInstallResumeObservation {
        try plan.validate()
        guard plan.candidate.action == .install, let root = plan.rootReceipt,
              try plan.candidate.destinationParent == .directory(destination),
              try plan.candidate.launchDaemonsParent == .directory(launchDaemons),
              try root.transactionDirectory == .directory(transaction) else { throw RouterSystemError.conflict }
        for leaf in ["final-proof.json", "complete.json", "active.closed", "active.publish"] {
            guard try transaction.read(leaf, maximum: 65536) == nil else { throw RouterSystemError.conflict }
        }
        guard try transaction.read("root.receipt", maximum: 65536) == root.encoded(),
              try transaction.read("frozen-tree.json", maximum: 65536) == RouterSystemInstallEncoding.encode(root.tree),
              try transaction.read("plan.json", maximum: 1024 * 1024) == RouterSystemInstallEncoding.encode(plan),
              try transaction.read("files-published.json", maximum: 65536) == RouterSystemInstallEncoding.encode(
                RouterSystemInstallPublished(version: 1, planDigest: plan.digest)),
              let receiptBytes = try transaction.read("active.receipt", maximum: 16384) else { throw RouterSystemError.conflict }
        let receipt = try RouterSystemInstallEncoding.decode(ActiveReceipt.self, receiptBytes)
        let active = try plan.active(in: transaction), activeBytes = try active.encoded()
        guard receipt.version == 1, receipt.active == active, try receipt.registry == .directory(registry),
              receipt.image == (try image("active.json", registry)),
              receipt.image.digest == RouterSystemObservation.hash(activeBytes), receipt.image.count == activeBytes.count else {
            throw RouterSystemError.conflict
        }
        let tree = try RouterSystemInstallTree(parent: destination)
        let parents = RouterSystemInstallParents(root: root.tree.root, bin: root.tree.bin,
            core: root.tree.core, run: root.tree.run, state: root.tree.state)
        guard try tree.parents() == parents else { throw RouterSystemError.conflict }
        for entry in plan.files {
            guard try transaction.read(entry.file.receiptLeaf("receipt"), maximum: 16384) == entry.encoded(),
                  try RouterSystemInstallEncoding.image(entry.file.leaf, in: tree.target(entry.file, launchDaemons: launchDaemons),
                    maximum: entry.file.maximum, mode: entry.file.mode) == entry.after,
                  try RouterSystemInstallEncoding.image(entry.file.receiptLeaf("publish"), in: transaction,
                    maximum: entry.file.maximum, mode: entry.file.mode) == nil,
                  try RouterSystemInstallEncoding.image(entry.file.receiptLeaf("retired"), in: transaction,
                    maximum: entry.file.maximum, mode: entry.file.mode) == nil else { throw RouterSystemError.conflict }
        }
        var stateFiles: [RouterSystemInstallImage] = []
        for entry in root.tree.files where entry.kind.installFile == nil {
            let value = try image(entry.kind.leaf, tree.state, maximum: entry.kind.maximum)
            guard value == entry.image else { throw RouterSystemError.conflict }
            stateFiles.append(value)
        }
        guard try tree.state.read("journal.json", maximum: RouterSystemJournalDecoder.maximumBytes) == plan.candidate.initialJournalBytes() else {
            throw RouterSystemError.conflict
        }
        let before = try service.registrationObserved(), socket = try service.observedSocket()
        guard try service.registrationObserved() == before, try service.observedSocket() == socket else { throw RouterSystemError.conflict }
        return .init(version: 1, planDigest: try plan.digest,
            records: try [image("active.json", registry), image("active.receipt", transaction), image("plan.json", transaction),
                          image("files-published.json", transaction), image("root.receipt", transaction), image("frozen-tree.json", transaction)],
            parents: parents, stateFiles: stateFiles, socket: socket, registered: before)
    }
    private func image(_ leaf: String, _ directory: RouterSystemDirectory, maximum: Int = 1024 * 1024) throws -> RouterSystemInstallImage {
        guard let value = try RouterSystemInstallEncoding.image(leaf, in: directory, maximum: maximum) else { throw RouterSystemError.conflict }
        return value
    }
}
