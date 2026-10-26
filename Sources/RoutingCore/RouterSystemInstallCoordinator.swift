import Foundation
import Darwin

struct RouterSystemInstallPublished: Codable, Equatable {
    let version: Int
    let planDigest: String
}

struct RouterSystemInstallFinalProof: Codable, Equatable {
    let version: Int
    let planDigest: String
    let service: RouterSystemInstallServiceProof
    let retiredDigest: String?
}

/// Resumes one sealed, confirmed transaction. The native entry retains the installer lease from
/// candidate revalidation through completion; existing installations also retain their operation
/// lease. No user-selected executable or filesystem path crosses this boundary.
final class RouterSystemInstallCoordinator {
    enum Boundary { case claimed, quiesced, filesPublished, serviceReady, proofSaved }
    private let registryDirectory: RouterSystemDirectory
    private let transaction: RouterSystemDirectory
    private let destination: RouterSystemDirectory
    private let launchDaemons: RouterSystemDirectory
    private let service: RouterSystemInstallService
    private let boundary: (Boundary) throws -> Void

    init(registry: RouterSystemDirectory, transaction: RouterSystemDirectory,
         destination: RouterSystemDirectory, launchDaemons: RouterSystemDirectory,
         service: RouterSystemInstallService, boundary: @escaping (Boundary) throws -> Void = { _ in }) {
        registryDirectory = registry; self.transaction = transaction
        self.destination = destination; self.launchDaemons = launchDaemons
        self.service = service; self.boundary = boundary
    }

    /// Private preparation follows an outer, read-only candidate recomputation under the same
    /// installer lease. A partial preparation is retained; this method never adopts or overwrites it.
    func prepare(candidate: RouterSystemInstallCandidate, payload: [RouterSystemInstallFile: Data],
                 initialJournal: Data?, installerLease: RouterSystemHostLease,
                 heldOperationLease: RouterSystemHostLease?) throws -> RouterSystemInstallPlan {
        try installerLease.verify(in: registryDirectory, purpose: .installer); try candidate.validate()
        defer { withExtendedLifetime((installerLease, heldOperationLease)) {} }
        guard try candidate.destinationParent == .directory(destination),
              try candidate.launchDaemonsParent == .directory(launchDaemons),
              try service.job() == candidate.originalJob,
              try registryDirectory.read("active.json", maximum: 8192) == nil,
              try transaction.read("plan.json", maximum: 1024 * 1024) == nil else { throw RouterSystemError.conflict }
        guard Set(payload.keys) == (candidate.action == .retire ? [] : Set(RouterSystemInstallFile.allCases)) else {
            throw RouterSystemError.invalidRequest
        }
        for file in candidate.files {
            guard payload[file.file].map(RouterSystemObservation.hash) == file.afterDigest,
                  payload[file.file]?.count == file.afterCount else { throw RouterSystemError.conflict }
        }
        let files = RouterSystemInstallTransaction(directory: transaction, id: candidate.transaction)
        var receipts: [RouterSystemInstallFileReceipt] = [], rootReceipt: RouterSystemInstallRoot.Receipt?
        if candidate.action == .install {
            guard let initialJournal, heldOperationLease == nil,
                  initialJournal == (try candidate.initialJournalBytes()) else {
                throw RouterSystemError.conflict
            }
            rootReceipt = try RouterSystemInstallRoot(transaction: transaction, destination: destination,
                id: candidate.transaction).stage(files: payload.filter { $0.key != .launchd }, initialJournal: initialJournal)
            let root = try transaction.installChild(.stagedRoot)
            for file in RouterSystemInstallFile.allCases {
                if file == .launchd { receipts.append(try files.stage(file, new: payload[file], target: launchDaemons)) }
                else {
                    let target: RouterSystemDirectory
                    switch file { case .helper: target = try root.installChild(.bin)
                    case .core: target = try root.installChild(.core); default: target = root }
                    receipts.append(try files.load(file, target: target))
                }
            }
        } else {
            guard initialJournal == nil, let heldOperationLease, let preserved = candidate.preserved else {
                throw RouterSystemError.conflict
            }
            let tree = try RouterSystemInstallTree(parent: destination)
            try heldOperationLease.verify(in: tree.state, purpose: .operation)
            try tree.verify(preserved, exactJournal: true)
            // Verify every before image before staging even the first file.
            for file in candidate.files {
                guard try RouterSystemInstallEncoding.image(file.file.leaf,
                    in: tree.target(file.file, launchDaemons: launchDaemons), maximum: file.file.maximum,
                    mode: file.file.mode) == file.before else { throw RouterSystemError.conflict }
            }
            for file in RouterSystemInstallFile.allCases {
                receipts.append(try files.stage(file, new: payload[file], target: tree.target(file, launchDaemons: launchDaemons)))
            }
            try tree.verify(preserved, exactJournal: true)
        }
        let plan = RouterSystemInstallPlan(version: 1, candidate: candidate, files: receipts, rootReceipt: rootReceipt)
        try plan.validate()
        try RouterSystemInstallEncoding.save(RouterSystemInstallEncoding.encode(plan), as: "plan.json", in: transaction)
        let retirement = RouterSystemInstallRetirement(registry: registryDirectory, transaction: transaction, launchDaemons: launchDaemons)
        if candidate.action == .retire { try retirement.prepare(plan: plan) }
        if candidate.action == .reinstall {
            try retirement.validateReinstall(plan: plan, tree: RouterSystemInstallTree(parent: destination), published: false)
        }
        try RouterSystemInstallRegistry(registry: registryDirectory, transaction: transaction).prepare(plan.active(in: transaction))
        return plan
    }

    func apply(confirmedCandidate: String, installerLease: RouterSystemHostLease,
               heldOperationLease: RouterSystemHostLease? = nil) throws -> RouterSystemInstallCompletion {
        try installerLease.verify(in: registryDirectory, purpose: .installer)
        defer { withExtendedLifetime(installerLease) {} }
        guard let bytes = try transaction.read("plan.json", maximum: 1024 * 1024) else {
            throw RouterSystemError.journalUnknown
        }
        let plan = try RouterSystemInstallPlan.decode(bytes), candidate = plan.candidate
        guard try candidate.digest == confirmedCandidate,
              try candidate.destinationParent == .directory(destination),
              try candidate.launchDaemonsParent == .directory(launchDaemons) else { throw RouterSystemError.conflict }
        let active = try plan.active(in: transaction)
        let registry = RouterSystemInstallRegistry(registry: registryDirectory, transaction: transaction)
        // A completed UUID is historical. In particular, never query/stop a newer installed job.
        if case .closed(let completed) = try registry.claim(active) { return completed }
        try service.authorizeResidualReplacement(candidate.priorSocket)
        try boundary(.claimed)
        let completion = try registry.pendingCompletion(active)
        let savedProof = try transaction.read("final-proof.json", maximum: 16384)
        let publishedBytes = try RouterSystemInstallEncoding.encode(
            RouterSystemInstallPublished(version: 1, planDigest: plan.digest))
        let published = try transaction.read("files-published.json", maximum: 16384)
        if let published {
            guard published == publishedBytes else { throw RouterSystemError.conflict }
            try RouterSystemInstallEncoding.save(published, as: "files-published.json", in: transaction)
        }
        guard (completion == nil && savedProof == nil) || published != nil else { throw RouterSystemError.journalUnknown }

        var initialOperation: RouterSystemHostLease?
        defer { withExtendedLifetime(initialOperation) {} }
        if published == nil, let receipt = plan.rootReceipt {
            let roots = RouterSystemInstallRoot(transaction: transaction, destination: destination, id: candidate.transaction)
            guard try roots.load() == receipt else { throw RouterSystemError.conflict }
            let position = try roots.position(receipt)
            guard let originalLock = receipt.tree.files.first(where: { $0.kind == .operationLock }),
                  let plist = plan.files.first(where: { $0.file == .launchd }) else { throw RouterSystemError.conflict }
            func prepublicationCheck() throws {
                guard try service.job() == .absent else { throw RouterSystemError.conflict }
                let current = try RouterSystemInstallEncoding.image(plist.file.leaf, in: launchDaemons,
                    maximum: plist.file.maximum, mode: plist.file.mode)
                guard current == nil || (position == .published && current == plist.after) else { throw RouterSystemError.conflict }
            }
            try prepublicationCheck()
            let parent = try position == .staged ? transaction.installChild(.stagedRoot) : destination.installChild(.installedRoot)
            let state = try parent.installChild(.state)
            guard try RouterSystemInstallEncoding.image("operation.lock", in: state, maximum: 1) == originalLock.image else {
                throw RouterSystemError.conflict
            }
            let lease = try heldOperationLease ?? RouterSystemHostLease.acquire(in: state, purpose: .operation)
            initialOperation = lease
            try lease.verify(in: state, purpose: .operation)
            guard try RouterSystemInstallEncoding.image("operation.lock", in: state, maximum: 1) == originalLock.image else {
                throw RouterSystemError.conflict
            }
            try prepublicationCheck()
            try roots.publish(receipt)
            try lease.rebindOperation(to: destination.installChild(.installedRoot).installChild(.state))
        }
        let tree = try RouterSystemInstallTree(parent: destination)
        let expectedLock: RouterSystemInstallImage
        if let preserved = candidate.preserved {
            try tree.verify(preserved, exactJournal: published == nil)
            expectedLock = preserved.operationLock
        } else {
            guard let original = plan.rootReceipt?.tree,
                  try tree.parents() == RouterSystemInstallParents(root: original.root, bin: original.bin,
                    core: original.core, run: original.run, state: original.state),
                  let lock = original.files.first(where: { $0.kind == .operationLock }) else { throw RouterSystemError.conflict }
            expectedLock = lock.image
        }
        // acquire may create a lock in other contexts. Here it must already be the original inode.
        guard try tree.operationImage() == expectedLock else { throw RouterSystemError.conflict }
        let operation = try initialOperation ?? heldOperationLease ?? RouterSystemHostLease.acquire(in: tree.state, purpose: .operation)
        try operation.verify(in: tree.state, purpose: .operation)
        defer { withExtendedLifetime(operation) {} }
        guard try tree.operationImage() == expectedLock else { throw RouterSystemError.conflict }
        if let preserved = candidate.preserved { try tree.verify(preserved, exactJournal: published == nil) }
        let retirement = RouterSystemInstallRetirement(registry: registryDirectory, transaction: transaction, launchDaemons: launchDaemons)
        if candidate.action == .reinstall { try retirement.validateReinstall(plan: plan, tree: tree, published: published != nil) }

        if published == nil {
            if let node = try service.observedSocket(), node != candidate.priorSocket { throw RouterSystemError.conflict }
            if candidate.action == .install || candidate.action == .reinstall {
                guard try service.job() == .absent else { throw RouterSystemError.conflict }
            } else { try service.quiesce(original: candidate.originalJob) }
            // Serializes with a demand activation racing the last job observation. The host takes
            // this lease before serving; its operation lease prevents dispatch while we maintain.
            let host = try RouterSystemHostLease.acquire(in: tree.state, purpose: .host)
            try host.verify(in: tree.state, purpose: .host)
            defer { withExtendedLifetime(host) {} }
            guard try service.job() == .absent else { throw RouterSystemError.operationUnsettled }
            try boundary(.quiesced)
            let files = RouterSystemInstallTransaction(directory: transaction, id: candidate.transaction)
            for receipt in plan.files {
                let target = tree.target(receipt.file, launchDaemons: launchDaemons)
                guard try files.load(receipt.file, target: target) == receipt else { throw RouterSystemError.conflict }
                try files.publish(receipt, target: target)
            }
            try verifyFiles(plan, tree: tree)
            try RouterSystemInstallEncoding.save(publishedBytes, as: "files-published.json", in: transaction)
            try boundary(.filesPublished)
        }
        // After publication, retry never boots out the host, reinitializes state or republishes root.
        try verifyFiles(plan, tree: tree)
        var retiredDigest: String?
        if candidate.action == .retire {
            retiredDigest = try retirement.publish(plan: plan, tree: tree)
        } else {
            if candidate.action == .reinstall { try retirement.consume(plan: plan, tree: tree) }
            // A saved terminal observation authorizes verification only, not registration replay.
            if savedProof == nil && completion == nil { try service.register() }
        }
        _ = try tree.journal(candidate.installation)
        let serviceProof = try service.proof(identity: candidate.installation, retired: candidate.action == .retire)
        guard serviceProof.installation == candidate.installation,
              serviceProof.registered == (candidate.action != .retire),
              (serviceProof.socketNode != nil) == serviceProof.registered,
              serviceProof.residualSocketNode == nil ||
                (candidate.action == .retire && serviceProof.residualSocketNode == candidate.priorSocket) else {
            throw RouterSystemError.conflict
        }
        try boundary(.serviceReady)
        let proof = RouterSystemInstallFinalProof(version: 1, planDigest: try plan.digest,
            service: serviceProof, retiredDigest: retiredDigest)
        let proofBytes = try RouterSystemInstallEncoding.encode(proof)
        if let savedProof { guard savedProof == proofBytes else { throw RouterSystemError.conflict } }
        if let completion {
            guard savedProof != nil, completion.proofDigest == RouterSystemObservation.hash(proofBytes) else {
                throw RouterSystemError.conflict
            }
            try registry.finish(completion)
            return completion
        }
        try RouterSystemInstallEncoding.save(proofBytes, as: "final-proof.json", in: transaction)
        try boundary(.proofSaved)
        let result = RouterSystemInstallCompletion(version: 1, active: active,
            proofDigest: RouterSystemObservation.hash(proofBytes))
        try registry.finish(result)
        return result
    }

    private func verifyFiles(_ plan: RouterSystemInstallPlan, tree: RouterSystemInstallTree) throws {
        let files = RouterSystemInstallTransaction(directory: transaction, id: plan.candidate.transaction)
        for receipt in plan.files {
            let target = tree.target(receipt.file, launchDaemons: launchDaemons)
            guard try files.load(receipt.file, target: target) == receipt,
                  try RouterSystemInstallEncoding.image(receipt.file.leaf, in: target,
                    maximum: receipt.file.maximum, mode: receipt.file.mode) == receipt.after,
                  try RouterSystemInstallEncoding.image(receipt.file.receiptLeaf("retired"), in: transaction,
                    maximum: receipt.file.maximum, mode: receipt.file.mode) == receipt.before,
                  try RouterSystemInstallEncoding.image(receipt.file.receiptLeaf("publish"), in: transaction,
                    maximum: receipt.file.maximum, mode: receipt.file.mode) == nil else {
                throw RouterSystemError.conflict
            }
        }
    }
}
