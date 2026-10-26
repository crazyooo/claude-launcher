import Foundation
import Security
import Darwin

/// Immutable staging; a successful check is not an execution grant.
final class RouterSystemStage {
    private struct Receipt: Encodable {
        let version = 1
        let installation: RouterSystemInstallationIdentity
        let instance: UUID
        let planDigest: String
        let coreSHA256 = RouterCoreRelease.executableSHA256
    }
    private let directory: RouterSystemDirectory
    private let identity: RouterSystemInstallationIdentity
    private let verifyCode: () throws -> Void
    private let check: (UUID) throws -> RouterProcessResult
    private let synchronize: (Int32) -> Int32
    private let lock = NSLock()
    private static let maximumConfiguration = 4 * RouterInput.maximumBytes

    convenience init(installation: RouterSystemInstallation, command: RouterSystemCommand) throws {
        try installation.verifyCode()
        self.init(directory: installation.state, identity: installation.manifest.identity,
                  verifyCode: installation.verifyCode, check: { try command.run(.validateCore($0)).0 })
    }
    private init(directory: RouterSystemDirectory, identity: RouterSystemInstallationIdentity,
                 verifyCode: @escaping () throws -> Void, check: @escaping (UUID) throws -> RouterProcessResult,
                 synchronize: @escaping (Int32) -> Int32 = fsync) {
        self.directory = directory; self.identity = identity; self.verifyCode = verifyCode; self.check = check
        self.synchronize = synchronize
    }
    static func fixture(directory: RouterSystemDirectory, identity: RouterSystemInstallationIdentity,
                        verifyCode: @escaping () throws -> Void = {},
                        synchronize: @escaping (Int32) -> Int32 = fsync,
                        check: @escaping (UUID) throws -> RouterProcessResult) throws -> RouterSystemStage {
        guard getuid() != 0, geteuid() != 0, identity.isValid else { throw RouterSystemError.ownershipUnknown }
        return .init(directory: directory, identity: identity, verifyCode: verifyCode, check: check, synchronize: synchronize)
    }

    func stage(_ intent: RouterSystemIntent, credentials: [UUID: RouterCredential]) throws -> String {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try verifyCode()
        guard intent.digest == (try RouterSystemCompiler.digest(plan: intent.plan, profile: intent.profile)) else {
            throw RouterSystemError.invalidPlan
        }
        // Validate all inputs and the main resolver path before writing anything private.
        let precheck = try compile(intent, credentials: credentials, secret: String(repeating: "0", count: 64))
        guard precheck.summary.resolverRoute == "resolver_route_planned_not_verified" else {
            throw RouterSystemError.configurationRejected
        }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let receipt = try encoder.encode(Receipt(installation: identity, instance: intent.id, planDigest: intent.digest))
        let name = "stage-" + intent.id.uuidString.lowercased()
        let stage: RouterSystemDirectory
        if let existing = try directory.childIfPresent(name) { stage = existing }
        else {
            try directory.boundedEntryCount(maximum: 60) // Leave room for the journal/lock and uncertain-write evidence.
            stage = try directory.createDirectory(name)
        }
        if let previous = try stage.read("receipt.json", maximum: 4096) {
            guard previous == receipt else { throw RouterSystemError.conflict }
        } else {
            try stage.boundedEntryCount(maximum: 1) // Only an empty mkdir-only interruption may continue.
            try create(receipt, named: "receipt.json", in: stage)
        }
        let previousConfiguration = try stage.read("config.json", maximum: Self.maximumConfiguration)
        let secret: Data
        if let existing = try stage.read("controller-secret", maximum: 64) { secret = existing }
        else {
            guard previousConfiguration == nil else { throw RouterSystemError.ownershipUnknown }
            secret = try Self.randomSecret()
            try create(secret, named: "controller-secret", in: stage)
        }
        guard let text = String(data: secret, encoding: .utf8), RouterSystemProvider.validDigest(text) else {
            throw RouterSystemError.ownershipUnknown
        }
        let configuration = try compile(intent, credentials: credentials, secret: text).privateJSON
        if let previousConfiguration {
            guard previousConfiguration == configuration else { throw RouterSystemError.conflict }
        } else { try create(configuration, named: "config.json", in: stage) }

        func verifyFiles() throws {
            guard try stage.read("receipt.json", maximum: 4096) == receipt,
                  try stage.read("controller-secret", maximum: 64) == secret,
                  try stage.read("config.json", maximum: Self.maximumConfiguration) == configuration else {
                throw RouterSystemError.ownershipUnknown
            }
        }
        try verifyFiles(); try verifyCode()
        let outcome = Result { try check(intent.id) }
        try verifyCode(); try verifyFiles() // Also check after timeout, failure and thrown command outcomes.
        let result = try outcome.get()
        guard result.settled else { throw RouterSystemError.operationUnsettled }
        guard !result.timedOut, result.exitCode == 0 else { throw RouterSystemError.configurationRejected }
        // Retry must settle earlier unknown fsync outcomes, even when every file already exists.
        for (name, bytes) in [("receipt.json", receipt), ("controller-secret", secret), ("config.json", configuration)] {
            try stage.synchronizeFile(name, expected: bytes, synchronize: synchronize)
        }
        try stage.validate()
        guard synchronize(stage.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
        guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try verifyCode(); try verifyFiles()
        return RouterSystemObservation.hash(configuration)
    }

    /// Checks the immutable, previously validated configuration without requesting credentials again.
    func verify(_ intent: RouterSystemIntent, configurationDigest: String) throws {
        _ = try controllerSecret(intent, configurationDigest: configurationDigest)
    }

    /// Returned only inside the root runtime; never part of status, command arguments or logs.
    func controllerSecret(_ intent: RouterSystemIntent, configurationDigest: String) throws -> String {
        try controllerMaterial(intent, configurationDigest: configurationDigest).secret
    }

    func controllerMaterial(_ intent: RouterSystemIntent, configurationDigest: String) throws -> RouterConnectionMaterial {
        guard lock.try() else { throw RouterSystemError.operationUnsettled }
        defer { lock.unlock() }
        try verifyCode()
        guard RouterSystemProvider.validDigest(configurationDigest),
              intent.digest == (try RouterSystemCompiler.digest(plan: intent.plan, profile: intent.profile)) else {
            throw RouterSystemError.configurationRejected
        }
        let stage = try directory.child("stage-" + intent.id.uuidString.lowercased())
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let receipt = try encoder.encode(Receipt(installation: identity, instance: intent.id, planDigest: intent.digest))
        guard try stage.read("receipt.json", maximum: 4096) == receipt,
              let bytes = try stage.read("config.json", maximum: Self.maximumConfiguration),
              RouterSystemObservation.hash(bytes) == configurationDigest,
              let secret = try stage.read("controller-secret", maximum: 64),
              let secretText = String(data: secret, encoding: .utf8), RouterSystemProvider.validDigest(secretText) else {
            throw RouterSystemError.ownershipUnknown
        }
        let object = try RouterStrictJSON.object(bytes, maximumBytes: Self.maximumConfiguration, maximumValues: 80_000)
        guard object["secret"] as? String == secretText else { throw RouterSystemError.ownershipUnknown }
        try verifyCode()
        guard try stage.read("receipt.json", maximum: 4096) == receipt,
              try stage.read("config.json", maximum: Self.maximumConfiguration) == bytes,
              try stage.read("controller-secret", maximum: 64) == secret else { throw RouterSystemError.ownershipUnknown }
        return try RouterConnectionMaterial.read(object)
    }

    /// Historical material capability. It is neither Codable nor an execution grant.
    /// Only this Stage can construct it after validating the original three files.
    final class EvidenceSource {
        let installation: RouterSystemInstallationIdentity
        let intent: RouterSystemIntent
        let configurationDigest: String
        let receiptDigest: String
        private let stage: RouterSystemDirectory
        private let images: EvidenceImages
        private let materialCheck: () throws -> Void

        fileprivate init(installation: RouterSystemInstallationIdentity, intent: RouterSystemIntent,
                         configurationDigest: String, stage: RouterSystemDirectory, images: EvidenceImages,
                         materialCheck: @escaping () throws -> Void) {
            self.installation = installation; self.intent = intent; self.configurationDigest = configurationDigest
            self.stage = stage; self.images = images; self.materialCheck = materialCheck
            receiptDigest = images.receipt.digest
        }
        private func verify() throws {
            try materialCheck()
            guard try EvidenceImages.read(stage) == images else { throw RouterTrafficEvidenceError.sourceChanged }
            try stage.validate()
        }
        func withVerifiedDirectory<T>(_ body: (RouterSystemDirectory) throws -> T) throws -> T {
            try verify()
            let result = Result { try body(stage) }
            try verify()
            return try result.get()
        }
        func matches(_ binding: RouterTrafficBinding) -> Bool {
            binding.installation == installation && binding.instance == intent.id &&
            binding.planDigest == intent.digest && binding.configurationDigest == configurationDigest &&
            binding.stageReceiptDigest == receiptDigest && binding.work.bootID == intent.issued.bootID &&
            binding.coreVersion == RouterCoreRelease.version &&
            binding.coreSHA256 == RouterCoreRelease.executableSHA256 &&
            binding.compilerPolicy == RouterSystemCompiler.policyVersion
        }
    }

    fileprivate struct EvidenceImages: Equatable {
        let receipt: RouterSystemInstallImage
        let configuration: RouterSystemInstallImage
        let secret: RouterSystemInstallImage
        static func read(_ directory: RouterSystemDirectory) throws -> Self {
            func image(_ name: String, maximum: Int) throws -> RouterSystemInstallImage {
                guard let value = try RouterSystemInstallEncoding.image(name, in: directory, maximum: maximum) else {
                    throw RouterTrafficEvidenceError.sourceChanged
                }
                return value
            }
            return try .init(receipt: image("receipt.json", maximum: 4096),
                configuration: image("config.json", maximum: RouterSystemStage.maximumConfiguration),
                secret: image("controller-secret", maximum: 64))
        }
    }

    func evidenceSource(_ intent: RouterSystemIntent, configurationDigest: String) throws -> EvidenceSource {
        _ = try controllerMaterial(intent, configurationDigest: configurationDigest)
        let stage = try directory.child("stage-" + intent.id.uuidString.lowercased())
        let images = try EvidenceImages.read(stage)
        _ = try controllerMaterial(intent, configurationDigest: configurationDigest)
        guard try EvidenceImages.read(stage) == images else { throw RouterTrafficEvidenceError.sourceChanged }
        return .init(installation: identity, intent: intent, configurationDigest: configurationDigest,
                     stage: stage, images: images, materialCheck: {
            _ = try self.controllerMaterial(intent, configurationDigest: configurationDigest)
        })
    }

    private func compile(_ intent: RouterSystemIntent, credentials: [UUID: RouterCredential], secret: String) throws -> RouterSystemConfiguration {
        let value = try RouterSystemCompiler.compile(plan: intent.plan, profile: intent.profile, secret: secret, credentials: credentials)
        guard value.privateJSON.count <= Self.maximumConfiguration else { throw RouterSystemError.configurationRejected }
        return value
    }
    private func create(_ bytes: Data, named name: String, in directory: RouterSystemDirectory) throws {
        try directory.create(name, data: bytes)
        guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        try directory.validate()
    }
    private static func randomSecret() throws -> Data {
        var bytes = [UInt8](repeating: 0, count: 32)
        let result = bytes.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, $0.count, $0.baseAddress!) }
        guard result == errSecSuccess else { throw RouterSystemError.operationUnsettled }
        return Data(bytes.map { String(format: "%02x", $0) }.joined().utf8)
    }
}
