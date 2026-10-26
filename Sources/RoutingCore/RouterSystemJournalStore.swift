import Foundation
import Darwin

enum RouterSystemJournalDecoder {
    static let maximumBytes = 4 * RouterInput.maximumBytes
    static func decode(_ data: Data) throws -> RouterSystemJournal {
        do {
            let input = try RouterStrictJSON.object(data, maximumBytes: maximumBytes, maximumValues: 80_000)
            let state = try JSONDecoder().decode(RouterSystemJournal.self, from: data)
            let canonical = try JSONSerialization.jsonObject(with: JSONEncoder().encode(state))
            guard sameStructure(input, canonical) else { throw RouterSystemError.journalUnknown }
            try RouterSystemProvider.validateJournal(state)
            return state
        } catch { throw RouterSystemError.journalUnknown }
    }
    /// Codable ignores unknown fields. Compare all nested keys to its canonical encoding,
    /// including enum payloads and arrays; explicit null for an omitted optional is rejected.
    private static func sameStructure(_ input: Any, _ encoded: Any) -> Bool {
        if let a = input as? [String: Any], let b = encoded as? [String: Any] {
            return Set(a.keys) == Set(b.keys) && a.allSatisfy { sameStructure($0.value, b[$0.key]!) }
        }
        if let a = input as? [Any], let b = encoded as? [Any] {
            return a.count == b.count && zip(a, b).allSatisfy { sameStructure($0, $1) }
        }
        if input is [String: Any] || input is [Any] || input is NSNull { return false }
        return !(encoded is [String: Any]) && !(encoded is [Any]) && !(encoded is NSNull)
    }
}

/// Missing state is an installation/recovery error. Never mint a fresh revision on service restart.
final class RouterSystemJournalStore {
    private let directory: RouterSystemDirectory
    private let installation: RouterSystemInstallationIdentity
    private let lockFD: Int32
    private let synchronize: (Int32) -> Int32
    private let inProcessLock = NSLock()
    private var baseline: (revision: UUID, bytes: Data)?

    init(directory: RouterSystemDirectory, installation: RouterSystemInstallationIdentity,
         synchronize: @escaping (Int32) -> Int32 = fsync) throws {
        guard installation.isValid else { throw RouterSystemError.ownershipUnknown }
        self.directory = directory; self.installation = installation; self.synchronize = synchronize
        lockFD = openat(directory.fd, "journal.lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0o600)
        guard lockFD >= 0 else { throw RouterSystemError.journalUnknown }
        do { _ = try directory.regular(lockFD, mode: 0o600) }
        catch { close(lockFD); throw error }
    }
    deinit { close(lockFD) }

    /// Installer only, after verifying a genuinely new installation. O_EXCL cannot overwrite any old state.
    func initialize() throws {
        try locked {
            var initial = RouterSystemJournal.empty()
            initial.installation = installation
            let data = try JSONEncoder().encode(initial)
            _ = try decodeBound(data)
            try directory.create("journal.json", data: data)
            guard synchronize(directory.fd) == 0 else { throw RouterSystemError.journalUnknown }
        }
    }
    func load() throws -> RouterSystemJournal {
        try loadBounded(until: nil)
    }
    func load(until deadline: TimeInterval) throws -> RouterSystemJournal {
        try loadBounded(until: deadline)
    }
    private func loadBounded(until deadline: TimeInterval?) throws -> RouterSystemJournal {
        try locked(until: deadline) {
            baseline = nil
            let bytes = try currentBytes()
            let state = try decodeBound(bytes)
            baseline = (state.revision, bytes)
            return state
        }
    }
    func save(_ state: RouterSystemJournal, expecting revision: UUID) throws {
        try saveBounded(state, expecting: revision, until: nil)
    }
    func save(_ state: RouterSystemJournal, expecting revision: UUID, until deadline: TimeInterval) throws {
        try saveBounded(state, expecting: revision, until: deadline)
    }
    /// Preserve the entire stopped instance before a new prepare replaces it. Retry verifies and
    /// synchronizes the same bytes; partial or conflicting history is never overwritten.
    func archiveEnvironment(_ state: RouterSystemJournal) throws {
        try locked {
            let bytes = try currentBytes(), current = try decodeBound(bytes)
            guard let previous = baseline, previous.bytes == bytes, previous.revision == state.revision,
                  current.phase == .stopped, current.usedEnvironmentReviewIDs != nil,
                  current.intent?.id == state.intent?.id else { throw RouterSystemError.conflict }
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            guard try encoder.encode(current) == encoder.encode(state), let instance = current.intent?.id else {
                throw RouterSystemError.conflict
            }
            let stage = try directory.child("stage-" + instance.uuidString.lowercased())
            let name = "environment-history.json"
            if let old = try stage.read(name, maximum: RouterSystemJournalDecoder.maximumBytes) {
                guard old == bytes else { throw RouterSystemError.conflict }
            } else {
                try stage.boundedEntryCount(maximum: 64)
                try stage.create(name, data: bytes)
            }
            try stage.synchronizeFile(name, expected: bytes, synchronize: synchronize)
            try stage.validate(); try directory.validate()
            guard synchronize(stage.fd) == 0, synchronize(directory.fd) == 0,
                  try currentBytes() == bytes, try stage.read(name, maximum: RouterSystemJournalDecoder.maximumBytes) == bytes else {
                throw RouterSystemError.journalUnknown
            }
        }
    }
    private func saveBounded(_ state: RouterSystemJournal, expecting revision: UUID, until deadline: TimeInterval?) throws {
        try locked(until: deadline) {
            guard let previous = baseline, previous.revision == revision else { throw RouterSystemError.journalUnknown }
            let current = try currentBytes()
            guard current == previous.bytes else { throw RouterSystemError.conflict }
            _ = try decodeBound(current)
            let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
            let bytes = try encoder.encode(state)
            guard state.revision != revision else { throw RouterSystemError.conflict }
            _ = try decodeBound(bytes)
            try directory.boundedEntryCount(maximum: 64)
            // From here every failed write requires a fresh load, even if replacement may not have occurred.
            baseline = nil
            let temporary = "journal-" + UUID().uuidString.lowercased()
            try directory.create(temporary, data: bytes)
            guard try currentBytes() == current,
                  try directory.read(temporary, maximum: RouterSystemJournalDecoder.maximumBytes) == bytes else { throw RouterSystemError.journalUnknown }
            guard renameat(directory.fd, temporary, directory.fd, "journal.json") == 0 else { throw RouterSystemError.journalUnknown }
            guard synchronize(directory.fd) == 0, try currentBytes() == bytes else { throw RouterSystemError.journalUnknown }
            baseline = (state.revision, bytes)
        }
    }
    private func decodeBound(_ bytes: Data) throws -> RouterSystemJournal {
        let state = try RouterSystemJournalDecoder.decode(bytes)
        guard state.installation == installation else { throw RouterSystemError.ownershipUnknown }
        return state
    }
    private func currentBytes() throws -> Data {
        guard let value = try directory.read("journal.json", maximum: RouterSystemJournalDecoder.maximumBytes) else { throw RouterSystemError.journalUnknown }
        return value
    }
    private func locked<T>(until deadline: TimeInterval? = nil, _ body: () throws -> T) throws -> T {
        guard inProcessLock.try() else { throw RouterSystemError.operationUnsettled }
        defer { inProcessLock.unlock() }
        func withinDeadline() throws {
            if let deadline {
                guard deadline.isFinite, deadline >= 0 else { throw RouterSystemError.invalidRequest }
                guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.stalePreview }
            }
        }
        func verifyLock() throws {
            try directory.validate()
            _ = try directory.regular(lockFD, mode: 0o600)
            var linked = stat(), held = stat()
            guard fstat(lockFD, &held) == 0, fstatat(directory.fd, "journal.lock", &linked, AT_SYMLINK_NOFOLLOW) == 0,
                  RouterSystemDirectory.unchanged(held, linked) else { throw RouterSystemError.ownershipUnknown }
        }
        while true {
            try withinDeadline(); try verifyLock(); try withinDeadline()
            if flock(lockFD, LOCK_EX | LOCK_NB) == 0 { break }
            let failure = errno
            guard let deadline, failure == EWOULDBLOCK || failure == EAGAIN else { throw RouterSystemError.operationUnsettled }
            try withinDeadline()
            Thread.sleep(forTimeInterval: min(0.005, max(0, deadline - ProcessInfo.processInfo.systemUptime)))
        }
        defer { flock(lockFD, LOCK_UN) }
        try verifyLock(); try withinDeadline()
        let result = try body()
        try withinDeadline() // A late save is an unknown result, never a new execution permission.
        return result
    }
}
