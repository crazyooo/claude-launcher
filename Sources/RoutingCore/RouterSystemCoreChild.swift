import Foundation
import Darwin

/// Installed root helper's private child entry. Permission is consumed by the parent;
/// this process verifies it independently, then becomes the fixed core using execve.
public enum RouterSystemCoreChild {
    struct Operations {
        var load: (TimeInterval) throws -> RouterSystemJournal
        var clock: () throws -> RouterSystemClock
        var identity: (RouterSystemDispatchFence) throws -> RouterSystemWork
        var claim: (RouterSystemIntent, RouterSystemDispatchFence) throws -> Void
        var stage: (RouterSystemIntent, String) throws -> Void
        var receive: (UUID, TimeInterval) throws -> Void
        var prepareExec: (UUID) throws -> Void
        var execute: () throws -> Never
    }

    public static func run(_ arguments: [String]) throws -> Never {
        let instance = try instance(arguments)
        guard getuid() == 0, geteuid() == 0 else { throw RouterSystemError.ownershipUnknown }
        try RouterOwnedChild.requireExclusiveReaping()
        var input = stat()
        guard fstat(STDIN_FILENO, &input) == 0, input.st_mode & S_IFMT == S_IFIFO else {
            throw RouterSystemError.ownershipUnknown
        }
        let installation = try RouterSystemInstallation.verify()
        let journal = try RouterSystemJournalStore(directory: installation.state, installation: installation.manifest.identity)
        let baseline = try RouterSystemBaselineStore(installation: installation)
        let command = try RouterSystemCommand(ownerUID: installation.manifest.ownerUID)
        let stage = try RouterSystemStage(installation: installation, command: command)
        var image: ExecImage?
        return try perform(instance: instance, installation: installation.manifest.identity,
            operations: .init(load: { try journal.load(until: $0) }, clock: RouterSystemKernelObservation.clock,
                identity: verifyIdentity, claim: baseline.verifyClaim, stage: stage.verify,
                receive: { try RouterSystemGate.receive(fd: STDIN_FILENO, instance: $0, deadline: $1) },
                prepareExec: { image = try ExecImage(instance: $0, installation: installation) },
                execute: {
                    guard let image else { throw RouterSystemError.operationUnsettled }
                    return try image.execute()
                }))
    }

    static func instance(_ arguments: [String]) throws -> UUID {
        guard arguments.count == 2, arguments[0] == "--core-child", let id = UUID(uuidString: arguments[1]),
              arguments[1] == id.uuidString.lowercased() else { throw RouterSystemError.invalidRequest }
        return id
    }

    /// Test effects never become root execution paths or IPC parameters.
    static func fixture(instance: UUID, installation: RouterSystemInstallationIdentity, operations: Operations) throws -> Never {
        guard getuid() != 0, geteuid() != 0 else { throw RouterSystemError.ownershipUnknown }
        return try perform(instance: instance, installation: installation, operations: operations)
    }

    private static func perform(instance: UUID, installation: RouterSystemInstallationIdentity, operations: Operations) throws -> Never {
        let began = try operations.clock(), initialDeadline = began.uptime + 2
        guard began.uptime.isFinite, began.uptime >= 0, initialDeadline.isFinite,
              began.date.timeIntervalSince1970.isFinite else { throw RouterSystemError.stalePreview }
        // No intent yet: a short read-availability budget, never an execution grant.
        let initial = try operations.load(initialDeadline), ended = try operations.clock()
        guard ended.bootID == began.bootID, ended.uptime >= began.uptime, ended.uptime < initialDeadline,
              ended.date >= began.date, ended.date.timeIntervalSince1970.isFinite else { throw RouterSystemError.stalePreview }
        try RouterSystemProvider.validateJournal(initial)
        guard initial.installation == installation, initial.phase == .applying,
              let intent = initial.intent, intent.id == instance,
              let fence = initial.dispatch, let digest = initial.configurationDigest else {
            throw RouterSystemError.ownershipUnknown
        }
        try RouterSystemProvider.validateDispatch(fence, intent: intent, configurationDigest: digest)
        let work = try operations.identity(fence)
        guard work.pid > 0, work.pid != fence.host.pid, work.bootID == fence.host.bootID,
              initial.work == nil || initial.work == work else { throw RouterSystemError.ownershipUnknown }
        func fresh() throws {
            let now = try operations.clock()
            guard now.uptime.isFinite, now.date.timeIntervalSince1970.isFinite,
                  now.bootID == intent.issued.bootID, now.uptime >= intent.issued.uptime, now.uptime < intent.deadlineUptime,
                  now.date >= intent.issued.date, now.date < intent.expiresAt else { throw RouterSystemError.stalePreview }
        }
        func bound() throws -> RouterSystemJournal {
            try fresh()
            let state = try operations.load(intent.deadlineUptime)
            try fresh()
            try RouterSystemProvider.validateJournal(state)
            guard state.installation == installation, state.phase == .applying, state.intent == intent,
                  state.dispatch == fence, state.configurationDigest == digest, state.work == work else {
                throw RouterSystemError.ownershipUnknown
            }
            return state
        }
        try fresh()
        try operations.claim(intent, fence)
        // Parent may still be saving work when this starts; only after UUID+EOF is work required.
        try operations.receive(instance, fence.gateDeadlineUptime)
        let authorized = try bound()
        guard try operations.identity(fence) == work else { throw RouterSystemError.ownershipUnknown }
        try fresh()
        try operations.claim(intent, fence)
        try operations.stage(intent, digest)
        try operations.prepareExec(instance)
        // Preparation and code verification consume the original deadline; never mint another one.
        try operations.stage(intent, digest)
        guard try bound().revision == authorized.revision, try operations.identity(fence) == work else {
            throw RouterSystemError.ownershipUnknown
        }
        try fresh()
        return try operations.execute()
    }

    private static func verifyIdentity(_ fence: RouterSystemDispatchFence) throws -> RouterSystemWork {
        let observed = try RouterSystemKernelObservation.Reader.live.process(getpid())
        let own = try RouterSystemKernelObservation.executable(observed.work, expected: [RouterSystemLayout.helper])
        let parent = try RouterSystemKernelObservation.executable(fence.host, expected: [RouterSystemLayout.helper])
        guard own.work.pid != fence.host.pid, own.work.bootID == fence.host.bootID,
              own.parentPID == fence.host.pid, own.processGroup == fence.processGroup,
              parent.processGroup == fence.processGroup, fence.processGroup == fence.host.pid,
              getppid() == fence.host.pid, getpgrp() == fence.processGroup else { throw RouterSystemError.ownershipUnknown }
        return own.work
    }

    private final class ExecImage {
        private var arguments: [UnsafeMutablePointer<CChar>?]
        private var environment: [UnsafeMutablePointer<CChar>?]
        init(instance: UUID, installation: RouterSystemInstallation) throws {
            let name = "stage-" + instance.uuidString.lowercased()
            let directory = try installation.state.child(name), path = RouterSystemLayout.state + "/" + name
            arguments = [RouterSystemLayout.core, "-d", path, "-f", path + "/config.json"].map { $0.withCString { strdup($0) } }
            environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C", "HOME=" + path].map { $0.withCString { strdup($0) } }
            // A throwing initializer releases these manually: deinit is not guaranteed before full initialization.
            guard arguments.allSatisfy({ $0 != nil }), environment.allSatisfy({ $0 != nil }) else {
                arguments.forEach { free($0) }; environment.forEach { free($0) }
                arguments = []; environment = []
                throw RouterSystemError.operationUnsettled
            }
            arguments.append(nil); environment.append(nil)
            let null = open("/dev/null", O_RDWR | O_CLOEXEC)
            guard null >= 0 else { throw RouterSystemError.operationUnsettled }
            defer { close(null) }
            for descriptor in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] {
                guard dup2(null, descriptor) == descriptor else { throw RouterSystemError.operationUnsettled }
            }
            _ = umask(0o077)
            try directory.validate()
            guard fchdir(directory.fd) == 0 else { throw RouterSystemError.ownershipUnknown }
        }
        deinit { arguments.forEach { free($0) }; environment.forEach { free($0) } }
        func execute() throws -> Never {
            execve(RouterSystemLayout.core, &arguments, &environment)
            throw RouterSystemError.operationUnsettled // Returning is a failure; never spawn a replacement.
        }
    }
}
