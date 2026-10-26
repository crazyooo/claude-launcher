import Foundation
import Darwin

enum RouterSystemInstallPlist {
    static func bytes(ownerUID: UInt32) throws -> Data {
        guard ownerUID >= 501, ownerUID < UInt32.max else { throw RouterSystemError.invalidRequest }
        return try PropertyListSerialization.data(fromPropertyList: [
            "Label": RouterSystemLayout.label,
            "ProgramArguments": [RouterSystemLayout.helper, "--host"],
            "UserName": "root", "GroupName": "wheel", "RunAtLoad": false, "KeepAlive": false,
            "AbandonProcessGroup": false, "WorkingDirectory": RouterSystemLayout.state,
            "EnvironmentVariables": ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"],
            "Sockets": ["Control": ["SockPathName": RouterSystemLayout.socket, "SockType": "stream",
                                      "SockPathOwner": ownerUID, "SockPathGroup": 0, "SockPathMode": 384]]
        ] as [String: Any], format: .xml, options: 0)
    }
}

/// Parser for the observed macOS launchctl print format. Only top-level fields and exact argv are
/// accepted; a matching string hidden in an environment or nested job cannot establish ownership.
///
/// Nested LWCR / cdhash blocks on modern macOS use irregular indentation and `=> {` dictionaries.
/// Those nests are skipped for ownership; root path/program/domain/arguments/pid remain exact.
enum RouterSystemInstallJobParser {
    static func pid(_ bytes: Data) throws -> Int32? {
        guard bytes.count <= 65536, !bytes.contains(0), let text = String(data: bytes, encoding: .utf8) else {
            throw RouterSystemError.ownershipUnknown
        }
        let lines = text.components(separatedBy: .newlines)
        guard lines.first == "system/" + RouterSystemLayout.label + " = {",
              lines.last(where: { !$0.isEmpty }) == "}" else { throw RouterSystemError.ownershipUnknown }
        var depth = 1, fieldsAtRoot: [String] = []
        for line in lines.dropFirst() where !line.isEmpty {
            let tabs = line.prefix(while: { $0 == "\t" }).count
            let content = String(line.dropFirst(tabs))
            if content == "}" {
                depth -= 1
                guard depth >= 0 else { throw RouterSystemError.ownershipUnknown }
                // Closing braces may sit at the parent indent (tabs == depth after decrement).
                continue
            }
            guard depth > 0 else { throw RouterSystemError.ownershipUnknown }
            if depth == 1 {
                // Root fields must be exactly one tab; anything else is a format break.
                guard tabs == 1 else { throw RouterSystemError.ownershipUnknown }
                fieldsAtRoot.append(line)
            } else if tabs < depth {
                // Nested content must not underrun its parent indent (blocks forged root fields).
                throw RouterSystemError.ownershipUnknown
            }
            if content.hasSuffix(" = {") || content.hasSuffix(" => {") {
                depth += 1
            }
        }
        guard depth == 0 else { throw RouterSystemError.ownershipUnknown }
        func values(_ name: String) -> [String] {
            let prefix = "\t" + name + " = "
            return fieldsAtRoot.filter { $0.hasPrefix(prefix) }.map { String($0.dropFirst(prefix.count)) }
        }
        guard values("path") == [RouterSystemLayout.launchDaemons + "/" + RouterSystemInstallFile.launchd.leaf],
              values("program") == [RouterSystemLayout.helper], values("domain") == ["system"],
              values("arguments") == ["{"],
              let start = lines.firstIndex(of: "\targuments = {"),
              let end = lines[(start + 1)...].firstIndex(of: "\t}"),
              Array(lines[(start + 1)..<end]) == ["\t\t" + RouterSystemLayout.helper, "\t\t--host"] else {
            throw RouterSystemError.ownershipUnknown
        }
        let fields = values("pid")
        guard fields.count <= 1 else { throw RouterSystemError.ownershipUnknown }
        if let field = fields.first {
            guard let pid = Int32(field), pid > 1, field == String(pid) else { throw RouterSystemError.ownershipUnknown }
            return pid
        }
        guard values("state").count == 1, values("state") != ["running"] else { throw RouterSystemError.ownershipUnknown }
        return nil
    }
}

/// Concrete fixed launchd adapter. Constructed only by the native root installer. It never runs the
/// core or changes proxies; registration only exposes the host's demand-activated control socket.
final class RouterSystemInstallNativeService: RouterSystemInstallService {
    private let ownerUID: UInt32
    private var permittedResidual: RouterSystemInstallNode?
    func observedSocket() throws -> RouterSystemInstallNode? { try socket() }
    func authorizeResidualReplacement(_ node: RouterSystemInstallNode?) throws { permittedResidual = node }
    private func requireConfirmedResidual() throws {
        // Some macOS versions remove the node; others retain it. Never adopt a new one.
        if let node = try socket(), node != permittedResidual { throw RouterSystemError.conflict }
    }
    private let command: RouterSystemCommand
    private let destination: RouterSystemDirectory
    private let launchDaemons: RouterSystemDirectory
    init(ownerUID: UInt32, destination: RouterSystemDirectory, launchDaemons: RouterSystemDirectory) throws {
        guard getuid() == 0, geteuid() == 0 else { throw RouterSystemError.ownershipUnknown }
        self.ownerUID = ownerUID; self.destination = destination; self.launchDaemons = launchDaemons
        command = try RouterSystemCommand(ownerUID: ownerUID)
    }
    func job() throws -> RouterSystemInstallJob {
        let (result, bytes) = try command.run(.systemJob)
        guard result.settled, !result.timedOut else { throw RouterSystemError.operationUnsettled }
        if result.exitCode == 113 { return .absent }
        guard result.exitCode == 0 else { throw RouterSystemError.ownershipUnknown }
        guard let pid = try RouterSystemInstallJobParser.pid(bytes) else { return .init(registered: true, work: nil) }
        let observed = try RouterSystemKernelObservation.Reader.live.process(pid)
        _ = try RouterSystemKernelObservation.executable(observed.work, expected: [RouterSystemLayout.helper])
        guard observed.processGroup == pid else { throw RouterSystemError.ownershipUnknown }
        return .init(registered: true, work: observed.work)
    }
    func quiesce(original: RouterSystemInstallJob) throws {
        try original.validate()
        try requireConfirmedResidual()
        let current = try job()
        if current.registered {
            guard current == original else { throw RouterSystemError.conflict }
            try verifyPlist()
            let (result, _) = try command.run(.bootoutSystemJob)
            guard result.settled else { throw RouterSystemError.operationUnsettled }
        }
        guard try job() == .absent else { throw RouterSystemError.operationUnsettled }
        // A missing label on retry is not evidence that the original process group has drained.
        if let work = original.work {
            let deadline = ProcessInfo.processInfo.systemUptime + 5
            while true {
                switch RouterSystemKernelObservation.Reader.live.formerHostGroup(work) {
                case .formerBootEnded, .formerHostGroupEmpty: break
                case .unknown: throw RouterSystemError.ownershipUnknown
                case .unsettled:
                    guard ProcessInfo.processInfo.systemUptime < deadline else { throw RouterSystemError.operationUnsettled }
                    _ = poll(nil, 0, 10); continue
                }
                break
            }
        }
        try requireConfirmedResidual()
    }
    func register() throws {
        try verifyPlist()
        if try registrationObserved() { return }
        try requireConfirmedResidual()
        let (result, _) = try command.run(.bootstrapSystemJob)
        guard result.settled else { throw RouterSystemError.operationUnsettled }
        guard try registrationObserved() else { throw RouterSystemError.operationUnsettled }
    }
    func proof(identity: RouterSystemInstallationIdentity, retired: Bool) throws -> RouterSystemInstallServiceProof {
        guard identity.ownerUID == ownerUID else { throw RouterSystemError.conflict }
        if !retired { try verifyPlist() }
        // A short-lived host can exit between samples. This proves registration only,
        // never host health or process-group drainage (quiesce establishes the latter).
        let before = try registrationObserved(), node = try socket(), after = try registrationObserved()
        guard before == after, after == !retired, try socket() == node,
              retired || node != nil else { throw RouterSystemError.operationUnsettled }
        var proof = RouterSystemInstallServiceProof(installation: identity, registered: after,
            socketNode: retired ? nil : node)
        proof.residualSocketNode = retired ? node : nil
        return proof
    }
    func registrationObserved() throws -> Bool {
        let (result, bytes) = try command.run(.systemJob)
        guard result.settled, !result.timedOut else { throw RouterSystemError.operationUnsettled }
        if result.exitCode == 113 { return false }
        guard result.exitCode == 0 else { throw RouterSystemError.ownershipUnknown }
        _ = try RouterSystemInstallJobParser.pid(bytes)
        return true
    }
    private func verifyPlist() throws {
        guard try launchDaemons.read(RouterSystemInstallFile.launchd.leaf, maximum: 65536, mode: 0o644) == RouterSystemInstallPlist.bytes(ownerUID: ownerUID) else {
            throw RouterSystemError.conflict
        }
    }
    private func socket() throws -> RouterSystemInstallNode? {
        let run = try destination.installChild(.installedRoot).installChild(.run)
        var before = stat(), after = stat()
        if fstatat(run.fd, "control.sock", &before, AT_SYMLINK_NOFOLLOW) != 0 {
            guard errno == ENOENT else { throw RouterSystemError.ownershipUnknown }; return nil
        }
        guard before.st_mode & S_IFMT == S_IFSOCK, before.st_mode & 0o7777 == 0o600,
              before.st_uid == ownerUID, before.st_gid == 0, before.st_nlink == 1,
              fstatat(run.fd, "control.sock", &after, AT_SYMLINK_NOFOLLOW) == 0,
              RouterSystemDirectory.unchanged(before, after) else { throw RouterSystemError.ownershipUnknown }
        try run.validate()
        return .init(after)
    }
}
