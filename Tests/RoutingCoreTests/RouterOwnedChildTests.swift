import XCTest
import Darwin
@testable import RoutingCore

final class RouterOwnedChildTests: XCTestCase {
    func testGateRequiresExactIdentityAndEOF() throws {
        let id = UUID()
        for payload in [RouterSystemGate.permit(id), Data(), Data("START\n".utf8),
                        RouterSystemGate.permit(UUID()), RouterSystemGate.permit(id) + Data("extra".utf8)] {
            var descriptors: [Int32] = [-1, -1]
            XCTAssertEqual(pipe(&descriptors), 0)
            defer { close(descriptors[0]) }
            _ = payload.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }
            close(descriptors[1])
            if payload == RouterSystemGate.permit(id) {
                XCTAssertNoThrow(try RouterSystemGate.receive(fd: descriptors[0], instance: id,
                    deadline: ProcessInfo.processInfo.systemUptime + 1))
            } else {
                XCTAssertThrowsError(try RouterSystemGate.receive(fd: descriptors[0], instance: id,
                    deadline: ProcessInfo.processInfo.systemUptime + 1))
            }
        }
    }
    func testFullPermitWithoutEOFStillTimesOut() throws {
        let id = UUID()
        var descriptors: [Int32] = [-1, -1]
        XCTAssertEqual(pipe(&descriptors), 0)
        defer { close(descriptors[0]); close(descriptors[1]) }
        let permit = RouterSystemGate.permit(id)
        _ = permit.withUnsafeBytes { Darwin.write(descriptors[1], $0.baseAddress, $0.count) }
        XCTAssertThrowsError(try RouterSystemGate.receive(fd: descriptors[0], instance: id,
            deadline: ProcessInfo.processInfo.systemUptime + 0.03))
    }
    func testExpiredPermitCannotBeAccepted() {
        XCTAssertThrowsError(try RouterSystemGate.receive(fd: -1, instance: UUID(), deadline: ProcessInfo.processInfo.systemUptime - 1))
    }
    func testDirectChildConsumesGateAndExitsWithoutNetworking() throws {
        let child = try RouterOwnedChild.spawn(instance: UUID(), executable: "/bin/cat", arguments: [])
        defer { try? child.signal(SIGKILL); _ = child.waitUntil(ProcessInfo.processInfo.systemUptime + 1) }
        XCTAssertEqual(child.observe(), .running)
        try child.releaseGate()
        guard case .exited(0) = child.waitUntil(ProcessInfo.processInfo.systemUptime + 2) else { return XCTFail("cat did not receive EOF") }
        XCTAssertThrowsError(try child.releaseGate())
        XCTAssertNoThrow(try child.signal(SIGTERM))
    }
    func testClosedGateAbortsWaitingReaderAndSignalIsBoundToDirectChild() throws {
        let child = try RouterOwnedChild.spawn(instance: UUID(), executable: "/bin/cat", arguments: [])
        child.closeGate()
        guard case .exited(0) = child.waitUntil(ProcessInfo.processInfo.systemUptime + 2) else { return XCTFail() }
        let sleeper = try RouterOwnedChild.spawn(instance: UUID(), executable: "/bin/sleep", arguments: ["10"])
        defer { try? sleeper.signal(SIGKILL); _ = sleeper.waitUntil(ProcessInfo.processInfo.systemUptime + 1) }
        XCTAssertEqual(sleeper.waitUntil(ProcessInfo.processInfo.systemUptime + 0.02), .running)
        sleeper.closeGate(); try sleeper.signal(SIGTERM)
        guard case .exited = sleeper.waitUntil(ProcessInfo.processInfo.systemUptime + 2) else { return XCTFail("owned child still running") }
    }
    func testExternallyReapedPIDNeverBecomesSignalTarget() throws {
        let child = try RouterOwnedChild.spawn(instance: UUID(), executable: "/usr/bin/true", arguments: [])
        var status: Int32 = 0
        XCTAssertEqual(waitpid(child.pid, &status, 0), child.pid) // Deliberately violate exclusive-owner contract.
        XCTAssertEqual(child.observe(), .ownershipUnknown)
        XCTAssertThrowsError(try child.signal(SIGKILL)) { XCTAssertEqual($0 as? RouterSystemError, .ownershipUnknown) }
    }
    func testSpawnFailureAndEmbeddedNULAreRejected() {
        XCTAssertThrowsError(try RouterOwnedChild.spawn(instance: UUID(), executable: "/nonexistent-router-fixture", arguments: []))
        XCTAssertThrowsError(try RouterOwnedChild.spawn(instance: UUID(), executable: "/usr/bin/true", arguments: ["bad\0argument"]))
    }
    func testAutomaticReaperDispositionsAreRejectedWithoutChangingHostSignals() {
        var action = sigaction()
        XCTAssertNoThrow(try RouterOwnedChild.validateReaping(action))
        action.sa_flags = SA_NOCLDWAIT
        XCTAssertThrowsError(try RouterOwnedChild.validateReaping(action))
        action.sa_flags = 0; action.__sigaction_u.__sa_handler = SIG_IGN
        XCTAssertThrowsError(try RouterOwnedChild.validateReaping(action))
    }
    func testUnrelatedParentDescriptorNotInherited() throws {
        let original = open("/dev/null", O_RDONLY)
        XCTAssertGreaterThanOrEqual(original, 0)
        defer { close(original) }
        let high = fcntl(original, F_DUPFD, 100)
        XCTAssertGreaterThanOrEqual(high, 100)
        defer { close(high) }
        let child = try RouterOwnedChild.spawn(instance: UUID(), executable: "/bin/test", arguments: ["-e", "/dev/fd/\(high)"])
        child.closeGate()
        defer { try? child.signal(SIGKILL); _ = child.waitUntil(ProcessInfo.processInfo.systemUptime + 1) }
        XCTAssertEqual(child.waitUntil(ProcessInfo.processInfo.systemUptime + 2), .exited(256))
    }
}
