import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemJournalContentionTests: XCTestCase {
    /// A separate process holds the actual flock; it never reads configuration or uses networking.
    private func holdingLock(_ fixture: RouterSystemDispatchFixture, for seconds: Double) throws -> Process {
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        process.arguments = ["-I", "-B", "-c", "import os,sys,fcntl,time\nf=os.open(sys.argv[1],os.O_RDWR)\nfcntl.flock(f,fcntl.LOCK_EX)\nos.write(1,b'L')\ntime.sleep(float(sys.argv[2]))\nos.close(f)",
            fixture.url.appendingPathComponent("journal.lock").path, String(seconds)]
        process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
        try process.run()
        XCTAssertEqual(try output.fileHandleForReading.read(upToCount: 1), Data("L".utf8))
        return process
    }
    func testCrossProcessContentionCanWaitForReadAndWriteWithoutRepeatingSave() throws {
        for writing in [false, true] {
            let f = try RouterSystemDispatchFixture()
            var state = try f.journal.load(); let original = state.revision; state.revision = UUID()
            let child = try holdingLock(f, for: 0.15)
            defer { child.waitUntilExit() }
            let began = ProcessInfo.processInfo.systemUptime
            if writing {
                try f.journal.save(state, expecting: original, until: began + 2)
                XCTAssertEqual(try f.journal.load().revision, state.revision)
            } else { XCTAssertEqual(try f.journal.load(until: began + 2).revision, original) }
            XCTAssertGreaterThan(ProcessInfo.processInfo.systemUptime - began, 0.05)
        }
    }
    func testContentionDoesNotExtendReadOrWriteDeadline() throws {
        for writing in [false, true] {
            let f = try RouterSystemDispatchFixture()
            var state = try f.journal.load(); let original = state.revision; state.revision = UUID()
            let child = try holdingLock(f, for: 0.2)
            let deadline = ProcessInfo.processInfo.systemUptime + 0.04
            if writing { XCTAssertThrowsError(try f.journal.save(state, expecting: original, until: deadline)) }
            else { XCTAssertThrowsError(try f.journal.load(until: deadline)) }
            child.waitUntilExit()
            XCTAssertEqual(try f.journal.load().revision, original)
        }
    }
    func testLockReplacementAndCorruptionAreNotTreatedAsContention() throws {
        let f = try RouterSystemDispatchFixture()
        try FileManager.default.moveItem(at: f.url.appendingPathComponent("journal.lock"), to: f.url.appendingPathComponent("preserved.lock"))
        try f.directory.create("journal.lock", data: Data())
        XCTAssertThrowsError(try f.journal.load(until: ProcessInfo.processInfo.systemUptime + 2)) { error in
            XCTAssertEqual(error as? RouterSystemError, .ownershipUnknown)
        }
        let g = try RouterSystemDispatchFixture()
        try Data("damaged".utf8).write(to: g.url.appendingPathComponent("journal.json"))
        XCTAssertThrowsError(try g.journal.load(until: ProcessInfo.processInfo.systemUptime + 2)) { error in
            XCTAssertEqual(error as? RouterSystemError, .journalUnknown)
        }
    }
    func testSaveFinishingLatePreservesPublishedStateWithoutReturningSuccess() throws {
        let f = try RouterSystemDispatchFixture()
        let store = try RouterSystemJournalStore(directory: f.directory, installation: f.identity, synchronize: { fd in
            Thread.sleep(forTimeInterval: 0.06)
            return fsync(fd)
        })
        var state = try store.load(); let original = state.revision; state.revision = UUID()
        XCTAssertThrowsError(try store.save(state, expecting: original, until: ProcessInfo.processInfo.systemUptime + 0.03))
        XCTAssertEqual(try store.load().revision, state.revision)
        XCTAssertThrowsError(try store.save(state, expecting: original))
    }
    func testLockReplacedWhileWaitingCannotBeAcquiredAsOriginal() throws {
        let f = try RouterSystemDispatchFixture(), moved = expectation(description: "preserve and replace lock")
        let child = try holdingLock(f, for: 0.3)
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.04) {
            do {
                try FileManager.default.moveItem(at: f.url.appendingPathComponent("journal.lock"), to: f.url.appendingPathComponent("preserved.lock"))
                try f.directory.create("journal.lock", data: Data())
            } catch { XCTFail("fixture lock replacement failed: \(error)") }
            moved.fulfill()
        }
        XCTAssertThrowsError(try f.journal.load(until: ProcessInfo.processInfo.systemUptime + 2)) { error in
            XCTAssertEqual(error as? RouterSystemError, .ownershipUnknown)
        }
        wait(for: [moved], timeout: 2); child.waitUntilExit()
    }
}
