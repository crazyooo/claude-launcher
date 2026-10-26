import XCTest
import Darwin
@testable import RoutingCore

final class RouterSystemKernelObservationTests: XCTestCase {
    private typealias Kernel = RouterSystemKernelObservation
    private final class Samples {
        let boot = UUID()
        var boots: [UUID] = []
        var processes: [Kernel.ProcessSample] = []
        var groups: [[Int32]] = []
        var bootFails = false, groupFails = false
        var processReads = 0, groupReads = 0
        var work: RouterSystemWork { .init(bootID: boot, pid: 700, birthSeconds: 100, birthMicroseconds: 12) }
        func snapshot(birth: UInt64 = 100) -> Kernel.ProcessSnapshot {
            .init(work: .init(bootID: boot, pid: 700, birthSeconds: birth, birthMicroseconds: 12),
                  uid: 0, realUID: 0, parentPID: 1, processGroup: 700)
        }
        var reader: Kernel.Reader {
            .init(boot: {
                if self.bootFails { throw RouterSystemError.ownershipUnknown }
                return self.boots.isEmpty ? self.boot : self.boots.removeFirst()
            }, sample: { pid, boot in
                XCTAssertEqual(pid, 700); XCTAssertEqual(boot, self.boot)
                self.processReads += 1
                return self.processes.isEmpty ? .present(self.snapshot()) : self.processes.removeFirst()
            }, group: { group in
                XCTAssertEqual(group, 700)
                self.groupReads += 1
                if self.groupFails { throw RouterSystemError.ownershipUnknown }
                return self.groups.isEmpty ? [] : self.groups.removeFirst()
            })
        }
        var fence: RouterSystemDispatchFence {
            .init(instance: UUID(), host: work, processGroup: 700, gateDeadlineUptime: 160,
                  gateExpiresAt: Date(timeIntervalSince1970: 1060), baselineID: UUID(),
                  baselineDigest: String(repeating: "a", count: 64), networkFingerprint: String(repeating: "b", count: 64),
                  configurationDigest: String(repeating: "c", count: 64))
        }
    }

    func testProcessRequiresStableFullSnapshotAndBoot() throws {
        let samples = Samples()
        XCTAssertEqual(try samples.reader.process(700), samples.snapshot())
        samples.processes = [.present(samples.snapshot()), .present(samples.snapshot(birth: 101))]
        XCTAssertThrowsError(try samples.reader.process(700))
        samples.processes = [.unknown]
        XCTAssertThrowsError(try samples.reader.process(700))
        samples.boots = [samples.boot, UUID()]
        XCTAssertThrowsError(try samples.reader.process(700))
    }

    func testExitSeparatesReuseAbsenceAndIncompleteEvidence() {
        let samples = Samples()
        XCTAssertEqual(samples.reader.exit(samples.work), .sameProcess)
        samples.processes = Array(repeating: .present(samples.snapshot(birth: 101)), count: 2)
        XCTAssertEqual(samples.reader.exit(samples.work), .exited)
        samples.processes = [.absent, .absent]
        XCTAssertEqual(samples.reader.exit(samples.work), .exited)
        samples.processes = [.unknown, .unknown]
        XCTAssertEqual(samples.reader.exit(samples.work), .unknown)
        samples.processes = [.present(samples.snapshot()), .absent]
        XCTAssertEqual(samples.reader.exit(samples.work), .unknown)
        samples.boots = [samples.boot, UUID()]
        XCTAssertEqual(samples.reader.exit(samples.work), .unknown)
    }

    func testDifferentBootMustBeStableAndDoesNotQueryReusedPID() {
        let samples = Samples(), newBoot = UUID()
        samples.boots = [newBoot, newBoot]
        XCTAssertEqual(samples.reader.exit(samples.work), .exited)
        XCTAssertEqual(samples.processReads, 0)
        samples.boots = [newBoot, UUID()]
        XCTAssertEqual(samples.reader.exit(samples.work), .unknown)
        samples.bootFails = true
        XCTAssertEqual(samples.reader.exit(samples.work), .unknown)
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unknown)
    }

    func testFormerDispatchRequiresHostExitAndTwoEmptyGroupReads() {
        let samples = Samples()
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unsettled)
        XCTAssertEqual(samples.groupReads, 0)
        samples.processes = Array(repeating: .absent, count: 4)
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .formerHostGroupEmpty)
        XCTAssertEqual(samples.groupReads, 2)
        samples.processes = Array(repeating: .absent, count: 4)
        samples.groups = [[], [901]]
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unsettled)
        samples.processes = [.absent, .absent]; samples.groupFails = true
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unknown)
        samples.groupFails = false; samples.processes = [.unknown, .unknown]
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unknown)
    }

    func testFormerBootAndBootChangeDuringGroupScan() {
        let samples = Samples(), newBoot = UUID()
        samples.boots = [newBoot, newBoot]
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .formerBootEnded)
        XCTAssertEqual(samples.groupReads, 0); XCTAssertEqual(samples.processReads, 0)
        samples.boots = [newBoot, UUID()]
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unknown)
        samples.processes = [.absent, .absent]
        samples.boots = [samples.boot, samples.boot, samples.boot, newBoot]
        XCTAssertEqual(samples.reader.formerDispatch(samples.fence), .unknown)
        XCTAssertEqual(samples.groupReads, 1)
    }

    func testProcessDecoderOnlyTreatsESRCHAsAbsent() {
        let boot = UUID(), size = Int32(MemoryLayout<proc_bsdinfo>.stride)
        var info = proc_bsdinfo()
        info.pbi_pid = 700; info.pbi_pgid = 700; info.pbi_ppid = 1
        info.pbi_start_tvsec = 100; info.pbi_start_tvusec = 12
        func decode(_ value: proc_bsdinfo, count: Int32, error: Int32 = 0) -> Kernel.ProcessSample {
            Kernel.decodeProcess(pid: 700, boot: boot, info: value, count: count, error: error)
        }
        guard case .present(let value) = decode(info, count: size) else { return XCTFail("Valid BSD process rejected") }
        XCTAssertEqual(value.work.birthSeconds, 100)
        guard case .absent = decode(info, count: 0, error: ESRCH) else { return XCTFail("ESRCH not recognized") }
        for error in [Int32(0), EPERM, EACCES, EINVAL] {
            guard case .unknown = decode(info, count: 0, error: error) else { return XCTFail("Read failure became exit") }
        }
        for count in [Int32(1), size - 1, size + 1] {
            guard case .unknown = decode(info, count: count) else { return XCTFail("Invalid size accepted") }
        }
        for change in 0..<5 {
            var malformed = info
            switch change {
            case 0: malformed.pbi_pid = 701
            case 1: malformed.pbi_pgid = UInt32.max
            case 2: malformed.pbi_ppid = UInt32.max
            case 3: malformed.pbi_start_tvsec = 0
            default: malformed.pbi_start_tvusec = 1_000_000
            }
            guard case .unknown = decode(malformed, count: size) else { return XCTFail("Invalid process accepted") }
        }
    }

    func testGroupDecoderRejectsErrorsTruncationAndMalformedMembers() throws {
        let stride = Int32(MemoryLayout<pid_t>.stride)
        XCTAssertEqual(try Kernel.decodeGroup([0, 0, 0], count: 0, error: 0), [])
        XCTAssertEqual(try Kernel.decodeGroup([700, 0, 0], count: stride, error: 0), [700])
        XCTAssertThrowsError(try Kernel.decodeGroup([0, 0], count: 0, error: EPERM))
        XCTAssertThrowsError(try Kernel.decodeGroup([], count: 0, error: 0))
        for count in [Int32(-1), stride - 1, stride * 3, stride * 4] {
            XCTAssertThrowsError(try Kernel.decodeGroup([700, 701, 702], count: count, error: 0))
        }
        for members: [Int32] in [[700, 700, 0], [700, 0, 0], [700, -1, 0]] {
            XCTAssertThrowsError(try Kernel.decodeGroup(members, count: stride * 2, error: 0))
        }
        for group: Int32 in [-1, 0] { XCTAssertThrowsError(try Kernel.groupMembers(group)) }
    }

    func testInvalidHistoricalIdentityCannotProveExit() {
        let samples = Samples()
        for work in [RouterSystemWork(bootID: samples.boot, pid: 0, birthSeconds: 100, birthMicroseconds: 12),
                     .init(bootID: samples.boot, pid: 700, birthSeconds: 0, birthMicroseconds: 12),
                     .init(bootID: samples.boot, pid: 700, birthSeconds: 100, birthMicroseconds: 1_000_000)] {
            XCTAssertEqual(samples.reader.exit(work), .unknown)
        }
        XCTAssertEqual(samples.processReads, 0)
    }

    func testActualCurrentProcessClockAndGroupWithoutLaunchingAnything() throws {
        let clock = try Kernel.clock(), process = try Kernel.Reader.live.process(getpid())
        XCTAssertEqual(process.work.pid, getpid()); XCTAssertEqual(process.work.bootID, clock.bootID)
        XCTAssertEqual(process.uid, geteuid()); XCTAssertEqual(process.realUID, getuid())
        XCTAssertEqual(process.processGroup, getpgrp()); XCTAssertGreaterThan(process.work.birthSeconds, 0)
        XCTAssertEqual(Kernel.Reader.live.exit(process.work), .sameProcess)
        XCTAssertTrue(try Kernel.groupMembers(getpgrp()).contains(getpid()))
        XCTAssertGreaterThanOrEqual(clock.uptime, 0); XCTAssertEqual(try Kernel.bootID(), clock.bootID)
    }
}
