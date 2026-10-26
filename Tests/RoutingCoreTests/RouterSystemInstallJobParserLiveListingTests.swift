import XCTest
@testable import RoutingCore

final class RouterSystemInstallJobParserLiveListingTests: XCTestCase {
    func testLiveLaunchctlPrintParsesHelperPid() throws {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = ["print", "system/" + RouterSystemLayout.label]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do { try task.run() } catch { throw XCTSkip("launchctl unavailable") }
        task.waitUntilExit()
        if task.terminationStatus == 113 { throw XCTSkip("system host not registered") }
        guard task.terminationStatus == 0 else {
            throw XCTSkip("launchctl print exit \(task.terminationStatus)")
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        let pid = try RouterSystemInstallJobParser.pid(data)
        
        if let pid {
            XCTAssertGreaterThan(pid, 1)
            print("PARSED_LIVE_PID=\(pid)")
        }
    }
}
