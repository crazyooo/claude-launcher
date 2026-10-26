import XCTest
@testable import LauncherCore

final class BrowserRuntimeTests: XCTestCase {
    func testPinnedBrowserArgumentsBindProfileAndConnector() throws {
        let profile = BrowserProfile(name: "Test"), directory = URL(fileURLWithPath: "/tmp/browser fixture")
        let args = try BrowserRuntime.arguments(profile: profile, directory: directory, port: 15366)
        XCTAssertTrue(args.contains("--proxy-server=http://127.0.0.1:15366"))
        XCTAssertTrue(args.contains("--proxy-bypass-list=<-loopback>"))
        XCTAssertTrue(args.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp"))
        XCTAssertTrue(args.contains("--fingerprint-platform=macos"))
        XCTAssertTrue(args.contains("--user-data-dir=/tmp/browser fixture"))
        XCTAssertEqual(args.last, "about:blank")
        XCTAssertThrowsError(try BrowserRuntime.requireLaunch())
    }
    func testProfileValidationRejectsUnsupportedValues() {
        var profile = BrowserProfile(name: "test"); profile.seed = 0; XCTAssertThrowsError(try profile.validate())
        profile.seed = 1; profile.language = "en-US --bad"; XCTAssertThrowsError(try profile.validate())
        profile.language = "en-US"; profile.timezone = "not/a/timezone"; XCTAssertThrowsError(try profile.validate())
    }
}
