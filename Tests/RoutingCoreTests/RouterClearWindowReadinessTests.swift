import XCTest
@testable import RoutingCore

final class RouterClearWindowReadinessTests: XCTestCase {
    func testDetectsLongmaoAndDoesNotRecommendGrant() {
        let effects = RouterClearWindowReadiness.Effects(listProcesses: {
            [
                (75649, "/Applications/你的代理客户端_Lite.app/Contents/MacOS/你的代理客户端_Lite"),
                (75656, "/Applications/你的代理客户端_Lite.app/Contents/MacOS/lmclientCore"),
                (1, "/sbin/launchd"),
            ]
        })
        let report = RouterClearWindowReadiness.probe(effects: effects)
        XCTAssertFalse(report.looksClearOfKnownForeignClients)
        XCTAssertFalse(report.canRecommendConversationGrant)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertEqual(report.clearWindowID, "tun-apply-clear-window-v1")
        XCTAssertTrue(report.foreignProcesses.contains(where: { $0.label.contains("你的代理客户端") }))
        XCTAssertTrue(report.summary.contains("外场客户端"))
    }

    func testEmptyProcessListCanRecommendGrantStillNotVerified() {
        let effects = RouterClearWindowReadiness.Effects(listProcesses: { [] })
        let report = RouterClearWindowReadiness.probe(effects: effects)
        XCTAssertTrue(report.looksClearOfKnownForeignClients)
        XCTAssertTrue(report.canRecommendConversationGrant)
        XCTAssertFalse(report.routingVerified)
        XCTAssertFalse(report.accepted)
        XCTAssertTrue(report.summary.contains("requireClear"))
    }

    func testIgnoresOwnLauncherPaths() {
        let effects = RouterClearWindowReadiness.Effects(listProcesses: {
            [
                (99, "/Users/me/Applications/Claude Launcher.app/Contents/MacOS/router-runtime"),
                (100, "/usr/bin/ssh"),
            ]
        })
        let report = RouterClearWindowReadiness.probe(effects: effects)
        XCTAssertTrue(report.looksClearOfKnownForeignClients)
        XCTAssertTrue(report.foreignProcesses.isEmpty)
    }

    func testResidualPrivilegedHelperDoesNotBlockGrantRecommendation() {
        let effects = RouterClearWindowReadiness.Effects(listProcesses: {
            [
                (555, "/Library/PrivilegedHelperTools/io.github.clash-verge-rev.clash-verge-rev.service.bundle/Contents/MacOS/clash-verge-service"),
            ]
        })
        let report = RouterClearWindowReadiness.probe(effects: effects)
        XCTAssertTrue(report.looksClearOfKnownForeignClients)
        XCTAssertTrue(report.canRecommendConversationGrant)
        XCTAssertEqual(report.foreignProcesses.count, 1)
        XCTAssertTrue(report.summary.contains("残余") || report.summary.contains("PrivilegedHelper"))
    }
}
