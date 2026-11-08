import XCTest
@testable import LauncherApp

@MainActor private final class AccountFixture {
    var status: [String: Any] = [
        "product": "claude_account_switch",
        "ok": true,
        "status": "status",
        "current": "A",
        "live_exists": true,
        "desktop_running": false,
        "slots": [
            "A": [
                "slot": "A", "is_current": true, "has_archive": true, "size_bytes": 2048,
                "mtime": "2026-11-07T00:00:00+00:00",
                "identity": ["label": "frank", "email": "frank@example.com", "organization": "Frank Org"],
                "usage": [
                    "subscription": "free",
                    "session": ["utilization": 12.0, "resets_at": "2026-11-07T10:00:00Z"],
                    "week": ["utilization": 3.0],
                    "fetched_at": "2026-11-07T04:00:00Z"
                ]
            ],
            "B": ["slot": "B", "is_current": false, "has_archive": false, "size_bytes": 0, "mtime": NSNull(), "identity": [:], "usage": [:]],
            "C": ["slot": "C", "is_current": false, "has_archive": false, "size_bytes": 0, "mtime": NSNull(), "identity": [:], "usage": [:]],
            "D": ["slot": "D", "is_current": false, "has_archive": false, "size_bytes": 0, "mtime": NSNull(), "identity": [:], "usage": [:]]
        ],
        "live_identity": ["label": "frank", "email": "frank@example.com"]
    ]
    var switchResult: [String: Any] = [
        "product": "claude_account_switch",
        "ok": true,
        "status": "switched",
        "current": "B",
        "opened": false
    ]
    var commands: [ProtectCommand] = []

    func json(_ value: [String: Any], code: Int32 = 0) -> ProtectCommandResult {
        .init(exitCode: code, output: String(data: try! JSONSerialization.data(withJSONObject: value), encoding: .utf8)!)
    }

    func model(defaults: UserDefaults = UserDefaults(suiteName: "claude.account.test.\(UUID().uuidString)")!) -> ClaudeAccountModel {
        .init(effects: .init(run: { command in
            self.commands.append(command)
            if command.arguments.contains("status") {
                return self.json(self.status)
            }
            if command.arguments.contains("switch") {
                return self.json(self.switchResult, code: (self.switchResult["ok"] as? Bool) == true ? 0 : 1)
            }
            if command.arguments.contains("adopt") {
                return self.json([
                    "product": "claude_account_switch",
                    "ok": true,
                    "status": "adopted",
                    "current": "A"
                ])
            }
            return self.json(["product": "claude_account_switch", "ok": false, "reason": "unknown"])
        }), toolsRoot: "/fixture", defaults: defaults)
    }
}

final class ClaudeAccountModelTests: XCTestCase {
    @MainActor private func settle(_ predicate: () -> Bool) async throws {
        for _ in 0..<500 {
            if predicate() { return }
            try await Task.sleep(nanoseconds: 2_000_000)
        }
        XCTFail("condition not met")
    }

    @MainActor func testRefreshParsesSlots() async throws {
        let fixture = AccountFixture()
        let model = fixture.model()
        model.refresh()
        try await settle { model.current == "A" && !model.refreshing }
        XCTAssertEqual(model.slots.map(\.name), ["A", "B", "C", "D"])
        XCTAssertTrue(model.slots[0].isCurrent)
        XCTAssertTrue(model.slots[0].hasArchive)
        XCTAssertFalse(model.slots[1].hasArchive)
        XCTAssertFalse(model.slots[2].hasArchive)
        XCTAssertFalse(model.slots[3].hasArchive)
        XCTAssertEqual(model.slots[0].identity.email, "frank@example.com")
        XCTAssertEqual(model.slots[0].identity.label, "frank")
        XCTAssertEqual(model.slots[0].usage.planLabel, "Free")
        XCTAssertEqual(model.slots[0].usage.sessionPercent, 12)
        XCTAssertEqual(model.liveIdentity.email, "frank@example.com")
        XCTAssertFalse(model.desktopRunning)
    }

    @MainActor func testSwitchPassesOpenFlagWhenEnabled() async throws {
        let suite = "claude.account.open.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defaults.removePersistentDomain(forName: suite)
        let fixture = AccountFixture()
        let model = fixture.model(defaults: defaults)
        model.openAfterSwitch = true
        model.switchTo("B")
        try await settle { !model.busy && model.message.contains("已切换") }
        let joined = fixture.commands.map { $0.arguments.joined(separator: " ") }.joined(separator: "\n")
        XCTAssertTrue(joined.contains("switch --to B --i-confirm-switch --open"))
    }

    @MainActor func testSwitchFailureSurfacesReason() async throws {
        let fixture = AccountFixture()
        fixture.switchResult = [
            "product": "claude_account_switch",
            "ok": false,
            "reason": "desktop_still_running",
            "detail": "请先退出"
        ]
        let model = fixture.model()
        model.switchTo("B")
        try await settle { !model.busy && model.message.contains("切换未完成") }
        XCTAssertTrue(model.message.contains("仍在运行"))
    }

    func testFormatBytes() {
        XCTAssertEqual(ClaudeAccountSlot.formatBytes(500), "500 B")
        XCTAssertEqual(ClaudeAccountSlot.formatBytes(2048), "2.0 KB")
    }
}
