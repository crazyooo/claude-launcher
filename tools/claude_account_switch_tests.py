#!/usr/bin/env python3
"""Offline tests for claude_account_switch (Desktop A/B)."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SPEC = importlib.util.spec_from_file_location(
    "claude_account_switch",
    Path(__file__).resolve().with_name("claude_account_switch.py"),
)
m = importlib.util.module_from_spec(_SPEC)
assert _SPEC and _SPEC.loader
_SPEC.loader.exec_module(m)


class Helpers:
    def make_home(self):
        root = Path(self._tmp.name)
        data = root / "Library" / "Application Support" / "Claude"
        data.mkdir(parents=True)
        (data / "Cookies").write_text("session-a", encoding="utf-8")
        (data / "config.json").write_text('{"oauth":"a"}', encoding="utf-8")
        return root, data

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)


class UsageTests(Helpers, unittest.TestCase):
    def test_summarize_usage_defaults_free(self):
        summary = m.summarize_usage_payload(
            {
                "five_hour": {"utilization": 10, "resets_at": "soon"},
                "seven_day": {"utilization": 2},
            }
        )
        self.assertEqual(summary["subscription"], "free")
        self.assertEqual(summary["session"]["utilization"], 10)
        self.assertEqual(summary["week"]["utilization"], 2)

    def test_refresh_usage_requires_confirmation(self):
        root, _ = self.make_home()
        payload = m.refresh_usage_for_slot("A", confirmed=False, home=root)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "confirmation_required")

    def test_refresh_usage_missing_token(self):
        root, data = self.make_home()
        base = root / ".claude-launcher"
        (base / "accounts" / "A").mkdir(parents=True)
        (base / "current").write_text("A\n", encoding="utf-8")
        (data / "config.json").write_text("{}", encoding="utf-8")
        payload = m.refresh_usage_for_slot(
            "A",
            confirmed=True,
            home=root,
            runner=lambda *a, **k: mock.Mock(returncode=1, stdout=b"", stderr=b""),
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "missing_token")

    def test_normalize_plan(self):
        self.assertEqual(m.normalize_plan("claude_free"), "free")
        self.assertEqual(m.normalize_plan("claude_pro"), "pro")
        self.assertEqual(m.normalize_plan(""), "free")

    def test_refresh_usage_via_session(self):
        root, data = self.make_home()
        base = root / ".claude-launcher"
        (base / "accounts" / "A").mkdir(parents=True)
        (base / "current").write_text("A\n", encoding="utf-8")
        (data / "config.json").write_text("{}", encoding="utf-8")

        def fake_session(desktop_root, runner=None, cf_fallback_root=None):
            return {"session_key": "sk-ant-sid02-test", "org_uuid": "org-1", "cookie": "sessionKey=x"}

        def fake_fetch(session):
            return m.ok(
                status="usage",
                usage=m.summarize_usage_payload({}, subscription="claude_free", source="claude_web_session"),
                identity={"email": "user@example.com", "label": "alice"},
            )

        with mock.patch.object(m, "load_oauth_credential", return_value=None), mock.patch.object(
            m, "load_session_credential", side_effect=fake_session
        ), mock.patch.object(m, "fetch_usage_via_session", side_effect=fake_fetch):
            payload = m.refresh_usage_for_slot("A", confirmed=True, home=root)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["usage"]["subscription"], "free")
        identity = json.loads((base / "accounts" / "A" / "identity.json").read_text(encoding="utf-8"))
        self.assertEqual(identity["email"], "user@example.com")
        self.assertEqual(identity["subscription"], "free")


class IdentityTests(Helpers, unittest.TestCase):
    def test_hides_default_organization_name(self):
        self.assertTrue(m.is_default_organization_name("alice's Organization"))
        self.assertTrue(m.is_default_organization_name("'user@example.com's Organization"))
        self.assertIsNone(m.meaningful_organization("frank's Organization"))
        self.assertEqual(m.meaningful_organization("Acme Team"), "Acme Team")

    def test_extract_identity_from_indexeddb_blob(self):
        root, data = self.make_home()
        blob_dir = data / "IndexedDB" / "https_claude.ai_0.indexeddb.blob" / "1" / "00"
        blob_dir.mkdir(parents=True)
        # Minimal binary-ish payload mimicking Chromium IDB field layout.
        payload = (
            b'account\x01uuid"$11111111-2222-3333-4444-555555555555"'
            b'email_address"\x18user@example.com"'
            b'display_name"\x05alice"'
            b'full_name"\x05alice"'
            b"organization\x01name\"\x12alice's Organization\""
        )
        (blob_dir / "3").write_bytes(payload)
        (data / "config.json").write_text(
            '{"lastKnownAccountUuid":"11111111-2222-3333-4444-555555555555"}',
            encoding="utf-8",
        )
        info = m.extract_identity(data)
        self.assertEqual(info.get("email"), "user@example.com")
        self.assertEqual(info.get("display_name"), "alice")
        self.assertIn("alice", info.get("label", ""))
        self.assertEqual(info.get("account_uuid"), "11111111-2222-3333-4444-555555555555")
        self.assertNotIn("organization", info)

    def test_status_includes_identity_for_current(self):
        root, data = self.make_home()
        blob_dir = data / "IndexedDB" / "https_claude.ai_0.indexeddb.blob" / "1" / "00"
        blob_dir.mkdir(parents=True)
        (blob_dir / "3").write_bytes(b'email_address"\x18work@example.com"display_name"\x04work"')
        base = root / ".claude-launcher"
        (base / "accounts" / "A").mkdir(parents=True)
        (base / "current").write_text("A\n", encoding="utf-8")
        # Archive empty A, rely on live refresh for current.
        payload = m.status_payload(home=root, runner=lambda *a, **k: mock.Mock(stdout="", returncode=1))
        self.assertTrue(payload["ok"])
        identity = payload["slots"]["A"]["identity"]
        self.assertEqual(identity.get("email"), "work@example.com")
        self.assertEqual(payload["live_identity"].get("email"), "work@example.com")


class StatusTests(Helpers, unittest.TestCase):
    def test_status_empty(self):
        root, _data = self.make_home()
        # empty live except we created files — wipe for empty case
        import shutil

        shutil.rmtree(root / "Library")
        (root / "Library" / "Application Support").mkdir(parents=True)
        payload = m.status_payload(home=root, runner=lambda *a, **k: mock.Mock(stdout="", returncode=1))
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["current"])
        self.assertFalse(payload["live_exists"])
        self.assertEqual(set(payload["slots"]), {"A", "B", "C", "D"})
        self.assertFalse(payload["slots"]["A"]["has_archive"])
        self.assertFalse(payload["desktop_running"])


class SwitchTests(Helpers, unittest.TestCase):
    def test_requires_confirmation(self):
        root, _ = self.make_home()
        payload = m.switch_to("B", confirmed=False, home=root)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "confirmation_required")

    def test_refuses_when_desktop_running(self):
        root, _ = self.make_home()

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="123\n", returncode=0)
            return mock.Mock(stdout="", returncode=0)

        payload = m.switch_to(
            "B",
            confirmed=True,
            home=root,
            runner=runner,
            sleeper=lambda _s: None,
        )
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "desktop_still_running")

    def test_first_switch_adopts_a_then_creates_b(self):
        root, data = self.make_home()
        calls = {"pgrep": 0}

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                calls["pgrep"] += 1
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        payload = m.switch_to("B", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["status"], "switched")
        self.assertEqual(payload["current"], "B")
        self.assertEqual(payload["previous"], "A")
        self.assertFalse(payload["opened"])

        a = root / ".claude-launcher" / "accounts" / "A"
        self.assertTrue((a / "Cookies").is_file())
        self.assertEqual((a / "Cookies").read_text(encoding="utf-8"), "session-a")
        # Live is empty B identity
        self.assertTrue(data.is_dir())
        self.assertFalse((data / "Cookies").exists())
        self.assertEqual((root / ".claude-launcher" / "current").read_text(encoding="utf-8").strip(), "B")

    def test_switch_back_restores_a(self):
        root, data = self.make_home()

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        first = m.switch_to("B", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertTrue(first["ok"], first)
        (data / "Cookies").write_text("session-b", encoding="utf-8")

        second = m.switch_to("A", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["current"], "A")
        self.assertEqual((data / "Cookies").read_text(encoding="utf-8"), "session-a")
        b = root / ".claude-launcher" / "accounts" / "B" / "Cookies"
        self.assertEqual(b.read_text(encoding="utf-8"), "session-b")

    def test_interrupted_archive_blocks_overwrite(self):
        root, data = self.make_home()
        base = root / ".claude-launcher"
        base.mkdir(parents=True)
        (base / "accounts").mkdir()
        (base / "accounts" / "A.new").mkdir()
        (base / "current").write_text("A\n", encoding="utf-8")

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        payload = m.switch_to("B", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "interrupted_archive_present")
        self.assertTrue((data / "Cookies").exists())

    def test_open_flag_invokes_open(self):
        root, _ = self.make_home()
        opens = []

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            if cmd[:2] == ["/usr/bin/open", "-a"]:
                opens.append(cmd)
                return mock.Mock(stdout="", returncode=0)
            return mock.Mock(stdout="", returncode=0)

        payload = m.switch_to(
            "B", confirmed=True, open_after=True, home=root, runner=runner, sleeper=lambda _s: None
        )
        self.assertTrue(payload["ok"], payload)
        self.assertTrue(payload["opened"])
        self.assertEqual(opens, [["/usr/bin/open", "-a", "Claude"]])

    def test_switch_to_d_supported(self):
        root, data = self.make_home()

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        payload = m.switch_to("D", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["current"], "D")
        self.assertTrue((root / ".claude-launcher" / "accounts" / "A" / "Cookies").is_file())
        self.assertTrue(data.is_dir())
        self.assertFalse((data / "Cookies").exists())


class AdoptTests(Helpers, unittest.TestCase):
    def test_adopt_a_keeps_live(self):
        root, data = self.make_home()

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        payload = m.adopt_live("A", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["current"], "A")
        self.assertEqual((data / "Cookies").read_text(encoding="utf-8"), "session-a")
        self.assertEqual(
            (root / ".claude-launcher" / "accounts" / "A" / "Cookies").read_text(encoding="utf-8"),
            "session-a",
        )

    def test_adopt_rejects_occupied(self):
        root, data = self.make_home()
        base = root / ".claude-launcher" / "accounts" / "A"
        base.mkdir(parents=True)
        (base / "Cookies").write_text("old", encoding="utf-8")

        def runner(cmd, **_k):
            if cmd[:2] == ["/usr/bin/pgrep", "-f"]:
                return mock.Mock(stdout="", returncode=1)
            return mock.Mock(stdout="", returncode=0)

        payload = m.adopt_live("A", confirmed=True, home=root, runner=runner, sleeper=lambda _s: None)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["reason"], "slot_occupied")
        self.assertEqual((data / "Cookies").read_text(encoding="utf-8"), "session-a")


class CliTests(Helpers, unittest.TestCase):
    def test_status_cli_json(self):
        root, _ = self.make_home()
        with mock.patch.dict(
            "os.environ",
            {
                "CLAUDE_ACCOUNT_HOME": str(root),
                "CLAUDE_ACCOUNT_BASE": str(root / ".claude-launcher"),
                "CLAUDE_ACCOUNT_DATA": str(root / "Library" / "Application Support" / "Claude"),
            },
            clear=False,
        ), mock.patch.object(m, "desktop_running", return_value=False):
            code = m.main(["status"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
