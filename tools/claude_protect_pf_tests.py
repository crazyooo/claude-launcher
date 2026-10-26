#!/usr/bin/env python3
"""Offline tests for claude_protect_pf (L3)."""
from __future__ import annotations

import io
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import claude_protect_pf as m


class PhysicalInterfaceTests(unittest.TestCase):
    def test_filters_virtual_ifconfig_fallback(self):
        listing = "lo0 en0 en1 utun8 awdl0 llw0 bridge0 ap1 gif0 stf0 anpi0 nan0"
        self.assertEqual(
            m.physical_interfaces(ifconfig_l=listing, hardware_ports=""),
            ["en0", "en1"],
        )

    def test_hardware_ports_skips_bridge(self):
        text = (
            "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: aa\n\n"
            "Hardware Port: Thunderbolt Bridge\nDevice: bridge0\nEthernet Address: bb\n\n"
            "Hardware Port: USB 10/100 LAN\nDevice: en7\nEthernet Address: cc\n"
        )
        self.assertEqual(m.list_hardware_port_devices(text), ["en0", "en7"])
        self.assertEqual(m.physical_interfaces(hardware_ports=text), ["en0", "en7"])

    def test_generate_conf_shape(self):
        conf = m.generate_pfconf(["en0", "en1"])
        meta = m.parse_canonical_conf(conf)
        self.assertEqual(meta["interfaces"], ["en0", "en1"])
        self.assertIn("block drop out quick on en0 to <anthropic_net>", conf)
        self.assertIn("pass out quick on lo0 all", conf)
        self.assertIn("160.79.104.0/21", conf)

    def test_rejects_virtual_in_conf(self):
        conf = m.generate_pfconf(["en0"])
        bad = conf.replace("on en0", "on utun8")
        with self.assertRaisesRegex(ValueError, "virtual"):
            m.parse_canonical_conf(bad)

    def test_rejects_overbroad(self):
        conf = (
            "table <anthropic_net> persist { 160.79.104.0/21, 2607:6bc0::/48 }\n"
            "pass out quick on lo0 all\n"
            "pass out quick to 127.0.0.1\n"
            "pass out quick to ::1\n"
            "block drop out quick on en0 to <anthropic_net>\n"
            "block drop out all\n"
        )
        with self.assertRaisesRegex(ValueError, "overbroad|non_anthropic"):
            m.parse_canonical_conf(conf)


class CliTests(unittest.TestCase):
    def test_generate_json(self):
        with mock.patch.object(m, "physical_interfaces", return_value=["en0"]):
            with mock.patch("sys.stdout", new_callable=io.StringIO):
                code = m.main(["generate"])
        self.assertEqual(code, 0)

    def test_apply_refuses_without_confirm(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            code = m.main(["apply", "--conf", "/tmp/x.pf"])
        self.assertEqual(code, 78)

    def test_apply_refuses_without_root_after_confirm(self):
        conf = m.generate_pfconf(["en0"])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "p.pf"
            path.write_text(conf, encoding="utf-8")
            with mock.patch.object(m.os, "geteuid", return_value=501):
                with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                    code = m.main(
                        [
                            "apply",
                            "--conf",
                            str(path),
                            "--i-confirm-apply",
                            "--i-confirm-window",
                            m.WINDOW,
                            "--i-acknowledge-network-mutation",
                        ]
                    )
            self.assertEqual(code, 78)
            self.assertIn("apply_requires_root", out.getvalue())

    def test_dry_run_missing_conf(self):
        code = m.main(["dry-run", "--conf", "/tmp/claude-protect-missing-conf.pf"])
        self.assertEqual(code, 78)

    def test_generate_to_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "protect.pf"
            with mock.patch.object(m, "physical_interfaces", return_value=["en0"]):
                code = m.main(["generate", "--output", str(path)])
            self.assertEqual(code, 0)
            text = path.read_text(encoding="utf-8")
            m.parse_canonical_conf(text)


class StatusTests(unittest.TestCase):
    def test_status_not_armed_when_empty(self):
        fake = mock.Mock(returncode=1, stdout="", stderr="")
        with mock.patch.object(m.subprocess, "run", return_value=fake):
            code = m.main(["status"])
        self.assertEqual(code, 0)


class EnableLifecycleTests(unittest.TestCase):
    def run_enable(self, *, hooked=False, phase=None, sha=None, confirmed=True,
                   interfaces=None, fail_hook=False):
        events = []
        hook = mock.Mock()
        hook.HookError = RuntimeError
        store = hook.Store.return_value
        store.lock.return_value = contextlib.nullcontext()
        hook.hook_status.return_value = {"hook_installed": hooked, "journal_phase": phase}
        hook.stage.side_effect = lambda *a: events.append("stage") or {"plan_sha256": "b" * 64}
        hook.restore.side_effect = lambda *a: events.append("restore")

        def apply_hook(*args):
            events.append("hook")
            if fail_hook:
                raise RuntimeError("fixture hook rejected")
        hook.apply_hook.side_effect = apply_hook
        module = mock.Mock(hook=hook)
        conf = m.generate_pfconf(["en0"])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "protect.pf"
            path.write_text(conf)
            args = ["enable", "--conf", str(path), "--conf-sha256", sha or m.sha256_text(conf)]
            if confirmed:
                args += ["--i-confirm-apply", "--i-confirm-window", m.WINDOW,
                         "--i-acknowledge-network-mutation"]
            with mock.patch.object(m, "protect_hook_module", return_value=module), \
                 mock.patch.object(m, "physical_interfaces", return_value=interfaces or ["en0"]), \
                 mock.patch.object(m.os, "geteuid", return_value=0), \
                 mock.patch.object(m, "apply_validated_conf", side_effect=lambda *a: events.append("rules") or 0), \
                 mock.patch("sys.stdout", new_callable=io.StringIO) as output:
                code = m.main(args)
        return code, events, output.getvalue()

    def test_fresh_system_initializes_hook_before_rules(self):
        code, events, _ = self.run_enable()
        self.assertEqual(code, 0)
        self.assertEqual(events, ["stage", "hook", "rules"])

    def test_existing_hook_does_not_reinitialize(self):
        code, events, _ = self.run_enable(hooked=True, phase="installed_unverified")
        self.assertEqual(code, 0)
        self.assertEqual(events, ["rules"])

    def test_stale_owned_journal_uses_restore_before_new_stage(self):
        code, events, _ = self.run_enable(phase="installed_unverified")
        self.assertEqual(code, 0)
        self.assertEqual(events, ["restore", "stage", "hook", "rules"])

    def test_unsettled_journal_blocks_new_mutation(self):
        code, events, _ = self.run_enable(phase="enable_pending")
        self.assertEqual(code, 78)
        self.assertEqual(events, [])

    def test_confirm_digest_and_interfaces_are_checked_before_mutation(self):
        for options in ({"confirmed": False}, {"sha": "c" * 64}, {"interfaces": ["en1"]}):
            code, events, _ = self.run_enable(**options)
            self.assertEqual(code, 78)
            self.assertEqual(events, [])

    def test_hook_failure_never_loads_rules_or_reports_success(self):
        code, events, output = self.run_enable(fail_hook=True)
        self.assertEqual(code, 78)
        self.assertEqual(events, ["stage", "hook"])
        self.assertIn("enable_hook_failed", output)
        self.assertIn('"protection_verified": false', output)


if __name__ == "__main__":
    unittest.main()
