#!/usr/bin/env python3
"""Offline tests for claude_protect_guard (L4)."""
from __future__ import annotations

import json
import unittest
from unittest import mock

import claude_protect_guard as g


class SnapshotTests(unittest.TestCase):
    def test_healthy_no_action(self):
        payload = g.snapshot(
            "127.0.0.1",
            1082,
            g.DEFAULT_CLAUDE_PATTERNS,
            dry_run=True,
            probe=lambda h, p: g.Health(True, "proxy_port_open"),
            pid_runner=lambda *a, **k: mock.Mock(stdout="123\n", returncode=0),
            act=True,
        )
        self.assertTrue(payload["healthy"])
        self.assertEqual(payload["action"], "none")
        self.assertEqual(payload["terminated"], [])

    def test_unhealthy_dry_run_lists_pids(self):
        def runner(*_a, **_k):
            return mock.Mock(stdout="4242\n", returncode=0)

        payload = g.snapshot(
            "127.0.0.1",
            1082,
            ("/Applications/Claude.app/Contents/",),
            dry_run=True,
            probe=lambda h, p: g.Health(False, "proxy_port_unreachable"),
            pid_runner=runner,
            act=True,
        )
        self.assertFalse(payload["healthy"])
        self.assertEqual(payload["action"], "terminate_claude")
        self.assertEqual(payload["would_terminate"], [4242])
        self.assertEqual(payload["terminated"], [])
        self.assertFalse(payload["protection_verified"])

    def test_unhealthy_terminates_and_notifies(self):
        killed = []
        notes = []

        def runner(*_a, **_k):
            return mock.Mock(stdout="7\n", returncode=0)

        payload = g.snapshot(
            "127.0.0.1",
            1082,
            ("/Applications/Claude.app/Contents/",),
            dry_run=False,
            probe=lambda h, p: g.Health(False, "proxy_port_unreachable"),
            pid_runner=runner,
            killer=lambda pid, sig: killed.append((pid, sig)),
            notifier=lambda t, m: notes.append((t, m)) or True,
            act=True,
        )
        self.assertEqual(payload["terminated"], [7])
        self.assertTrue(payload["notified"])
        self.assertEqual(killed[0][0], 7)
        self.assertTrue(notes)


class CliTests(unittest.TestCase):
    def test_status_exit_codes(self):
        with mock.patch.object(
            g,
            "snapshot",
            return_value={
                "healthy": False,
                "health_reason": "proxy_port_unreachable",
                "claude_pids": [],
                "action": "none",
                "terminated": [],
                "notified": False,
                "dry_run": True,
                "protection_verified": False,
                "routing_verified": False,
                "accepted": False,
                "version": 1,
                "product": "claude_protect_l4",
                "proxy_host": "127.0.0.1",
                "proxy_port": 1082,
            },
        ):
            code = g.main(["status"])
        self.assertEqual(code, 1)

    def test_check_dry_run(self):
        with mock.patch.object(
            g,
            "snapshot",
            return_value={
                "healthy": False,
                "health_reason": "proxy_port_unreachable",
                "claude_pids": [1],
                "action": "terminate_claude",
                "terminated": [],
                "would_terminate": [1],
                "notified": False,
                "dry_run": True,
                "protection_verified": False,
                "routing_verified": False,
                "accepted": False,
                "version": 1,
                "product": "claude_protect_l4",
                "proxy_host": "127.0.0.1",
                "proxy_port": 1082,
            },
        ):
            code = g.main(["check", "--dry-run"])
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
