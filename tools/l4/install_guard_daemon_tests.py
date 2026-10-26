#!/usr/bin/env python3
"""Offline tests for L4 daemon installer (no root mutation)."""
from __future__ import annotations

import io
import unittest
from unittest import mock

import install_guard_daemon as d


class PlanTests(unittest.TestCase):
    def test_plan_ok(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO):
            code = d.main(["plan"])
        self.assertEqual(code, 0)

    def test_install_requires_confirm(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = d.main(["install"])
        self.assertEqual(code, 78)
        self.assertIn("install_requires_confirm", out.getvalue())

    def test_install_requires_root(self):
        with mock.patch.object(d.os, "geteuid", return_value=501):
            with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
                code = d.main(["install", "--i-confirm-install"])
        self.assertEqual(code, 78)
        self.assertIn("install_requires_root", out.getvalue())


if __name__ == "__main__":
    unittest.main()
