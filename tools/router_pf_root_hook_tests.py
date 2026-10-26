#!/usr/bin/env python3
"""Offline tests for router_pf_root_hook (FakePF — never loads host PF)."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

import router_pf_root_hook as h

APPLE_SCRUB = 'scrub-anchor "com.apple/*" all fragment reassemble'
APPLE_FILTER = 'anchor "com.apple/*" all'
APPLE_ROOT = APPLE_SCRUB + "\n" + APPLE_FILTER


class FakePF:
    def __init__(self, enabled: bool = False):
        self.active = enabled
        self.root_rules = APPLE_ROOT
        self.refs = "No pf starter references held\n"
        self.mutations: list = []
        self.fail: str | None = None

    def enabled(self) -> bool:
        return self.active

    def root(self) -> str:
        return h.normalize(self.root_rules)

    def references(self) -> str:
        return self.refs

    def syntax(self, source: str) -> str:
        return h.normalize(source)

    def load_root(self, source: str) -> None:
        self.mutations.append(("load_root", source))
        self.root_rules = source
        if self.fail == "load":
            self.fail = None
            raise h.HookError("simulated_post_load_failure")

    def enable_with_receipt(self, store: h.Store) -> str:
        fd = store.create_receipt()
        with os.fdopen(fd, "wb") as stream:
            stream.write(b"pf enabled\nToken : 12345\n")
        self.active = True
        self.refs = (
            "PID      Process Name                 TOKEN                    TIMESTAMP\n"
            "44       pfctl                        12345                    0 days 00:00:01\n"
        )
        self.mutations.append(("enable",))
        return "12345"

    def release(self, token: str) -> None:
        self.mutations.append(("release", token))
        self.refs = "No pf starter references held\n"
        self.active = False


class RootHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.journal = Path(self.temp.name)
        os.chmod(self.journal, 0o700)
        self.store = h.Store(self.journal)
        self.pf = FakePF(enabled=False)

    def test_build_root_after_inserts_after_scrub_and_allows_clguard(self):
        before = APPLE_SCRUB + "\n" + 'anchor "clguard_abcdef0123456789abcdef0123456789" quick all\n' + APPLE_FILTER
        after = h.build_root_after(before)
        lines = after.splitlines()
        self.assertEqual(lines[0], APPLE_SCRUB)
        self.assertEqual(lines[1], f'anchor "{h.ANCHOR}" quick all')
        self.assertIn("clguard_", lines[2])

    def test_build_root_after_refuses_duplicate_and_foreign_baseline(self):
        dup = APPLE_ROOT + "\n" + f'anchor "{h.ANCHOR}" quick all'
        with self.assertRaises(h.HookError) as ctx:
            h.build_root_after(dup)
        self.assertEqual(str(ctx.exception), "failclosed_anchor_already_hooked")
        with self.assertRaises(h.HookError) as ctx2:
            h.build_root_after("block drop out all\n")
        self.assertEqual(str(ctx2.exception), "root_baseline_requires_manual_review")

    def test_stage_apply_restore_with_enable_token(self):
        with self.store.lock():
            plan = h.stage(self.pf, self.store)
        self.assertFalse(self.pf.active)
        self.assertIn(f'anchor "{h.ANCHOR}" quick all', plan["root_after"])
        self.assertEqual(self.pf.root(), h.normalize(APPLE_ROOT))

        with self.store.lock():
            state = h.apply_hook(plan, self.pf, self.store, plan["plan_sha256"])
        self.assertEqual(state["phase"], "installed_unverified")
        self.assertTrue(self.pf.active)
        self.assertIn(f'anchor "{h.ANCHOR}"', self.pf.root())
        self.assertTrue(any(m[0] == "enable" for m in self.pf.mutations))

        with self.store.lock():
            h.restore(plan, self.pf, self.store)
        self.assertEqual(self.pf.root(), h.normalize(APPLE_ROOT))
        self.assertFalse(self.pf.active)
        self.assertTrue(any(m[0] == "release" for m in self.pf.mutations))
        self.assertEqual(self.store.read("state")["phase"], "restored")

    def test_stage_when_already_enabled_skips_minus_e(self):
        self.pf.active = True
        self.pf.refs = (
            "PID      Process Name                 TOKEN                    TIMESTAMP\n"
            "1        launchd                      9                        0 days 00:00:01\n"
        )
        with self.store.lock():
            plan = h.stage(self.pf, self.store)
        self.assertTrue(plan["pf_was_enabled"])
        with self.store.lock():
            h.apply_hook(plan, self.pf, self.store, plan["plan_sha256"])
        self.assertFalse(any(m[0] == "enable" for m in self.pf.mutations))
        self.assertFalse(self.store.has("receipt"))

    def test_apply_rolls_back_on_load_failure(self):
        with self.store.lock():
            plan = h.stage(self.pf, self.store)
        self.pf.fail = "load"
        with self.store.lock(), self.assertRaises(h.HookError):
            h.apply_hook(plan, self.pf, self.store, plan["plan_sha256"])
        self.assertEqual(self.pf.root(), h.normalize(APPLE_ROOT))

    def test_cli_apply_refuses_without_flags(self):
        with self.store.lock():
            plan = h.stage(self.pf, self.store)
        code = h.main(
            [
                "apply",
                "--journal-dir",
                str(self.journal),
                "--plan-sha256",
                plan["plan_sha256"],
            ],
            pf=self.pf,
        )
        self.assertEqual(code, 78)

    def test_cli_stage_and_status(self):
        code = h.main(["stage", "--journal-dir", str(self.journal)], pf=self.pf)
        self.assertEqual(code, 0)
        code = h.main(["status", "--journal-dir", str(self.journal)], pf=self.pf)
        self.assertEqual(code, 0)

    def test_reapply_after_restore(self):
        with self.store.lock():
            plan = h.stage(self.pf, self.store)
        with self.store.lock():
            h.apply_hook(plan, self.pf, self.store, plan["plan_sha256"])
        with self.store.lock():
            h.restore(plan, self.pf, self.store)
        with self.store.lock():
            plan2 = h.stage(self.pf, self.store)
        with self.store.lock():
            state = h.apply_hook(plan2, self.pf, self.store, plan2["plan_sha256"])
        self.assertEqual(state["phase"], "installed_unverified")
        self.assertIn(f'anchor "{h.ANCHOR}"', self.pf.root())


class BuildRootUnit(unittest.TestCase):
    def test_reference_tokens_empty_and_table(self):
        self.assertEqual(h.reference_tokens("No pf starter references held\n"), set())
        table = (
            "PID      Process Name                 TOKEN                    TIMESTAMP\n"
            "44       pfctl                        12345                    0 days 00:00:01\n"
        )
        self.assertEqual(h.reference_tokens(table), {"12345"})


if __name__ == "__main__":
    unittest.main()
