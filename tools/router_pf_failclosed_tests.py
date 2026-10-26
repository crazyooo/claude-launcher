#!/usr/bin/env python3
"""Offline tests for tools/router_pf_failclosed.py (no root apply)."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().with_name("router_pf_failclosed.py")


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        capture_output=True,
        text=True,
        timeout=30,
    )


class RouterPFFailClosedTests(unittest.TestCase):
    def test_generate_direct_only_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps({"rules": [], "defaultDestination": {"kind": "direct"}}))
            out = Path(tmp) / "out"
            result = run("generate", "--plan", str(plan), "--output", str(out))
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["status"], "generated")
            self.assertFalse(payload["applicable"])
            self.assertFalse(payload["armed"])
            self.assertFalse(payload["routing_verified"])
            meta = json.loads((out / "failclosed.artifact.json").read_text())
            self.assertIn("no_protected_subjects_fail_closed_not_applicable", meta["blockers"])

    def test_generate_with_block_domain_and_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = {
                "rules": [{
                    "id": "11111111-1111-1111-1111-111111111111",
                    "selector": {"domain": {"kind": "exact", "value": "example.com"}},
                    "destination": {"kind": "block"},
                }],
                "defaultDestination": {"kind": "direct"},
            }
            plan_path = Path(tmp) / "plan.json"
            plan_path.write_text(json.dumps(plan))
            digest = "a" * 64
            out = Path(tmp) / "out"
            result = run(
                "generate",
                "--plan", str(plan_path),
                "--plan-digest", digest,
                "--address", "1.1.1.1",
                "--output", str(out),
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            payload = json.loads(result.stdout)
            self.assertTrue(payload["applicable"])
            conf = (out / "failclosed.pf.conf").read_text()
            self.assertIn("claude_router_failclosed", conf)
            self.assertIn("1.1.1.1", conf)
            self.assertIn("block drop out quick inet", conf)

    def test_apply_refuses_without_flags(self):
        with tempfile.TemporaryDirectory() as tmp:
            meta = {
                "plan_digest": "b" * 64,
                "applicable": True,
                "blockers": [],
                "source_sha256": "0" * 64,
                "pf_conf_path": str(Path(tmp) / "x.pf.conf"),
            }
            artifact = Path(tmp) / "a.json"
            artifact.write_text(json.dumps(meta))
            result = run("apply", "--artifact", str(artifact), "--plan-digest", "b" * 64)
            self.assertEqual(result.returncode, 78)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["reason"], "missing_flag_i_confirm_pf_arming_user_confirm_v1")
            self.assertFalse(payload["pf_modified"])

    def test_rejects_private_address(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = Path(tmp) / "plan.json"
            plan.write_text(json.dumps({
                "rules": [{
                    "id": "11111111-1111-1111-1111-111111111111",
                    "selector": {"domain": {"kind": "exact", "value": "example.com"}},
                    "destination": {"kind": "block"},
                }],
                "defaultDestination": {"kind": "direct"},
            }))
            out = Path(tmp) / "out"
            result = run(
                "generate", "--plan", str(plan),
                "--address", "192.168.1.1", "--output", str(out),
            )
            self.assertEqual(result.returncode, 78)
            self.assertIn("destination_address_not_public_unicast", result.stdout)


    def _block_plan(self, tmp, extra_selector=None, proxies=None):
        selector = {"domain": {"kind": "exact", "value": "example.com"}}
        selector.update(extra_selector or {})
        plan = {"proxies": proxies or [], "rules": [{
            "id": "11111111-1111-1111-1111-111111111111",
            "selector": selector, "destination": {"kind": "block"}}],
            "defaultDestination": {"kind": "direct"}}
        path = Path(tmp) / "plan.json"
        path.write_text(json.dumps(plan))
        return path

    def test_rejects_non_global_addresses(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self._block_plan(tmp)
            for addr in ("198.18.0.5", "100.64.1.1", "::", "ff02::1", "2001:db8::1", "8_8.8.8.8"):
                result = run("generate", "--plan", str(plan), "--address", addr, "--output", str(Path(tmp) / "o"))
                self.assertEqual(result.returncode, 78, addr)
                self.assertIn("destination_address_not_public_unicast", result.stdout, addr)

    def test_rejects_proxy_transport_overlap(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self._block_plan(tmp, proxies=[{"host": "9.9.9.9"}])
            result = run("generate", "--plan", str(plan), "--address", "9.9.9.9", "--output", str(Path(tmp) / "o"))
            self.assertEqual(result.returncode, 78)
            self.assertIn("destination_overlaps_proxy_transport", result.stdout)

    def test_process_path_makes_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self._block_plan(tmp, {"processPath": "/usr/bin/curl"})
            out = Path(tmp) / "o"
            result = run("generate", "--plan", str(plan), "--address", "1.1.1.1", "--output", str(out))
            self.assertFalse(json.loads(result.stdout)["applicable"])
            self.assertNotIn("block drop", (out / "failclosed.pf.conf").read_text())

    def test_apply_refuses_self_consistent_tampered_conf_before_root(self):
        import hashlib
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "c.conf"
            conf.write_text("block drop out all\n")
            digest = "c" * 64
            artifact = Path(tmp) / "a.json"
            artifact.write_text(json.dumps({
                "plan_digest": digest, "applicable": True, "blockers": [], "addresses": [],
                "source_sha256": hashlib.sha256(conf.read_bytes()).hexdigest(),
                "pf_conf_path": str(conf)}))
            result = run("apply", "--artifact", str(artifact), "--plan-digest", digest,
                         "--i-confirm-pf-arming-user-confirm-v1", "--i-acknowledge-network-mutation")
            self.assertEqual(result.returncode, 78)
            self.assertEqual(json.loads(result.stdout)["reason"], "pf_conf_not_canonical")

    def test_generate_rejects_malformed_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = self._block_plan(tmp)
            result = run("generate", "--plan", str(plan), "--plan-digest", "nothex", "--output", str(Path(tmp) / "o"))
            self.assertEqual(json.loads(result.stdout)["reason"], "plan_digest_required_64_hex")

if __name__ == "__main__":
    unittest.main()
