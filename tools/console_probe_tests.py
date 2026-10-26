#!/usr/bin/env python3
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch
import console_probe as c
import providers as p
from providers_tests import fixture, server, respond_json


class ConsoleProbeTests(unittest.TestCase):
    def test_real_adapter_uses_stdin_and_fixed_gets(self):
        data = fixture()
        with server(lambda r: respond_json(r, data[r.path])) as (url, calls):
            run = subprocess.run(["/usr/bin/python3", "-I", "-B", str(Path(c.__file__).resolve())],
                                 input=json.dumps({"endpoint": url, "token": "TEST_SECRET"}),
                                 text=True, capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stdout)
        report = json.loads(run.stdout)
        self.assertEqual(report["totalConnections"], 2)
        self.assertEqual(report["endpoint"], url)
        self.assertLessEqual(report["startedAt"], report["completedAt"])
        self.assertEqual([v[:2] for v in calls], [("GET", v) for v in p.API_PATHS])
        self.assertTrue(all(v[2] == "Bearer TEST_SECRET" for v in calls))
        for private in ("TEST_SECRET", "PRIVATE_PATH", "PRIVATE_ID", '"secret"', '"password"'):
            self.assertNotIn(private, run.stdout)
        self.assertEqual(run.stderr, "")

    def test_reflected_token_removed_and_process_path_not_returned(self):
        data = fixture()
        data["/version"]["version"] = "token-secret"
        row = data["/connections"]["connections"][0]
        row["metadata"].update(host="token-secret.example", process="/private/user/Claude", processPath="PRIVATE_FULL_PATH")
        row["chains"] = ["token-secret"]
        result = c.summarize(data, "token-secret")
        self.assertEqual(result["connections"][0]["process"], "Claude")
        for secret in ("token-secret", "PRIVATE_FULL_PATH", "/private/user", "SECRET"):
            self.assertNotIn(secret, json.dumps(result))

    def test_limit_connections_and_chain_length(self):
        data = fixture()
        row = data["/connections"]["connections"][0]
        row["chains"] = ["x" * 1000] * 100
        data["/connections"]["connections"] = [row] * 80
        result = c.summarize(data, "test")
        self.assertEqual(result["totalConnections"], 80)
        self.assertEqual(len(result["connections"]), 40)
        self.assertEqual(len(result["connections"][0]["chains"]), 8)
        self.assertLess(len(json.dumps(result).encode()), 120000)

    def test_partial_batch_failure_returns_no_snapshot(self):
        data = fixture()
        with server(lambda r: respond_json(r, data[r.path], 403 if r.path == "/connections" else 200)) as (url, _):
            with self.assertRaisesRegex(p.InspectionError, "auth_rejected"):
                c.collect(url, "fixture-token")

    def test_invalid_schema_and_counters(self):
        for bad in (-1, True, "42", 2**63):
            data = fixture()
            data["/connections"]["uploadTotal"] = bad
            with self.assertRaises(p.InspectionError):
                c.summarize(data, "token")
        data = fixture(); data["/configs"]["tun"] = {"enable": "false"}
        with self.assertRaises(p.InspectionError):
            c.summarize(data, "token")

    def test_escaped_maximum_token_envelope_accepted(self):
        data = fixture()
        token = '"' * 4096
        with server(lambda r: respond_json(r, data[r.path])) as (url, _):
            run = subprocess.run(["/usr/bin/python3", "-I", "-B", c.__file__],
                                 input=json.dumps({"endpoint": url, "token": token}),
                                 text=True, capture_output=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stdout)

    def test_invalid_stdin_does_not_echo(self):
        for raw in ('{"token":"PRIVATE_SECRET",', "PRIVATE_SECRET" * 2000):
            run = subprocess.run(["/usr/bin/python3", "-I", "-B", c.__file__], input=raw,
                                 text=True, capture_output=True, timeout=3)
            self.assertNotEqual(run.returncode, 0)
            self.assertNotIn("PRIVATE_SECRET", run.stdout + run.stderr)


if __name__ == "__main__":
    unittest.main()
