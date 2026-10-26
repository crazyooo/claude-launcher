import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import fetch_router_core as fetch

class DownloadTests(unittest.TestCase):
    def test_deadline_kills_worker_and_never_waits_without_bound(self):
        class Worker:
            returncode = 0
            def __init__(self): self.calls = []; self.killed = False
            def communicate(self, timeout):
                self.calls.append(timeout)
                if not self.killed: raise subprocess.TimeoutExpired("worker", timeout)
                return b"", None
            def kill(self): self.killed = True
        worker = Worker()
        with self.assertRaisesRegex(ValueError, "download_total_timeout"):
            fetch.download_archive(timeout=0.1, popen=lambda *a, **k: worker)
        self.assertTrue(worker.killed); self.assertEqual(worker.calls, [0.1, 3])
    def test_unconfirmed_cleanup_is_not_reported_as_reaped(self):
        class Worker:
            def communicate(self, timeout): raise subprocess.TimeoutExpired("worker", timeout)
            def kill(self): pass
        with self.assertRaisesRegex(ValueError, "cleanup_unconfirmed"):
            fetch.download_archive(timeout=0.1, popen=lambda *a, **k: Worker())
    def test_worker_failure_hides_raw_exception(self):
        with patch.object(fetch.urllib.request, "urlopen", side_effect=RuntimeError("secret-token")):
            self.assertEqual(fetch.download_worker(), 1)
    def test_actual_child_is_stopped_at_total_deadline(self):
        import sys
        children = []
        def launch(*args, **kwargs):
            child = subprocess.Popen([sys.executable, "-I", "-c", "import time; time.sleep(10)"], **kwargs)
            children.append(child); return child
        with self.assertRaisesRegex(ValueError, "download_total_timeout"):
            fetch.download_archive(timeout=0.1, popen=launch)
        self.assertIsNotNone(children[0].poll())
    def test_verify_rejects_changed_bytes_and_link_without_execution(self):
        directory = Path(tempfile.mkdtemp(prefix="router-fetch-test-")).resolve()
        core = directory / "core"; core.write_bytes(b"untrusted"); core.chmod(0o700)
        with self.assertRaisesRegex(ValueError, "changed_preserved"): fetch.verify_core(core)
        link = directory / "link"; link.symlink_to(core)
        with self.assertRaisesRegex(ValueError, "symlink"): fetch.verify_core(link)
        self.assertEqual(core.read_bytes(), b"untrusted")

if __name__ == "__main__": unittest.main()
