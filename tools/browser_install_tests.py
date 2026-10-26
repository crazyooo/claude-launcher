"""No browser download, launch or real profile changes."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import browser_install as browser

class BrowserInstallerTests(unittest.TestCase):
    def test_inspect_missing_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory)/'absent'
            with patch.object(browser, 'ROOT', missing):
                self.assertEqual(browser.inspect()['reason'], 'browser_not_installed')
            self.assertFalse(missing.exists())
    def test_download_has_deadline_and_rejects_wrong_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'image.dmg'
            with patch.object(browser, 'command') as run:
                with self.assertRaisesRegex(browser.Failure, 'digest_mismatch'): browser.download(path)
            args = run.call_args.args[0]
            self.assertIn('--max-time', args); self.assertIn('900', args)
            self.assertEqual(run.call_args.kwargs['timeout'], 905)
    def test_system_verifier_failure_is_static(self):
        with patch.object(browser.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, b'', b'private response')):
            with self.assertRaises(browser.Failure) as error: browser.command(['/usr/bin/codesign', 'test'])
        self.assertEqual(str(error.exception), 'verification_failed_codesign')

if __name__ == '__main__': unittest.main()
