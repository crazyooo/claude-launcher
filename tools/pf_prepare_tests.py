#!/usr/bin/env python3
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import pf_prepare as p


class PreparationTests(unittest.TestCase):
    def test_authentication_failure_does_not_sample_or_stage(self):
        with patch('pf_prepare.os.geteuid', return_value=501), \
                patch('pf_prepare.subprocess.run', return_value=subprocess.CompletedProcess([], 1)) as run, \
                patch('pf_prepare.discover') as discover, redirect_stdout(io.StringIO()):
            self.assertEqual(p.main(), 78)
        run.assert_called_once_with(['/usr/bin/sudo', '-v'])
        discover.assert_not_called()

    def test_success_authenticates_before_sampling_then_only_stages(self):
        events = []
        now = time.time()
        policy = {'version': 1, 'entries': [{'cidr': '160.79.104.10/32', 'source': 'fixture',
                                          'observed_at': now - 1, 'expires_at': now + 100}]}
        output = {'reason': 'staged_only_no_pf_changes', 'id': 'a'*32,
                  'protection_verified': False, 'launch_authorized': False}

        def run(command, **kwargs):
            events.append(command)
            return subprocess.CompletedProcess(command, 0, stdout=json.dumps(output).encode())

        def discover():
            events.append('sample')
            return policy

        with patch('pf_prepare.os.geteuid', return_value=501), patch('pf_prepare.subprocess.run', side_effect=run), \
                patch('pf_prepare.discover', side_effect=discover), patch('pf_prepare.save_snapshot', return_value='/tmp/test-policy.json'), \
                redirect_stdout(io.StringIO()) as capture:
            self.assertEqual(p.main(), 0)
        self.assertEqual(events[0], ['/usr/bin/sudo', '-v'])
        self.assertEqual(events[1], 'sample')
        self.assertEqual(events[2][-3:], ['stage', '--policy', '/tmp/test-policy.json'])
        self.assertFalse(json.loads(capture.getvalue())['pf_modified'])
        self.assertTrue(json.loads(capture.getvalue())['observer_install_command'].endswith('install --id ' + 'a'*32))

    def test_snapshot_private_and_roundtrips(self):
        with tempfile.TemporaryDirectory() as directory:
            original = tempfile.mkstemp
            with patch('pf_prepare.tempfile.mkstemp', side_effect=lambda **kwargs: original(dir=directory, **kwargs)):
                filename = p.save_snapshot({'version': 1})
            self.assertEqual(stat.S_IMODE(os.stat(filename).st_mode), 0o600)
            self.assertEqual(json.loads(Path(filename).read_text()), {'version': 1})

    def test_root_invocation_refused_before_authentication(self):
        with patch('pf_prepare.os.geteuid', return_value=0), patch('pf_prepare.subprocess.run') as run, redirect_stdout(io.StringIO()):
            self.assertEqual(p.main(), 78)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
