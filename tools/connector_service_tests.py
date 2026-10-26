"""Lifecycle parsing tests; never starts a real launchd job."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
import connector_service as service

class ConnectorServiceTests(unittest.TestCase):
    def test_healthy_requires_fresh_live_unprivileged_snapshot(self):
        value = dict(sampledAt=time.time()-978307200, heartbeatAge=0.5, state='blocked', port=12345,
                     launchAuthorized=False, protectionVerified=False)
        self.assertTrue(service.healthy(value))
        for change in [dict(state='stopped'), dict(port=0), dict(heartbeatAge=3), dict(heartbeatAge=-1),
                       dict(sampledAt=value['sampledAt']-5), dict(sampledAt=value['sampledAt']+5),
                       dict(launchAuthorized=True), dict(protectionVerified=True)]:
            self.assertFalse(service.healthy(dict(value, **change)))

    def test_absence_requires_exact_error(self):
        absent = ('Could not find service "' + service.LABEL + '" in domain for user gui: ' + str(os.getuid())).encode()
        with patch.object(service, 'run', return_value=subprocess.CompletedProcess([], 113, b'', absent)):
            self.assertIsNone(service.job())
        for code in (1, 5, 113):
            with patch.object(service, 'run', return_value=subprocess.CompletedProcess([], code, b'', b'unknown failure')):
                with self.assertRaises(service.ServiceError): service.job()
    def test_loaded_identity_and_top_level_pid(self):
        text = (service.DOMAIN + '/' + service.LABEL + ' = {\n' +
                '\tpath = ' + str(service.PLIST) + '\n\tprogram = ' + str(service.TOOL) +
                '\n\tstate = running\n\tactive count = 1\n\tpid = 34567\n\targuments = {\n\t\t' + str(service.TOOL) +
                '\n\t\tconnector-guard\n\t}\n}\n')
        with patch.object(service, 'run', return_value=subprocess.CompletedProcess([], 0, text.encode(), b'')):
            self.assertEqual(service.job(), 34567)
        for altered in (text.replace('connector-guard', 'other'), text.replace('\tpid', '\t\tpid')):
            with patch.object(service, 'run', return_value=subprocess.CompletedProcess([], 0, altered.encode(), b'')):
                with self.assertRaises(service.ServiceError): service.job()
    def test_pending_stop_is_not_forgotten_after_job_disappears(self):
        with tempfile.TemporaryDirectory() as root:
            manifest = Path(root)/'manifest.json'; value = {'pending_stop_pids': [34567]}
            times = iter([0, 0, 9])
            with patch.object(service, 'MANIFEST', manifest), patch.object(service, 'job', return_value=None), \
                 patch.object(service, 'alive', return_value=True), patch.object(service.time, 'monotonic', side_effect=lambda: next(times)), \
                 patch.object(service.time, 'sleep'):
                with self.assertRaisesRegex(service.ServiceError, 'stop_pending'): service.await_stopped(value)
                self.assertEqual(value['pending_stop_pids'], [34567])
            with patch.object(service, 'MANIFEST', manifest), patch.object(service, 'job', return_value=None), \
                 patch.object(service, 'alive', return_value=False):
                service.await_stopped(value)
                self.assertNotIn('pending_stop_pids', json.loads(manifest.read_text()))

if __name__ == '__main__': unittest.main()
