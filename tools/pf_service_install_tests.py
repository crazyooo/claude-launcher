"""Installer lifecycle tests with temporary files and a fake launchd/PF backend."""
import json
import io
import os
from pathlib import Path
import plistlib
import tempfile
import subprocess
import unittest
from contextlib import redirect_stdout, nullcontext
from unittest.mock import patch

import pf_guard as g
import pf_service as s
import pf_service_install as i
from pf_guard_tests import FakePF
from pf_service_tests import dns_policy
from pf_policy import fingerprint


class InstallerTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        directory = Path(temp.name)
        self.root = directory/'support'; self.root.mkdir()
        self.plist = directory/'launchd.plist'
        self.store = g.Store(directory/'journal')
        self.pf = FakePF()
        with self.store.lock():
            self.plan = g.stage(dns_policy(), self.pf, self.store)
            g.apply(self.plan, fingerprint(self.plan), self.pf, self.store)
        self.initial_mutations = list(self.pf.mutations)
        self.calls = []
        self.patches = [patch.object(i, 'ROOT', self.root), patch.object(i, 'PLIST', self.plist),
                        patch.object(i, 'MANIFEST', self.root/'installation.json'),
                        patch.object(i, 'Store', return_value=self.store), patch.object(i, 'PF', return_value=self.pf),
                        patch.object(i, 'trusted_directory'), patch.object(i, 'stop_job'),
                        patch.object(i, 'job_snapshot', return_value=None),
                        patch.object(i, 'publish'),
                        patch.object(i, 'launchctl', side_effect=lambda *args: self.calls.append(args)),
                        patch.object(i, 'safe_read', side_effect=lambda path, **kw: s.safe_read(path, owner=os.geteuid(), **kw))]
        for item in self.patches:
            item.start(); self.addCleanup(item.stop)

    def install(self):
        return i.install(self.plan['id'])

    def test_install_retry_uninstall_preserves_pf_and_runtime(self):
        result = self.install()
        manifest = i.read_manifest()
        runtime = Path(manifest['runtime'])
        config = plistlib.loads(self.plist.read_bytes())
        self.assertEqual(config['ProgramArguments'][:4], ['/usr/bin/python3', '-E', '-s', '-B'])
        self.assertEqual(set(path.name for path in runtime.iterdir()), set(i.FILES))
        self.assertEqual(result['plan_id'], self.plan['id'])
        self.assertEqual(manifest['phase'], 'installed')
        self.assertEqual(os.stat(runtime).st_mode & 0o777, 0o755)
        self.assertEqual(os.stat(i.MANIFEST).st_mode & 0o777, 0o600)
        self.install()
        i.uninstall()
        self.assertFalse(self.plist.exists())
        self.assertTrue((runtime/'pf_guard.py').exists())
        self.assertEqual(i.read_manifest()['phase'], 'uninstalled')
        self.assertEqual(self.pf.mutations, self.initial_mutations)
        self.assertEqual(len(list(self.root.glob('archived-*.plist'))), 1)

    def test_unowned_plist_is_preserved(self):
        self.plist.write_bytes(b'foreign')
        with self.assertRaisesRegex(g.GuardError, 'unowned_launchd'):
            self.install()
        self.assertEqual(self.plist.read_bytes(), b'foreign')
        self.assertEqual(self.calls, [])

    def test_changed_runtime_refuses_update_and_uninstall(self):
        self.install()
        manifest = i.read_manifest()
        path = Path(manifest['runtime'])/'pf_service.py'
        path.write_bytes(b'changed')
        for action in (self.install, i.uninstall):
            with self.assertRaisesRegex(g.GuardError, 'modified_runtime'):
                action()
        self.assertEqual(path.read_bytes(), b'changed')

    def test_partial_runtime_write_can_retry(self):
        original = i.atomic
        def interrupted(path, value, mode=0o600, **kwargs):
            if path.name == 'pf_guard.py':
                raise OSError('simulated interruption')
            return original(path, value, mode, **kwargs)
        with patch.object(i, 'atomic', side_effect=interrupted), self.assertRaises(OSError):
            self.install()
        self.assertEqual(i.read_manifest()['phase'], 'install_pending')
        self.install()
        self.assertEqual(i.read_manifest()['phase'], 'installed')

    def test_upgrade_pending_can_accept_only_recorded_previous_plist(self):
        self.install()
        old = self.plist.read_bytes()
        original = i.atomic
        def interrupted(path, value, mode=0o600, **kwargs):
            if path == self.plist:
                raise OSError('simulated interruption')
            return original(path, value, mode, **kwargs)
        package = i.package(); package['pf_service.py'] += b'\n# upgrade fixture\n'
        with patch.object(i, 'package', return_value=package):
            with patch.object(i, 'atomic', side_effect=interrupted), self.assertRaises(OSError):
                self.install()
            manifest = i.read_manifest()
            self.assertEqual(manifest['previous_plist_sha256'], i.sha(old))
            self.assertNotEqual(manifest['plist_sha256'], i.sha(old))
            i.verify_files(manifest)
            manifest['phase'] = 'bootstrap_pending'
            with self.assertRaises(g.GuardError):
                i.verify_files(manifest)
            self.install()
        self.assertEqual(i.read_manifest()['phase'], 'installed')

    def test_restore_during_copy_prevents_bootstrap(self):
        original = i.package
        def restore_during_package():
            with self.store.lock():
                g.recover(self.plan, self.pf, self.store)
            return original()
        with patch.object(i, 'package', side_effect=restore_during_package), self.assertRaisesRegex(g.GuardError, 'active_applied'):
            self.install()
        self.assertEqual(self.calls, [])
        self.assertEqual(i.read_manifest()['phase'], 'bootstrap_pending')

    def test_crash_after_temporary_file_write_can_retry(self):
        original = os.replace
        def interrupted(source, target):
            if Path(target).name == 'pf_service.py':
                raise OSError('interrupted before replace')
            return original(source, target)
        with patch.object(s.os, 'replace', side_effect=interrupted), self.assertRaises(OSError):
            self.install()
        leftovers = list(self.root.glob('.pending-*'))
        self.assertEqual(len(leftovers), 1)
        self.assertGreater(leftovers[0].stat().st_size, 0)
        self.install()
        self.assertTrue(leftovers[0].exists())  # Preserve recoverable bytes.
        self.assertEqual(i.read_manifest()['phase'], 'installed')

    def test_restored_plan_rejected_before_files(self):
        with self.store.lock():
            g.recover(self.plan, self.pf, self.store)
        with self.assertRaisesRegex(g.GuardError, 'active_applied'):
            self.install()
        self.assertFalse(i.MANIFEST.exists())

    def loaded(self):
        manifest = i.read_manifest()
        config = i.definition(self.plan['id'], Path(manifest['runtime']))
        return {'pid': 1234, 'path': str(self.plist), 'program': '/usr/bin/python3',
                'cwd': config['WorkingDirectory'], 'arguments': config['ProgramArguments']}

    def test_identical_loaded_install_does_not_restart_or_clear_fault(self):
        self.install()
        before = i.MANIFEST.read_bytes()
        self.calls.clear(); i.stop_job.reset_mock(); i.publish.reset_mock()
        with patch.object(i, 'job_snapshot', return_value=self.loaded()):
            result = self.install()
        self.assertEqual(result['reason'], 'observer_already_loaded_state_preserved')
        self.assertEqual(self.calls, [])
        i.stop_job.assert_not_called(); i.publish.assert_not_called()
        self.assertEqual(i.MANIFEST.read_bytes(), before)

    def test_same_install_absent_job_bootstraps_once(self):
        self.install(); self.calls.clear()
        self.install()
        self.assertEqual(sum(args[0] == 'bootstrap' for args in self.calls), 1)

    def test_missing_runtime_file_never_takes_noop(self):
        self.install()
        loaded = self.loaded()
        runtime = Path(i.read_manifest()['runtime'])
        (runtime/'pf_service.py').rename(self.root/'archived-service.py')
        self.calls.clear()
        with patch.object(i, 'job_snapshot', return_value=loaded):
            self.install()
        self.assertIn(('bootstrap', 'system', str(self.plist)), self.calls)

    def test_loaded_identity_mismatch_preserved(self):
        self.install()
        loaded = self.loaded(); loaded['arguments'] = ['/usr/bin/foreign']
        self.calls.clear(); i.stop_job.reset_mock()
        with patch.object(i, 'job_snapshot', return_value=loaded), self.assertRaisesRegex(g.GuardError, 'identity_mismatch'):
            self.install()
        self.assertEqual(self.calls, []); i.stop_job.assert_not_called()

    def test_bootstrap_pending_complete_loaded_job_finishes_without_restart(self):
        self.install()
        manifest = i.read_manifest(); manifest['phase'] = 'bootstrap_pending'; i.write_manifest(manifest)
        self.calls.clear(); i.stop_job.reset_mock()
        with patch.object(i, 'job_snapshot', return_value=self.loaded()):
            self.install()
        self.assertEqual(i.read_manifest()['phase'], 'installed')
        i.stop_job.assert_not_called(); self.assertEqual(self.calls, [])


class LaunchctlTests(unittest.TestCase):
    def manifest(self):
        return {'phase': 'installed', 'plan_id': 'a'*32, 'runtime': str(i.ROOT/'runtime-test')}

    def fixture(self, pid=1234):
        manifest = self.manifest()
        argv = i.definition(manifest['plan_id'], Path(manifest['runtime']))['ProgramArguments']
        return (f'system/{i.LABEL} = {{\n\tactive count = 1\n\tpath = {i.PLIST}\n'
                '\tstate = running\n\tprogram = /usr/bin/python3\n\targuments = {\n' +
                ''.join('\t\t'+arg+'\n' for arg in argv) + '\t}\n' +
                f'\tworking directory = {manifest["runtime"]}\n\tpid = {pid}\n' +
                '\tresource coalition = {\n\t\tstate = active\n\t\tactive count = 1\n\t}\n}\n').encode()

    def absent(self):
        return subprocess.CompletedProcess([], 113, b'',
            f'Could not find service "{i.LABEL}" in domain for system\n'.encode())

    def present(self, pid=1234):
        return subprocess.CompletedProcess([], 0, self.fixture(pid), b'')

    def test_real_wrapper_parses_top_level_and_exact_absence(self):
        with patch.object(i.subprocess, 'run', side_effect=[self.present(), self.absent()]):
            loaded = i.job_snapshot()
            self.assertEqual(loaded['pid'], 1234)
            self.assertTrue(i.job_matches(loaded, self.manifest()))
            self.assertIsNone(i.job_snapshot())
        for result in (subprocess.CompletedProcess([], 1, b'', self.absent().stderr),
                       subprocess.CompletedProcess([], 113, b'', b'permission denied')):
            with patch.object(i.subprocess, 'run', return_value=result), self.assertRaises(i.LaunchdError):
                i.job_snapshot()

    def test_ambiguous_or_missing_top_level_pid_rejected(self):
        for raw in (self.fixture()+b'\tstate = running\n',
                    self.fixture().replace(b'\tpid = 1234\n', b''),
                    self.fixture().replace(b'\targuments = {', b'  arguments = {')):
            with patch.object(i.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, raw, b'')), self.assertRaises(g.GuardError):
                i.job_snapshot()

    def test_nonzero_and_timeout_diagnostics_do_not_include_raw_output(self):
        with patch.object(i.subprocess, 'run', return_value=subprocess.CompletedProcess([], 5, b'private', b'private')):
            with self.assertRaises(i.LaunchdError) as raised:
                i.launchctl('bootstrap', 'system', str(i.PLIST))
        self.assertEqual(raised.exception.diagnostic, {'operation': 'bootstrap', 'exit_code': 5, 'timed_out': False})
        with patch.object(i.subprocess, 'run', side_effect=subprocess.TimeoutExpired('private', 5)):
            with self.assertRaises(i.LaunchdError) as raised:
                i.launchctl('bootout', 'system/'+i.LABEL)
        self.assertTrue(raised.exception.diagnostic['timed_out'])
        with patch.object(i.os, 'geteuid', return_value=0), patch.object(i, 'installation_lock', return_value=nullcontext()), \
                patch.object(i, 'install', side_effect=raised.exception), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(i.main(['install','--id','a'*32]), 78)
        self.assertEqual(json.loads(output.getvalue())['launchd_error']['operation'], 'bootout')
        self.assertNotIn('private', output.getvalue())

    def test_stop_waits_for_process_after_job_disappears(self):
        manifest = self.manifest(); calls = []
        results = [self.present(), subprocess.CompletedProcess([], 0, b'', b''), self.absent(), self.absent()]
        with patch.object(i.subprocess, 'run', side_effect=results), patch.object(i, 'write_manifest', side_effect=lambda m: calls.append(json.loads(json.dumps(m)))), \
                patch.object(i, 'pid_gone', side_effect=[False, True]) as gone, patch.object(i.time, 'sleep'):
            i.stop_job(manifest)
        self.assertTrue(calls[0]['stop_requested'])
        self.assertEqual(calls[0]['stop_pids'], [1234])
        self.assertEqual(gone.call_count, 2)
        self.assertFalse(manifest['stop_requested'])

    def test_stop_nonzero_or_timeout_can_be_confirmed_removed(self):
        for failure in (subprocess.CompletedProcess([], 36, b'', b''), subprocess.TimeoutExpired('bootout', 15)):
            manifest = self.manifest()
            with patch.object(i.subprocess, 'run', side_effect=[self.present(), failure, self.absent()]), \
                    patch.object(i, 'write_manifest'), patch.object(i, 'pid_gone', return_value=True):
                result = i.stop_job(manifest)
            self.assertEqual(result['effect'], 'job_absent_old_processes_exited')
            self.assertEqual(manifest['last_stop_attempt']['timed_out'], isinstance(failure, subprocess.TimeoutExpired))

    def test_new_pid_observed_while_stopping_is_also_waited(self):
        manifest = self.manifest()
        results = [self.present(), subprocess.CompletedProcess([], 0, b'', b''), self.present(5678), self.absent()]
        with patch.object(i.subprocess, 'run', side_effect=results), patch.object(i, 'write_manifest'), \
                patch.object(i, 'pid_gone', return_value=True) as gone, patch.object(i.time, 'sleep'):
            i.stop_job(manifest)
        self.assertEqual([call.args[0] for call in gone.call_args_list], [1234, 5678])

    def test_pending_stop_retry_retains_process_and_prior_attempt(self):
        manifest = self.manifest()
        manifest.update(stop_requested=True, stop_pids=[1234], last_stop_attempt={'exit_code': 36})
        with patch.object(i.subprocess, 'run', side_effect=[self.absent(), self.absent()]), \
                patch.object(i, 'write_manifest'), patch.object(i, 'pid_gone', return_value=True) as gone:
            result = i.stop_job(manifest)
        gone.assert_called_once_with(1234)
        self.assertEqual(result['bootout'], {'exit_code': 36})

    def test_wait_timeout_preserves_pending_state(self):
        manifest = self.manifest()
        with patch.object(i.subprocess, 'run', side_effect=[self.present(), subprocess.CompletedProcess([], 0, b'', b'')]), \
                patch.object(i, 'write_manifest'), patch.object(i.time, 'monotonic', side_effect=[0, 16]):
            with self.assertRaises(i.LaunchdError) as raised:
                i.stop_job(manifest)
        self.assertEqual(raised.exception.diagnostic['operation'], 'wait_for_removal')
        self.assertTrue(manifest['stop_requested'])
        self.assertEqual(manifest['stop_pids'], [1234])


if __name__ == '__main__':
    unittest.main()
