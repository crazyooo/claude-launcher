"""Runtime/control integration using private fixture journals; no root or PF changes."""
from contextlib import contextmanager, nullcontext, redirect_stdout
import io
import json
import os
from pathlib import Path
import plistlib
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pf_runtime_identity as identity
import pf_recovery_receipt as recovery
import pf_service as service
import pf_service_install as installer
from pf_guard import GuardError
import pf_service_tests as observer_fixtures
import pf_service_install_tests as installer_fixtures


class IdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.plist = self.root / 'job.plist'
        self.plan = {'id': '1' * 32}
        files = {name: identity.digest(name.encode()) for name in identity.FILES}
        self.runtime = self.root / ('runtime-' + identity.fingerprint(files))
        self.runtime.mkdir()
        for name in files:
            (self.runtime / name).write_bytes(name.encode())
        self.plist.write_bytes(plistlib.dumps(identity.definition(self.plan['id'], self.runtime), sort_keys=True))
        self.manifest = {'version': 1, 'phase': 'installed', 'plan_id': self.plan['id'],
            'plan_sha256': identity.fingerprint(self.plan), 'files': files, 'runtime': str(self.runtime),
            'plist_sha256': identity.digest(self.plist.read_bytes()),
            'control_version': 1, 'control_sha256': files['pf_control.py']}
        (self.root / 'pf_control.py').write_bytes(b'pf_control.py')
        (self.root / 'installation.json').write_text(json.dumps(self.manifest))
        self.job = {'pid': 1234, 'path': str(self.plist), 'program': '/usr/bin/python3',
                    'cwd': str(self.runtime),
                    'arguments': identity.definition(self.plan['id'], self.runtime)['ProgramArguments']}
        reader = identity.safe_read
        self.patches = [patch.object(identity, 'trusted_directory'),
                        patch.object(identity, 'safe_read', side_effect=lambda path, **kw:
                                     reader(path, owner=os.geteuid(), **kw)),
                        patch.object(identity, 'running_job', return_value=self.job)]
        for item in self.patches:
            item.start()
            self.addCleanup(item.stop)

    def verify(self, **kwargs):
        return identity.verify_complete(self.manifest, root=self.root, plist=self.plist,
                                        service_file=self.runtime/'pf_service.py', **kwargs)

    def test_complete_files_and_definition_are_required(self):
        self.assertEqual(self.verify(), self.runtime)
        path = self.runtime / 'pf_service.py'
        path.rename(self.root / 'retained-service.py')
        with self.assertRaisesRegex(identity.IdentityError, 'runtime_files_incomplete'):
            self.verify()
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(identity.IdentityError, 'runtime_digest_mismatch'):
            self.verify()
        path.write_bytes(path.name.encode())
        (self.runtime / 'unknown.py').write_bytes(b'foreign')
        with self.assertRaisesRegex(identity.IdentityError, 'runtime_files_incomplete'):
            self.verify()

    def test_manifest_layout_requires_exact_known_set_and_hash_path(self):
        self.assertEqual(identity.manifest_layout(self.manifest, self.root), identity.FILES)
        for change in ({'version': True}, {'plan_id': '../x'}, {'files': []}, {'runtime': str(self.root/'runtime-' )},
                       {'files': dict(self.manifest['files'], extra='a'*64)}, {'plan_sha256': 'wrong'},
                       {'phase': 'unknown'}):
            with self.subTest(change=list(change)), self.assertRaises(identity.IdentityError):
                identity.manifest_layout(dict(self.manifest, **change), self.root)
        legacy = dict(self.manifest, files={name: self.manifest['files'][name] for name in identity.LEGACY_FILES})
        legacy.pop('control_version'); legacy.pop('control_sha256')
        legacy['runtime'] = str(self.root / ('runtime-' + identity.fingerprint(legacy['files'])))
        self.assertEqual(identity.manifest_layout(legacy, self.root), identity.LEGACY_FILES)
        receipt = dict(legacy, files={name: self.manifest['files'][name] for name in identity.RECEIPT_FILES})
        receipt['runtime'] = str(self.root / ('runtime-' + identity.fingerprint(receipt['files'])))
        self.assertEqual(identity.manifest_layout(receipt, self.root), identity.RECEIPT_FILES)

    def test_plist_edited_bytes_or_semantics_cannot_be_blessed_by_manifest(self):
        config = identity.definition(self.plan['id'], self.runtime)
        config['EnvironmentVariables']['EXTRA'] = 'changed'
        self.plist.write_bytes(plistlib.dumps(config, sort_keys=True))
        self.manifest['plist_sha256'] = identity.digest(self.plist.read_bytes())
        with self.assertRaisesRegex(identity.IdentityError, 'launchd_definition_mismatch'):
            self.verify()

    def test_fixed_entry_digest_is_required_even_during_bootstrap(self):
        entry = self.root/'pf_control.py'
        entry.write_bytes(b'old entry')
        self.manifest['previous_control_sha256'] = identity.digest(entry.read_bytes())
        with self.assertRaisesRegex(identity.IdentityError, 'control_digest_mismatch'):
            self.verify()
        self.manifest['phase'] = 'bootstrap_pending'
        with self.assertRaisesRegex(identity.IdentityError, 'control_digest_mismatch'):
            self.verify(startup=True)

    def test_new_control_manifest_fields_cannot_be_mixed_with_legacy_layouts(self):
        for change in ({'control_version': True}, {'control_version': 2},
                       {'control_sha256': 'f'*64}, {'previous_control_sha256': 'bad'}):
            with self.assertRaisesRegex(identity.IdentityError, 'invalid_control_manifest'):
                identity.manifest_layout(dict(self.manifest, **change), self.root)
        for layout in (identity.LEGACY_FILES, identity.RECEIPT_FILES):
            manifest = dict(self.manifest, files={name: self.manifest['files'][name] for name in layout})
            manifest['runtime'] = str(self.root/('runtime-'+identity.fingerprint(manifest['files'])))
            with self.assertRaisesRegex(identity.IdentityError, 'invalid_control_manifest'):
                identity.manifest_layout(manifest, self.root)

    def test_pending_install_only_allows_startup_and_stop_pending_always_rejects(self):
        self.manifest['phase'] = 'bootstrap_pending'
        with self.assertRaisesRegex(identity.IdentityError, 'current_installation_required'):
            self.verify()
        self.assertEqual(self.verify(startup=True), self.runtime)
        for fields in ({'stop_requested': True}, {'stop_requested': 0}, {'stop_pids': [1234]}):
            with patch.dict(self.manifest, fields), self.assertRaisesRegex(identity.IdentityError, 'service_stop_pending'):
                self.verify(startup=True)

    def test_full_installation_plan_path_and_job_identity(self):
        def installed(plan=self.plan, path=None):
            return identity.installed_for_plan(plan, path or self.runtime/'pf_service.py',
                                               root=self.root, plist=self.plist)
        value = installed()
        self.assertEqual(value['service_pid'], 1234)
        self.assertEqual(value['runtime_sha256'], identity.fingerprint(self.manifest['files']))
        with self.assertRaisesRegex(identity.IdentityError, 'service_plan_binding_mismatch'):
            installed(dict(self.plan, changed=True))
        with self.assertRaisesRegex(identity.IdentityError, 'stale_runtime_command'):
            installed(path=self.root/'pf_service.py')
        for change in ({'pid': None}, {'pid': True}, {'pid': 1}, {'cwd': '/tmp'},
                       {'arguments': []}, {'path': '/tmp/foreign.plist'}, {'program': '/usr/bin/other'}):
            with patch.dict(self.job, change), self.assertRaises(identity.IdentityError):
                installed()

    def test_instance_requires_current_runtime_pid_and_plan(self):
        installed = {'service_pid': 1234, 'runtime_sha256': '2'*64}
        state = dict(version=1, running=True, service_instance='3'*32,
                     plan_sha256=identity.fingerprint(self.plan), **installed)
        self.assertEqual(identity.verify_instance(state, installed, self.plan)['service_instance'], '3'*32)
        for change in ({'version': True}, {'service_pid': 1235}, {'service_pid': True}, {'running': 1},
                       {'runtime_sha256': '4'*64}, {'service_instance': ''}, {'plan_sha256': '5'*64}):
            with self.subTest(change=list(change)), self.assertRaisesRegex(identity.IdentityError, 'instance_mismatch'):
                identity.verify_instance(dict(state, **change), installed, self.plan)

    def test_reader_rejects_links_and_writable_content(self):
        target = self.runtime/'pf_service.py'
        target.chmod(0o666)
        with self.assertRaisesRegex(identity.IdentityError, 'untrusted_service_file'):
            self.verify()
        target.chmod(0o644)
        os.link(target, self.root/'hardlink')
        with self.assertRaisesRegex(identity.IdentityError, 'untrusted_service_file'):
            self.verify()

    def test_directory_trust_rejects_symlink_and_group_write(self):
        self.patches[0].stop()
        # Use only the target's real ancestry owned by the current user in this
        # fixture; system root components are tested as explicit lstat results.
        good = os.stat_result((0o40755, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        bad = os.stat_result((0o40775, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(Path, 'lstat', return_value=good):
            identity.trusted_directory(Path('/owned/runtime'))
        with patch.object(Path, 'lstat', side_effect=[good, bad, good]), self.assertRaises(identity.IdentityError):
            identity.trusted_directory(Path('/owned/runtime'))
        symlink = os.stat_result((0o120777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        with patch.object(Path, 'lstat', side_effect=[good, good, symlink]), self.assertRaises(identity.IdentityError):
            identity.trusted_directory(Path('/owned/runtime'))

    def test_control_lock_missing_is_not_created_and_links_rejected(self):
        with self.assertRaises(FileNotFoundError), identity.control_lock(self.root):
            self.fail('missing lock accepted')
        self.assertFalse((self.root/'install.lock').exists())
        (self.root/'install.lock').symlink_to(self.plist)
        with self.assertRaises(OSError), identity.control_lock(self.root):
            self.fail('symlink accepted')

    def test_control_lock_permissions_and_actual_contention(self):
        lock = self.root/'install.lock'
        lock.write_bytes(b'')
        info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0, st_nlink=1)
        with patch.object(identity.os, 'fstat', return_value=info):
            with identity.control_lock(self.root):
                with self.assertRaisesRegex(identity.IdentityError, 'installation_in_progress'), identity.control_lock(self.root):
                    self.fail('concurrent control accepted')
            for changes in ({'st_mode': stat.S_IFREG | 0o644}, {'st_uid': 501}, {'st_nlink': 2}):
                bad = SimpleNamespace(**dict(vars(info), **changes))
                with patch.object(identity.os, 'fstat', return_value=bad), \
                        self.assertRaisesRegex(identity.IdentityError, 'unsafe_service_lock'), identity.control_lock(self.root):
                    self.fail('unsafe lock accepted')


class MigrationTests(unittest.TestCase):
    setUp = installer_fixtures.InstallerTests.setUp
    install = installer_fixtures.InstallerTests.install

    def legacy_install(self):
        content = {name: data for name, data in installer.package().items() if name in identity.LEGACY_FILES}
        with patch.object(installer, 'FILES', identity.LEGACY_FILES), patch.object(installer, 'package', return_value=content):
            self.install()
        return installer.read_manifest()

    def test_four_file_install_upgrades_preserving_old_runtime_and_pf(self):
        old = self.legacy_install()
        before = {name: (Path(old['runtime'])/name).read_bytes() for name in old['files']}
        self.install()
        current = installer.read_manifest()
        self.assertEqual(set(current['files']), set(identity.FILES))
        self.assertNotEqual(current['runtime'], old['runtime'])
        self.assertEqual(before, {name: (Path(old['runtime'])/name).read_bytes() for name in old['files']})
        self.assertEqual(self.pf.mutations, self.initial_mutations)

    def test_old_runtime_may_not_silently_gain_new_module(self):
        old = self.legacy_install()
        foreign = Path(old['runtime'])/'pf_recovery_receipt.py'
        foreign.write_bytes(b'foreign')
        for action in (self.install, installer.uninstall):
            with self.assertRaisesRegex(GuardError, 'unknown_runtime_file_preserved'):
                action()
        self.assertEqual(foreign.read_bytes(), b'foreign')

    def test_partial_six_file_upgrade_can_retry(self):
        old = self.legacy_install()
        original = installer.atomic
        def interrupt(path, value, mode=0o600, **kwargs):
            if path.name == 'pf_recovery_receipt.py':
                raise OSError('interrupted')
            return original(path, value, mode, **kwargs)
        with patch.object(installer, 'atomic', side_effect=interrupt), self.assertRaises(OSError):
            self.install()
        self.assertEqual(installer.read_manifest()['phase'], 'install_pending')
        self.install()
        self.assertEqual(installer.read_manifest()['phase'], 'installed')
        self.assertTrue(Path(old['runtime']).is_dir())


class ControlTests(unittest.TestCase):
    setUp = observer_fixtures.ObserverTests.setUp
    tick = observer_fixtures.ObserverTests.tick
    candidate = observer_fixtures.ObserverTests.candidate

    def production_observer(self):
        self.installation = {'runtime_sha256': 'a'*64, 'service_pid': os.getpid(), 'runtime': '/fixture'}
        self.observer = service.Observer(self.plan, self.pf, self.store, self.messages.append,
                                          installation=self.installation)
        self.observer.next_sample = float('inf')

    def submit(self, **request):
        with patch.object(identity, 'control_lock', return_value=nullcontext()), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(identity, 'installed_for_plan', return_value=self.installation):
            return service.submit_recheck(self.plan['id'], **request)

    def test_bound_request_is_consumed_but_legacy_and_previous_instance_are_not(self):
        self.production_observer()
        legacy = {'request': 'b'*32, 'plan_sha256': self.observer.binding}
        self.store.write(self.plan['id'], 'recheck', legacy)
        self.tick()
        self.assertFalse(self.observer.manual_pending)
        sent = self.submit()
        self.assertEqual(sent['recovery']['service_instance'], self.observer.state['service_instance'])
        self.tick()
        self.assertTrue(self.observer.manual_pending)
        self.candidate()
        self.assertEqual(self.tick()['status'], 'observed')
        self.production_observer()
        self.tick()
        self.assertFalse(self.observer.manual_pending)
        self.assertEqual(self.observer.state['fault'], 'service_restarted')

    def test_submission_uses_install_then_store_lock(self):
        self.production_observer()
        events = []
        original = self.store.lock
        @contextmanager
        def install_lock():
            events.append('install_enter')
            yield
            events.append('install_exit')
        @contextmanager
        def store_lock():
            events.append('store_enter')
            with original():
                yield
            events.append('store_exit')
        with patch.object(identity, 'control_lock', side_effect=install_lock), \
                patch.object(self.store, 'lock', side_effect=store_lock), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(identity, 'installed_for_plan', return_value=self.installation):
            service.submit_recheck(self.plan['id'])
        self.assertEqual(events, ['install_enter', 'store_enter', 'store_exit', 'install_exit'])

    def test_changed_job_or_journal_rejected_without_request_write(self):
        self.production_observer()
        with patch.object(identity, 'control_lock', return_value=nullcontext()), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(identity, 'installed_for_plan', side_effect=[self.installation, dict(self.installation, service_pid=999999)]), \
                self.assertRaisesRegex(identity.IdentityError, 'instance_mismatch'):
            service.submit_recheck(self.plan['id'])
        self.assertFalse(self.store.path(self.plan['id'], 'recovery').exists())
        state = self.store.read(self.plan['id'], 'service')
        state['runtime_sha256'] = 'c'*64
        self.store.write(self.plan['id'], 'service', state)
        with self.assertRaisesRegex(identity.IdentityError, 'instance_mismatch'):
            self.submit()
        self.assertFalse(self.store.path(self.plan['id'], 'recovery').exists())

    def test_write_after_replace_failure_is_unknown_not_no_changes(self):
        self.production_observer()
        original = self.store.write
        def failed(plan_id, kind, value):
            original(plan_id, kind, value)
            if kind == 'recovery':
                raise OSError('private-error')
        with patch.object(self.store, 'write', side_effect=failed), \
                self.assertRaisesRegex(recovery.ReceiptError, 'recovery_receipt_write_outcome_unknown'):
            self.submit()
        self.assertEqual(self.store.read(self.plan['id'], 'recovery')['service_instance'],
                         self.observer.state['service_instance'])

    def test_rejected_control_never_publishes_daemon_failure(self):
        for error in (identity.IdentityError('stale_runtime_command'), OSError('private-error')):
            output = io.StringIO()
            with patch.object(service.os, 'geteuid', return_value=0), \
                    patch.object(service, 'submit_recheck', side_effect=error), patch.object(service, 'publish') as publish, \
                    redirect_stdout(output):
                self.assertEqual(service.main(['recheck', '--id', self.plan['id']]), 78)
            publish.assert_not_called()
            self.assertNotIn('private-error', output.getvalue())
            self.assertFalse(json.loads(output.getvalue())['launch_authorized'])

    def test_nonroot_cli_never_enters_submission(self):
        with patch.object(service.os, 'geteuid', return_value=501), patch.object(service, 'submit_recheck') as submit, \
                patch.object(service, 'publish') as publish, redirect_stdout(io.StringIO()):
            self.assertEqual(service.main(['recheck', '--id', self.plan['id']]), 78)
        submit.assert_not_called()
        publish.assert_not_called()

    def test_unverified_run_cannot_replace_live_daemon_report(self):
        for installed in (identity.IdentityError('stale_runtime_command'),
                          {'service_pid': os.getpid()+1, 'runtime_sha256': 'a'*64}):
            result = {'side_effect': installed} if isinstance(installed, Exception) else {'return_value': installed}
            root_os = Mock(wraps=os)
            root_os.geteuid.return_value = 0
            with patch.object(service, 'os', root_os), patch.object(service, 'trusted_directory'), \
                    patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                    patch.object(identity, 'installed_for_plan', **result) as verify, patch.object(service, 'publish') as publish:
                self.assertEqual(service.main(['run', '--id', self.plan['id']]), 78)
            verify.assert_called_once()
            publish.assert_not_called()


if __name__ == '__main__':
    unittest.main()
