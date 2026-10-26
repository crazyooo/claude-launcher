"""Fixed privileged entry tests with fixture files, launchd/PF and no elevation."""
from contextlib import contextmanager, redirect_stdout
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pf_control as control
import pf_runtime_identity as identity
import pf_runtime_identity_tests as identities
import pf_service as service
import pf_service_install as installer
import pf_service_install_tests as fixtures
import pf_recovery_receipt as recovery
from pf_guard import GuardError


class FixedEntryTests(unittest.TestCase):
    setUp = fixtures.InstallerTests.setUp

    def install(self):
        installer.install(self.plan['id'])
        self.manifest = installer.read_manifest()
        self.runtime = Path(self.manifest['runtime'])

    @contextmanager
    def local_control(self):
        # Only substitute root ownership for test-user files; regular file,
        # link count, mode, size, no-follow and real flock behavior stay active.
        system = SimpleNamespace(**vars(os))
        system.geteuid = lambda: 0
        system.open = Mock(wraps=os.open)
        def root_stat(fd):
            fields = list(os.fstat(fd)); fields[4] = 0
            return os.stat_result(fields)
        system.fstat = root_stat
        with patch.object(control, 'ROOT', self.root), patch.object(control, '__file__', str(self.root/'pf_control.py')), \
                patch.object(control, 'trusted_directory'), patch.object(control, 'os', system):
            yield system

    def args(self, **changes):
        values = dict(id=self.plan['id'], request_id='a'*32, expected_revision=0,
                      plan_sha256=self.manifest['plan_sha256'], runtime_sha256=identity.fingerprint(self.manifest['files']),
                      service_instance='b'*32)
        values.update(changes)
        return SimpleNamespace(**values)

    def test_exact_seven_file_snapshot_precedes_any_import(self):
        self.install()
        with self.local_control(), patch.object(control, 'VerifiedModules') as loader:
            runtime, sources = control.verified_sources(self.manifest)
        self.assertEqual(runtime, self.runtime)
        self.assertEqual(set(sources), {name[:-3] for name in identity.RECEIPT_FILES})
        self.assertEqual(sources['pf_service'], (self.runtime/'pf_service.py').read_bytes())
        loader.assert_not_called()

    def test_changed_manifest_or_entry_rejected_before_module_loading(self):
        self.install()
        invalid = [dict(version=True), dict(phase='bootstrap_pending'), dict(stop_requested=True),
                   dict(stop_pids=[123]), dict(control_version=2), dict(control_sha256='f'*64),
                   dict(runtime='/tmp/untrusted'), dict(plan_id='../x'), dict(plist_sha256='x')]
        for change in invalid:
            with self.subTest(change=change), self.local_control(), \
                    patch.object(control, 'VerifiedModules') as loader, self.assertRaises(control.ControlError):
                with control.verified_modules(dict(self.manifest, **change)):
                    self.fail('unverified import')
            loader.assert_not_called()
        for layout in (identity.LEGACY_FILES, identity.RECEIPT_FILES):
            old = dict(self.manifest, files={name: self.manifest['files'][name] for name in layout})
            old['runtime'] = str(self.root/('runtime-'+identity.fingerprint(old['files'])))
            with self.local_control(), self.assertRaisesRegex(control.ControlError, 'upgrade_required'):
                control.verified_sources(old)
        entry = self.root/'pf_control.py'
        original = entry.read_bytes(); entry.write_bytes(b'raise RuntimeError("private-secret")')
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'modified_control'):
            control.verified_sources(self.manifest)
        entry.write_bytes(original)
        with self.local_control(), patch.object(control, '__file__', '/tmp/pf_control.py'), \
                self.assertRaisesRegex(control.ControlError, 'fixed_control_entry_required'):
            control.verified_sources(self.manifest)

    def test_unknown_missing_and_modified_runtime_are_rejected(self):
        self.install()
        target = self.runtime/'pf_service.py'
        original = target.read_bytes()
        target.write_bytes(b'raise RuntimeError("must-not-execute")')
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'digest_mismatch'):
            control.verified_sources(self.manifest)
        target.rename(self.root/'saved-service.py')
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'files_incomplete'):
            control.verified_sources(self.manifest)
        target.write_bytes(original)
        (self.runtime/'evil.py').write_text('raise RuntimeError("must-not-execute")')
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'files_incomplete'):
            control.verified_sources(self.manifest)

    def test_reader_rejects_symlink_hardlink_writable_oversized_and_fifo(self):
        self.install()
        target = self.root/'test-file'; target.write_bytes(b'safe')
        with self.local_control():
            self.assertEqual(control.safe_read(target), b'safe')
            with self.assertRaisesRegex(control.ControlError, 'untrusted_control_file'):
                control.safe_read(target, limit=3)
            target.chmod(0o666)
            with self.assertRaisesRegex(control.ControlError, 'untrusted_control_file'):
                control.safe_read(target)
            target.chmod(0o644)
            os.link(target, self.root/'hardlink')
            with self.assertRaisesRegex(control.ControlError, 'untrusted_control_file'):
                control.safe_read(target)
            link = self.root/'symlink'; link.symlink_to(target)
            with self.assertRaises(OSError): control.safe_read(link)
            fifo = self.root/'fifo'; os.mkfifo(fifo)
            with self.assertRaisesRegex(control.ControlError, 'untrusted_control_file'):
                control.safe_read(fifo)

    def test_directory_ancestry_must_be_root_owned_regular_and_not_writable(self):
        path = Path('/Library/Application Support/Claude Launcher PF')
        for mode, uid in [(0o40755, 501), (0o40775, 0), (0o120777, 0)]:
            def info(component):
                return SimpleNamespace(st_uid=uid if component == path.parent else 0,
                                       st_mode=mode if component == path.parent else 0o40755)
            with patch.object(Path, 'lstat', info), self.assertRaisesRegex(control.ControlError, 'untrusted_control_directory'):
                control.trusted_directory(path)

    def test_existing_lock_busy_missing_permissions_and_dispatch_lock_order(self):
        self.install()
        path = self.root/'install.lock'
        with self.local_control(), self.assertRaises(FileNotFoundError):
            with control.installation_lock(): pass
        path.write_bytes(b''); path.chmod(0o600)
        with path.open('rb') as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.local_control(), self.assertRaisesRegex(control.ControlError, 'installation_in_progress'):
                with control.installation_lock(): pass
        path.chmod(0o644)
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'unsafe_service_lock'):
            with control.installation_lock(): pass
        path.chmod(0o600)
        events = []
        @contextmanager
        def modules(manifest):
            events.append('verified_modules')
            def submit(*args):
                with path.open('rb') as fd, self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                events.append('submit_locked')
                return {'reason': 'recheck_requested', 'launch_authorized': False}
            yield SimpleNamespace(submit_recheck_locked=submit)
        with self.local_control() as system, patch.object(control, 'verified_modules', side_effect=modules):
            result = control.execute(self.args())
            opens = [call for call in system.open.call_args_list if Path(call.args[0]) == path]
            self.assertEqual(len(opens), 1)
        self.assertEqual(events, ['verified_modules', 'submit_locked'])
        self.assertEqual(result['reason'], 'recheck_requested')
        with path.open('rb') as fd: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_preloaded_runtime_modules_rejected_without_removing_them(self):
        self.install()
        original = sys.modules['pf_service']
        with self.local_control(), self.assertRaisesRegex(control.ControlError, 'module_already_loaded'):
            with control.verified_modules(self.manifest): pass
        self.assertIs(sys.modules['pf_service'], original)

    def test_isolated_import_uses_captured_bytes_and_never_user_paths(self):
        self.install()
        # Real subprocess + production module graph. The loader reads captured
        # bytes even after a file changes; complete installation checks elsewhere
        # reject that change before any control submission.
        marker = self.root/'should-not-exist'
        (self.root/'sitecustomize.py').write_text('raise RuntimeError("site executed")')
        payload = r'''
import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('control_fixture',sys.argv[1])
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
runtime=pathlib.Path(sys.argv[2]);sources={n[:-3]:(runtime/n).read_bytes() for n in control.FILES if n!='pf_control.py'}
(runtime/'pf_service.py').write_text('raise RuntimeError("changed disk code executed")')
loader=control.VerifiedModules(runtime,sources);sys.meta_path.insert(0,loader)
import pf_service
assert pf_service.__file__==str(runtime/'pf_service.py')
assert callable(pf_service.submit_recheck_locked)
assert not any(p.name=='__pycache__' for p in runtime.iterdir())
assert '' not in sys.path and str(runtime) not in sys.path
print(json.dumps({'loaded':True,'isolated':sys.flags.isolated,'no_site':sys.flags.no_site}))
'''
        env = dict(os.environ, PYTHONPATH=str(self.root), PYTHONSTARTUP=str(marker))
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', payload,
                                 str(Path(control.__file__).absolute()), str(self.runtime)],
                                capture_output=True, text=True, cwd=self.root, env=env, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'loaded': True, 'isolated': 1, 'no_site': 1})
        self.assertFalse(marker.exists())

    def test_entry_flags_nonroot_and_invalid_arguments_never_submit(self):
        self.install()
        values = ['recheck', '--id', self.plan['id'], '--request-id', 'a'*32, '--expected-revision', '0',
                  '--plan-sha256', 'b'*64, '--runtime-sha256', 'c'*64, '--service-instance', 'd'*32]
        output = io.StringIO()
        with patch.object(control, 'execute') as execute, redirect_stdout(output):
            self.assertEqual(control.main(values), 78)  # unittest interpreter is not -I -S.
        execute.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['reason'], 'isolated_control_interpreter_required')
        output = io.StringIO()
        with redirect_stdout(output): self.assertEqual(control.main(['private-secret']), 78)
        self.assertNotIn('private-secret', output.getvalue())
        root_os = Mock(wraps=os); root_os.geteuid.return_value = 501
        with patch.object(control, 'os', root_os), patch.object(control, 'installation_lock') as lock, \
                self.assertRaisesRegex(control.ControlError, 'administrator_required'):
            control.execute(self.args())
        lock.assert_not_called()
        for change in [dict(expected_revision=True), dict(expected_revision=-1), dict(expected_revision=2**53),
                       dict(request_id='bad'), dict(plan_sha256='bad'), dict(runtime_sha256='bad'), dict(service_instance='bad')]:
            with self.local_control(), patch.object(control, 'installation_lock') as lock, \
                    self.assertRaisesRegex(control.ControlError, 'invalid_control_request'):
                control.execute(self.args(**change))
            lock.assert_not_called()

    def test_subprocess_complete_dispatch_validates_installation_then_commits_idempotently(self):
        self.install()
        (self.root/'install.lock').write_bytes(b''); (self.root/'install.lock').chmod(0o600)
        runtime_hash = identity.fingerprint(self.manifest['files'])
        self.store.write(self.plan['id'], 'service', dict(version=1, running=True,
            plan_sha256=self.manifest['plan_sha256'], service_pid=1234,
            runtime_sha256=runtime_hash, service_instance='b'*32))
        script = r'''
import importlib.util,json,os,pathlib,sys,types
spec=importlib.util.spec_from_file_location('control_fixture',sys.argv[1])
control=importlib.util.module_from_spec(spec);spec.loader.exec_module(control)
root=pathlib.Path(sys.argv[2]);plist=pathlib.Path(sys.argv[3]);journal=pathlib.Path(sys.argv[4])
manifest=json.loads((root/'installation.json').read_text());runtime=pathlib.Path(manifest['runtime'])
control.ROOT=root;control.__file__=str(root/'pf_control.py')
# Test-user ownership, launchd and PF syntax are the only external substitutes.
system=types.SimpleNamespace(**vars(os));system.geteuid=lambda:0
def root_stat(fd):
    fields=list(os.fstat(fd));fields[4]=0;return os.stat_result(fields)
system.fstat=root_stat;control.os=system
def directory(path):
    assert path in (root,runtime,plist.parent) and path.is_dir()
control.trusted_directory=directory
original=control.VerifiedModules.exec_module;checks=[]
def load(loader,module):
    original(loader,module)
    if module.__name__=='pf_runtime_identity':
        module.trusted_directory=directory
        module.safe_read.__defaults__=(os.geteuid(),65536)
        module.verify_complete.__kwdefaults__.update(root=root,plist=plist)
        module.installed_for_plan.__kwdefaults__.update(root=root,plist=plist)
        module.running_job=lambda:{'pid':1234,'path':str(plist),'program':'/usr/bin/python3','cwd':str(runtime),
            'arguments':module.definition(manifest['plan_id'],runtime)['ProgramArguments']}
        complete=module.verify_complete
        def verified(*args,**kwargs):
            value=complete(*args,**kwargs);checks.append('complete');return value
        module.verify_complete=verified
    if module.__name__=='pf_service':
        guard=sys.modules['pf_guard']
        module.Store=lambda:guard.Store(journal)
        module.PF=lambda:types.SimpleNamespace(syntax=guard.normalize)
control.VerifiedModules.exec_module=load
args=types.SimpleNamespace(id=manifest['plan_id'],request_id='a'*32,expected_revision=0,
    plan_sha256=manifest['plan_sha256'],runtime_sha256=control.fingerprint(manifest['files']),service_instance='b'*32)
first=control.execute(args);second=control.execute(args)
assert first['reason']=='recheck_requested',first
assert first==second,(first,second)
assert len(checks)==6,checks
assert not any(name[:-3] in sys.modules for name in control.FILES if name!='pf_control.py')
print(json.dumps({'reason':first['reason'],'receipt':first['recovery'],'verified_calls':len(checks)}))
'''
        result = subprocess.run(['/usr/bin/python3', '-I', '-S', '-B', '-c', script,
                                 str(Path(control.__file__).absolute()), str(self.root), str(self.plist), str(self.store.directory)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertEqual(value['verified_calls'], 6)
        saved = self.store.read(self.plan['id'], 'recovery')
        self.assertEqual(saved, value['receipt']); self.assertEqual(saved['revision'], 1)
        self.assertEqual(self.pf.mutations, self.initial_mutations)

    def test_dispatch_cleanup_failure_reports_unknown_with_same_retry_identity(self):
        self.install()
        (self.root/'install.lock').write_bytes(b''); (self.root/'install.lock').chmod(0o600)
        flags = SimpleNamespace(isolated=1, no_site=1, dont_write_bytecode=1)
        values = ['recheck', '--id', self.plan['id'], '--request-id', 'a'*32, '--expected-revision', '0',
                  '--plan-sha256', 'b'*64, '--runtime-sha256', 'c'*64, '--service-instance', 'd'*32]
        performed = []
        @contextmanager
        def modules(manifest):
            def submit(*args):
                performed.append(args)
                return {'reason': 'recheck_requested', 'launch_authorized': False}
            yield SimpleNamespace(submit_recheck_locked=submit)
            raise OSError('private-after-submit')
        output = io.StringIO()
        with self.local_control(), patch.object(control.sys, 'flags', flags), \
                patch.object(control, 'verified_modules', side_effect=modules), redirect_stdout(output):
            self.assertEqual(control.main(values), 78)
        self.assertEqual(len(performed), 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result['reason'], 'control_outcome_unknown')
        self.assertEqual(result['request_id'], 'a'*32); self.assertEqual(result['expected_revision'], 0)
        self.assertNotIn('private-after-submit', output.getvalue())


class AuthorizationBindingTests(unittest.TestCase):
    setUp = identities.ControlTests.setUp
    production_observer = identities.ControlTests.production_observer
    tick = identities.ControlTests.tick
    candidate = identities.ControlTests.candidate
    submit = identities.ControlTests.submit

    def test_changed_authorization_binding_never_writes_receipt_or_public_status(self):
        self.production_observer()
        binding = self.observer.recovery_binding()
        before = self.store.read(self.plan['id'], 'service')
        for key in binding:
            changed = dict(binding, **{key: '9' * len(binding[key])})
            with self.assertRaisesRegex(identity.IdentityError, 'authorization_context_changed'):
                self.submit(request_id='e'*32, expected_revision=0, expected_binding=changed)
            self.assertFalse(self.store.path(self.plan['id'], 'recovery').exists())
            self.assertEqual(self.store.read(self.plan['id'], 'service'), before)
        self.assertEqual(self.messages, [])

    def test_authorized_idempotent_retry_keeps_original_revision_through_terminal(self):
        self.production_observer()
        args = dict(request_id='e'*32, expected_revision=0, expected_binding=self.observer.recovery_binding())
        received = self.submit(**args)['recovery']
        self.assertEqual(self.submit(**args)['recovery'], received)
        self.tick()
        checking = self.submit(**args)['recovery']; self.assertEqual(checking['status'], 'checking')
        self.candidate()
        terminal = self.tick()['recovery']; self.assertEqual(terminal['status'], 'passed')
        self.assertEqual(self.submit(**args)['recovery'], terminal)
        with self.assertRaisesRegex(recovery.ReceiptError, 'revision_conflict'):
            self.submit(**dict(args, request_id='f'*32))
        self.production_observer()
        with self.assertRaisesRegex(identity.IdentityError, 'authorization_context_changed'):
            self.submit(**args)

    def test_context_snapshot_tracks_receipt_and_is_not_launch_permission(self):
        self.production_observer()
        first = self.tick()
        context = first['control_context']
        self.assertEqual(context, dict(self.observer.recovery_binding(), version=1, receipt_revision=0))
        self.submit()
        checking = self.tick()
        self.assertEqual(checking['control_context']['receipt_revision'], checking['recovery']['revision'])
        self.candidate()
        done = self.tick()
        self.assertEqual(done['control_context']['receipt_revision'], done['recovery']['revision'])
        self.assertFalse(done['launch_authorized']); self.assertFalse(done['protection_verified'])
        self.observer.closed = True
        self.assertIsNone(self.observer.public_control_context())
        self.observer.closed = False; self.observer.installation = None
        self.assertIsNone(self.observer.public_control_context())

    def test_store_lock_cleanup_failure_after_commit_keeps_generated_retry_identity(self):
        self.production_observer()
        original = service.startup_lock
        @contextmanager
        def failed_cleanup(store):
            with original(store): yield
            raise OSError('private-after-commit')
        with patch.object(service, 'startup_lock', side_effect=failed_cleanup), self.assertRaises(OSError) as caught:
            self.submit(expected_binding=self.observer.recovery_binding())
        saved = self.store.read(self.plan['id'], 'recovery')
        result = service.recheck_failure(caught.exception)
        self.assertEqual(result['reason'], 'recheck_outcome_unknown')
        self.assertEqual(result['request_id'], saved['request_id']); self.assertEqual(result['expected_revision'], 0)
        self.assertEqual(self.submit(request_id=result['request_id'], expected_revision=0)['recovery'], saved)
        self.assertNotIn('private-after-commit', json.dumps(result))

    def test_install_lock_cleanup_after_commit_keeps_generated_retry_identity(self):
        self.production_observer()
        @contextmanager
        def failed_cleanup():
            yield
            raise OSError('private-after-commit')
        with patch.object(identity, 'control_lock', side_effect=failed_cleanup), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(identity, 'installed_for_plan', return_value=self.installation), self.assertRaises(OSError) as caught:
            service.submit_recheck(self.plan['id'])
        saved = self.store.read(self.plan['id'], 'recovery')
        result = service.recheck_failure(caught.exception)
        self.assertEqual(result['reason'], 'recheck_outcome_unknown')
        self.assertEqual(result['request_id'], saved['request_id']); self.assertEqual(result['expected_revision'], 0)
        self.assertEqual(self.submit(request_id=result['request_id'], expected_revision=0)['recovery'], saved)

    def test_both_lock_cleanups_fail_without_losing_generated_request_identity(self):
        self.production_observer()
        original = service.startup_lock
        @contextmanager
        def store_cleanup(store):
            try:
                with original(store): yield
            finally:
                raise OSError('inner cleanup')
        @contextmanager
        def install_cleanup():
            try: yield
            finally: raise OSError('outer cleanup')
        with patch.object(identity, 'control_lock', side_effect=install_cleanup), \
                patch.object(service, 'startup_lock', side_effect=store_cleanup), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(identity, 'installed_for_plan', return_value=self.installation), self.assertRaises(OSError) as caught:
            service.submit_recheck(self.plan['id'])
        saved = self.store.read(self.plan['id'], 'recovery')
        result = service.recheck_failure(caught.exception)
        self.assertEqual(result['reason'], 'recheck_outcome_unknown')
        self.assertEqual(result['request_id'], saved['request_id']); self.assertEqual(result['expected_revision'], 0)
        self.assertEqual(self.submit(request_id=result['request_id'], expected_revision=0)['recovery'], saved)


class FixedControlInstallTests(unittest.TestCase):
    setUp = fixtures.InstallerTests.setUp
    install = fixtures.InstallerTests.install
    loaded = fixtures.InstallerTests.loaded

    def test_six_file_install_migrates_preserving_old_runtime_and_pf(self):
        content = {name: data for name, data in installer.package().items() if name in identity.RECEIPT_FILES}
        with patch.object(installer, 'FILES', identity.RECEIPT_FILES), patch.object(installer, 'package', return_value=content):
            self.install()
        old = installer.read_manifest()
        old_bytes = {name: (Path(old['runtime'])/name).read_bytes() for name in old['files']}
        self.assertNotIn('control_sha256', old)
        self.assertFalse((self.root/'pf_control.py').exists())
        result = self.install()
        current = installer.read_manifest()
        self.assertEqual(current['control_version'], 1)
        self.assertEqual(current['control_sha256'], current['files']['pf_control.py'])
        self.assertEqual((self.root/'pf_control.py').read_bytes(), (Path(current['runtime'])/'pf_control.py').read_bytes())
        self.assertEqual(result['control_entry'], str(self.root/'pf_control.py'))
        self.assertEqual(old_bytes, {name: (Path(old['runtime'])/name).read_bytes() for name in old['files']})
        self.assertEqual(self.pf.mutations, self.initial_mutations)

    def test_unowned_modified_or_linked_entry_is_preserved_before_stopping_job(self):
        entry = self.root/'pf_control.py'
        entry.write_bytes(b'foreign')
        with self.assertRaisesRegex(GuardError, 'unowned_control'):
            self.install()
        installer.stop_job.assert_not_called()
        entry.rename(self.root/'saved-foreign.py')
        self.install()
        original = entry.read_bytes(); entry.write_bytes(b'changed')
        installer.stop_job.reset_mock()
        for action in (self.install, installer.uninstall):
            with self.assertRaisesRegex(GuardError, 'modified_control'):
                action()
        installer.stop_job.assert_not_called()
        entry.write_bytes(original); entry.rename(self.root/'saved-control.py')
        entry.symlink_to(self.root/'saved-control.py')
        for action in (self.install, installer.uninstall):
            with self.assertRaises(OSError): action()
        installer.stop_job.assert_not_called()

    def test_same_install_preserves_job_and_missing_owned_entry_is_repaired(self):
        self.install()
        manifest = installer.MANIFEST.read_bytes()
        installer.stop_job.reset_mock(); self.calls.clear()
        with patch.object(installer, 'job_snapshot', return_value=self.loaded()):
            result = self.install()
        self.assertEqual(result['reason'], 'observer_already_loaded_state_preserved')
        installer.stop_job.assert_not_called(); self.assertEqual(self.calls, [])
        self.assertEqual(installer.MANIFEST.read_bytes(), manifest)
        entry = self.root/'pf_control.py'; saved = entry.read_bytes()
        entry.rename(self.root/'saved-entry.py')
        self.install()
        self.assertEqual(entry.read_bytes(), saved)
        self.assertEqual(self.pf.mutations, self.initial_mutations)

    def test_previous_entry_digest_is_accepted_only_during_install_pending(self):
        self.install()
        manifest = installer.read_manifest()
        entry = self.root/'pf_control.py'
        entry.write_bytes(b'previous owned entry')
        manifest['previous_control_sha256'] = installer.sha(entry.read_bytes())
        manifest['phase'] = 'install_pending'
        installer.verify_files(manifest)
        for phase in ('bootstrap_pending', 'installed', 'uninstalled'):
            manifest['phase'] = phase
            with self.assertRaisesRegex(GuardError, 'modified_control'):
                installer.verify_files(manifest)

    def test_uninstall_archives_fixed_entry_but_retains_runtime_for_restore(self):
        self.install()
        manifest = installer.read_manifest()
        source = (self.root/'pf_control.py').read_bytes()
        installer.uninstall()
        self.assertFalse((self.root/'pf_control.py').exists())
        archives = list(self.root.glob('archived-control-*.py'))
        self.assertEqual(len(archives), 1); self.assertEqual(archives[0].read_bytes(), source)
        self.assertEqual((Path(manifest['runtime'])/'pf_control.py').read_bytes(), source)
        self.assertTrue((Path(manifest['runtime'])/'pf_guard.py').exists())
        self.assertEqual(installer.read_manifest()['phase'], 'uninstalled')
        self.assertEqual(self.pf.mutations, self.initial_mutations)
        installer.uninstall()  # A repeated uninstall does not need the archived entry.

    def test_uninstall_retries_after_entry_was_archived(self):
        self.install()
        original = os.rename
        def interrupt(source, target):
            original(source, target)
            if Path(source) == self.root/'pf_control.py':
                raise OSError('after control archive')
        with patch.object(installer.os, 'rename', side_effect=interrupt), self.assertRaises(OSError):
            installer.uninstall()
        installer.uninstall()
        self.assertEqual(installer.read_manifest()['phase'], 'uninstalled')
        self.assertEqual(len(list(self.root.glob('archived-control-*.py'))), 1)


class FixedControlUpgradeInterruptionTests(unittest.TestCase):
    def test_upgrade_recovers_each_durable_boundary_without_pf_changes(self):
        for stage in ('pending_manifest', 'runtime_control', 'control_archive', 'control_before',
                      'control_after', 'plist_after', 'bootstrap_manifest', 'installed_manifest'):
            with self.subTest(stage=stage):
                case = fixtures.InstallerTests(); case.setUp()
                try:
                    case.install()
                    entry = case.root/'pf_control.py'; old = entry.read_bytes()
                    old_runtime = Path(installer.read_manifest()['runtime'])
                    content = installer.package(); content['pf_control.py'] += b'\n# newer fixture\n'
                    atomic, rename = installer.atomic, os.rename
                    hit = []
                    def interrupt_atomic(path, data, mode=0o600, **kwargs):
                        if stage == 'control_before' and path == entry:
                            hit.append(stage); raise OSError('before write')
                        atomic(path, data, mode, **kwargs)
                        selected = ((stage == 'runtime_control' and path.name == 'pf_control.py' and path != entry) or
                                    (stage == 'control_after' and path == entry) or
                                    (stage == 'plist_after' and path == case.plist))
                        if path == installer.MANIFEST:
                            phase = json.loads(data)['phase']
                            selected = selected or (stage, phase) in {
                                ('pending_manifest', 'install_pending'), ('bootstrap_manifest', 'bootstrap_pending'),
                                ('installed_manifest', 'installed')}
                        if selected:
                            hit.append(stage); raise OSError('after write')
                    def interrupt_rename(source, target):
                        rename(source, target)
                        if stage == 'control_archive' and Path(source) == entry:
                            hit.append(stage); raise OSError('after archive')
                    with patch.object(installer, 'package', return_value=content):
                        with patch.object(installer, 'atomic', side_effect=interrupt_atomic), \
                                patch.object(installer.os, 'rename', side_effect=interrupt_rename), self.assertRaises(OSError):
                            case.install()
                        self.assertEqual(hit, [stage])
                        installer.verify_files(installer.read_manifest())
                        case.install()
                    final = installer.read_manifest()
                    self.assertEqual(final['phase'], 'installed')
                    self.assertEqual(entry.read_bytes(), content['pf_control.py'])
                    self.assertEqual((old_runtime/'pf_control.py').read_bytes(), old)
                    self.assertIn(old, [p.read_bytes() for p in case.root.glob('archived-control-*.py')])
                    self.assertEqual(case.pf.mutations, case.initial_mutations)
                finally:
                    case.doCleanups()
if __name__ == '__main__':
    unittest.main()
