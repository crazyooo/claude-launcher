#!/usr/bin/env python3
"""Isolated retirement tests. No installed paths, launchctl, PF or network calls."""
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import subprocess
import stat
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('retirement', Path(__file__).with_name('retire_legacy.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def write(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value if isinstance(value, bytes) else m.encoded(value))
    path.chmod(mode)


class FakeConnector:
    def __init__(self):
        self.loaded = None
        self.calls = []
        self.fail = False
        self.before_stop = lambda: None

    def ownership(self):
        if self.fail:raise RuntimeError('fixture-ownership-private')
        return {}

    def job(self):
        return self.loaded

    def operate(self, action):
        self.before_stop()
        self.calls.append(action)
        if self.fail:raise RuntimeError('fixture-failure-private')
        self.loaded = None


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.home = self.base / 'home'
        self.connector = FakeConnector()
        self.calls = []
        self.tool = m.Retirement(home=self.home, pf_root=self.base/'pf', pf_store=self.base/'store',
                                 launchdaemons=self.base/'daemons', root_uid=os.getuid(),
                                 connector=self.connector, runner=self.runner,
                                 process_gone=lambda pid: True, environment={})
        self.tool.root.mkdir(parents=True, mode=0o700)
        self.manifest = {'installed': True, 'mode': 'preflight', 'integration': False,
                         'vscodeIntegration': True, 'scripts': {}}
        for name in ('claude-safe', 'claude-vscode-preflight'):
            data = ('#!/bin/sh\n# owned-' + name + '\n').encode()
            write(self.tool.bin/name, data, 0o700)
            self.manifest['scripts'][name] = m.digest(data)
        write(self.tool.manifest, self.manifest)
        self.code = self.home/'Library/Application Support/Code/User/settings.json'
        write(self.code, {'theme':'keep', 'claudeCode.claudeProcessWrapper':str(self.tool.bin/'claude-vscode-preflight')})
        write(self.tool.app/'Contents/keep', b'application-sentinel')
        write(self.home/'.local/bin/claude', b'native-sentinel')

    def tearDown(self):
        self.temp.cleanup()

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[-2:] == ['connector', 'status']:
            return subprocess.CompletedProcess(argv, 0, b'{"port":18761}', b'')
        self.fail('unexpected subprocess; real commands prohibited: ' + argv[0])

    def plan(self):
        return self.tool.user_plan()[0]

    def test_plan_is_read_only_and_apply_detaches_before_archiving(self):
        before = {str(p.relative_to(self.base)):p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        plan = self.plan()
        self.assertFalse(plan['blockers'])
        after = {str(p.relative_to(self.base)):p.read_bytes() for p in self.base.rglob('*') if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(self.tool.apply_user(plan['fingerprint'])['status'], 'complete')
        self.assertEqual(json.loads(self.code.read_bytes()), {'theme':'keep'})
        self.assertEqual((self.tool.app/'Contents/keep').read_bytes(), b'application-sentinel')
        self.assertEqual((self.home/'.local/bin/claude').read_bytes(), b'native-sentinel')
        self.assertFalse((self.tool.bin/'claude-safe').exists())
        self.assertTrue(list((self.tool.root/'retired').rglob('claude-safe.*')))
        self.assertEqual(self.plan()['status'], 'not_needed')
        self.assertEqual(self.calls, [])

    def test_settings_undo_never_copies_other_fields(self):
        settings = json.loads(self.code.read_bytes())
        settings['apiKey'] = 'secret-sentinel-never-archive'
        write(self.code, settings)
        self.tool.apply_user(self.plan()['fingerprint'])
        self.assertEqual(json.loads(self.code.read_bytes())['apiKey'], settings['apiKey'])
        archive_files = [p for p in (self.tool.root/'retired').rglob('*') if p.is_file()]
        self.assertTrue(any(p.name.endswith('.field-undo.json') for p in archive_files))
        self.assertFalse(any(b'secret-sentinel-never-archive' in p.read_bytes() for p in archive_files))
        undo = json.loads(next(p for p in archive_files if p.name.endswith('.field-undo.json')).read_bytes())
        self.assertEqual(undo['field'], 'claudeCode.claudeProcessWrapper')
        self.assertEqual(undo['removed_value'], str(self.tool.bin/'claude-vscode-preflight'))

    def test_uninstalled_manifest_does_not_bypass_stale_dependencies(self):
        self.manifest.update(installed=False, vscodeIntegration=False)
        write(self.tool.manifest, self.manifest)
        self.assertTrue(self.plan()['blockers'])

    def test_archive_symlink_directory_is_preserved(self):
        outside = self.base/'outside'; outside.mkdir()
        (self.tool.root/'retired').symlink_to(outside, target_is_directory=True)
        before = self.code.read_bytes()
        with self.assertRaisesRegex(m.RetirementError, 'symlink_directory_preserved'):
            self.tool.apply_user(self.plan()['fingerprint'])
        self.assertEqual(self.code.read_bytes(), before)
        self.assertEqual(list(outside.iterdir()), [])

    def test_modified_wrapper_or_field_keeps_all_files(self):
        for kind in ('wrapper', 'field', 'jsonc'):
            with self.subTest(kind=kind):
                original = self.code.read_bytes()
                wrapper = self.tool.bin/'claude-vscode-preflight'
                script = wrapper.read_bytes()
                if kind == 'wrapper':write(wrapper, b'user-custom-script')
                elif kind == 'field':write(self.code, {'claudeCode.claudeProcessWrapper':str(wrapper)+' --custom'})
                else:write(self.code, b'{// retain comments\n"theme":"keep"}')
                plan = self.plan()
                self.assertTrue(plan['blockers'])
                with self.assertRaises(m.RetirementError):self.tool.apply_user(plan['fingerprint'])
                self.assertTrue(wrapper.exists())
                write(self.code, original); write(wrapper, script, 0o700)

    def test_same_field_without_manifest_ownership_is_preserved(self):
        self.manifest['vscodeIntegration'] = False
        write(self.tool.manifest, self.manifest)
        self.assertTrue(self.plan()['blockers'])

    def test_changed_plan_rejected_before_writes(self):
        plan = self.plan()
        write(self.code, {'theme':'new', 'claudeCode.claudeProcessWrapper':str(self.tool.bin/'claude-vscode-preflight')})
        before = self.code.read_bytes()
        with self.assertRaisesRegex(m.RetirementError, 'plan_changed'):self.tool.apply_user(plan['fingerprint'])
        self.assertEqual(self.code.read_bytes(), before)

    def test_manifest_path_traversal_rejected(self):
        self.manifest['scripts']['../../escape'] = 'a'*64
        write(self.tool.manifest, self.manifest)
        with self.assertRaisesRegex(m.RetirementError, 'unknown_script'):self.plan()

    def test_dangling_configuration_and_wrapper_are_preserved(self):
        self.code.rename(self.code.with_suffix('.backup'))
        self.code.symlink_to(self.base/'missing')
        with self.assertRaises(m.RetirementError):self.plan()
        self.assertTrue(self.code.is_symlink())

    def test_dangling_settings_parent_and_profile_directory_are_unknown(self):
        directory = self.home/'.claude'
        directory.symlink_to(self.base/'missing-claude', target_is_directory=True)
        with self.assertRaisesRegex(m.RetirementError, 'symlink_path_preserved'):self.plan()
        directory.rename(self.home/'saved-link')
        profiles = self.home/'Library/Application Support/Code/User/profiles'
        profiles.symlink_to(self.base/'missing-profiles', target_is_directory=True)
        with self.assertRaisesRegex(m.RetirementError, 'profile_directory_untrusted'):self.plan()

    def test_connector_references_block_stop(self):
        write(self.tool.root/'connector-installation.json', {'version':1})
        write(self.tool.root/'connector.json', {'listenPort':18761,'upstreamPort':1082})
        write(self.home/'.claude/settings.local.json', {'env':{'HTTPS_PROXY':'http://127.0.0.1:18761'}})
        plan = self.plan()
        self.assertTrue(any(item.startswith('gateway_reference:') for item in plan['blockers']))
        with self.assertRaises(m.RetirementError):self.tool.apply_user(plan['fingerprint'])
        self.assertEqual(self.connector.calls, [])

    def test_connector_environment_reference_blocks_stop(self):
        write(self.tool.root/'connector-installation.json', {'version':1})
        write(self.tool.root/'connector.json', {'listenPort':18761,'upstreamPort':1082})
        self.tool.environment['HTTPS_PROXY'] = 'http://private:secret@127.0.0.1:18761'
        plan = self.plan()
        self.assertIn('gateway_reference:process_environment', plan['blockers'])
        self.assertNotIn('secret', json.dumps(plan))

    def test_connector_is_stopped_after_detach_and_before_scripts_move(self):
        write(self.tool.root/'connector-installation.json', {'version':1})
        write(self.tool.root/'connector.json', {'listenPort':18761,'upstreamPort':1082})
        def inspect():
            self.assertNotIn('claudeCode.claudeProcessWrapper', json.loads(self.code.read_bytes()))
            self.assertTrue((self.tool.bin/'claude-safe').exists())
        self.connector.before_stop = inspect
        self.tool.apply_user(self.plan()['fingerprint'])
        self.assertEqual(self.connector.calls, ['uninstall'])
        self.assertFalse((self.tool.root/'connector-installation.json').exists())
        self.assertEqual(self.plan()['status'], 'not_needed')

    def test_partial_connector_failure_preserves_dependencies_and_retries(self):
        write(self.tool.root/'connector-installation.json', {'version':1})
        write(self.tool.root/'connector.json', {'listenPort':18761,'upstreamPort':1082})
        original = self.connector.operate
        self.connector.operate = lambda action: (_ for _ in ()).throw(RuntimeError('private secret'))
        with self.assertRaisesRegex(m.RetirementError, 'connector_retirement_incomplete'):
            self.tool.apply_user(self.plan()['fingerprint'])
        self.assertTrue((self.tool.bin/'claude-safe').exists())
        self.assertNotIn('claudeCode.claudeProcessWrapper', json.loads(self.code.read_bytes()))
        self.connector.operate = original
        self.assertEqual(self.tool.apply_user(self.plan()['fingerprint'])['status'], 'complete')

    def test_concurrent_settings_change_is_not_overwritten(self):
        plan = self.plan()
        original = m.atomic
        def altered(path, data, **kw):
            if path == self.code:
                write(path, {'user':'concurrent'})
            return original(path, data, **kw)
        with patch.object(m, 'atomic', side_effect=altered):
            with self.assertRaisesRegex(m.RetirementError, 'file_changed'):
                self.tool.apply_user(plan['fingerprint'])
        self.assertEqual(json.loads(self.code.read_bytes()), {'user':'concurrent'})
        self.assertTrue((self.tool.bin/'claude-safe').exists())


class RootRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.calls = []; self.loaded = True; self.restore_failure = False
        self.tool = m.Retirement(home=self.base/'home', pf_root=self.base/'pf', pf_store=self.base/'store',
            launchdaemons=self.base/'daemons', root_uid=os.getuid(), runner=self.runner,
            process_gone=lambda pid: True, environment={})
        # A fixture tree cannot make its real /tmp ancestors root-private; test trust
        # checks within this isolated tree without weakening the production method.
        self.tool.trusted_directory = lambda path: m.require(path.resolve() == path.absolute() and path.is_dir(), 'fixture_untrusted_directory')
        files = {name:m.digest(('fixture '+name).encode()) for name in m.PF_FILES}
        self.runtime = self.tool.pf_root / ('runtime-'+m.fingerprint(files))
        for name in files:write(self.runtime/name, ('fixture '+name).encode(), 0o644)
        write(self.tool.pf_root/'pf_control.py', b'fixture pf_control.py',0o644)
        self.plan_id = 'a'*32
        plan = {'version':1,'id':self.plan_id,'fixture':True,'root_before':'anchor "com.apple/*" all'}
        write(self.tool.pf_store/(self.plan_id+'.plan'), plan)
        self.state = self.tool.pf_store/(self.plan_id+'.state')
        write(self.state, {'plan_sha256':m.fingerprint(plan),'phase':'installed_unverified'})
        self.argv = ['/usr/bin/python3','-E','-s','-B',str(self.runtime/'pf_service.py'),'run','--id',self.plan_id]
        self.plist = self.tool.daemons/(m.PF_LABEL+'.plist')
        raw = plistlib.dumps({'Label':m.PF_LABEL,'ProgramArguments':self.argv,'WorkingDirectory':str(self.runtime)})
        write(self.plist, raw, 0o644)
        self.manifest = {'version':1,'plan_id':self.plan_id,'plan_sha256':m.fingerprint(plan),
                         'runtime':str(self.runtime),'files':files,'phase':'installed','plist_sha256':m.digest(raw)}
        write(self.tool.pf_root/'installation.json',self.manifest,0o644)

    def tearDown(self):self.temp.cleanup()

    def runner(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:2] == ['/bin/launchctl','print']:
            if not self.loaded:
                return subprocess.CompletedProcess(argv,113,b'',('Could not find service "'+m.PF_LABEL+'" in domain for system\n').encode())
            raw = 'system/'+m.PF_LABEL+' = {\n'
            raw += '\tpath = '+str(self.plist)+'\n\tprogram = /usr/bin/python3\n\tworking directory = '+str(self.runtime)+'\n'
            raw += '\tstate = running\n\tactive count = 1\n\tpid = 4242\n\targuments = {\n'
            raw += ''.join('\t\t'+item+'\n' for item in self.argv)+'\t}\n}\n'
            return subprocess.CompletedProcess(argv,0,raw.encode(),b'')
        if argv[:2] == ['/bin/launchctl','bootout']:
            self.loaded = False
            return subprocess.CompletedProcess(argv,0,b'',b'')
        if argv[:4] == ['/usr/bin/python3','-E','-s','-B']:
            self.assertFalse(self.loaded)
            self.assertEqual(argv[4:], [str(self.runtime/'pf_guard.py'),'restore','--id',self.plan_id])
            if self.restore_failure:return subprocess.CompletedProcess(argv,78,b'{"reason":"fixture"}',b'')
            value = json.loads(self.state.read_bytes());value['phase'] = 'restored';write(self.state,value)
            return subprocess.CompletedProcess(argv,0,b'{"reason":"owned_rules_restored_states_cannot_be_recreated"}',b'')
        if argv == ['/sbin/pfctl','-s','rules']:
            return subprocess.CompletedProcess(argv,0,b'anchor "com.apple/*" all\n',b'')
        if argv == ['/sbin/pfctl','-a','clguard_'+self.plan_id,'-s','rules']:
            return subprocess.CompletedProcess(argv,0,b'',b'')
        self.fail('unexpected root command')

    def test_verified_runtime_only_and_stops_observer_before_restore(self):
        plan = self.tool.root_plan()[0]
        self.assertTrue(all(argv[1] == 'print' for argv in self.calls))
        result = self.tool.apply_root(plan['fingerprint'])
        self.assertEqual(result['status'],'complete')
        actions = [argv[1] for argv in self.calls]
        self.assertLess(actions.index('bootout'), actions.index('-E'))
        self.assertFalse(self.plist.exists())
        self.assertTrue(list((self.tool.pf_root/'retired').glob('*.plist.*')))
        self.assertTrue((self.runtime/'pf_guard.py').exists())
        self.assertFalse(any('-d' in argv or '-F' in argv for argv in self.calls))

    def test_modified_runtime_blocks_before_bootout(self):
        write(self.runtime/'pf_guard.py', b'untrusted edit',0o644)
        with self.assertRaisesRegex(m.RetirementError,'runtime_digest_changed'):self.tool.root_plan()
        self.assertEqual(self.calls,[])

    def test_wrong_plan_digest_blocks_before_bootout(self):
        write(self.tool.pf_store/(self.plan_id+'.plan'), {'id':self.plan_id,'changed':True})
        with self.assertRaisesRegex(m.RetirementError,'root_plan_changed'):self.tool.root_plan()
        self.assertEqual(self.calls,[])

    def test_foreign_loaded_service_is_preserved(self):
        self.argv[-1] = 'f'*32
        with self.assertRaisesRegex(m.RetirementError,'observer_identity_mismatch'):self.tool.root_plan()
        self.assertFalse(any(argv[1] == 'bootout' for argv in self.calls))

    def test_restore_failure_is_partial_and_can_retry(self):
        self.restore_failure = True
        with self.assertRaisesRegex(m.RetirementError,'owned_pf_restore_incomplete'):
            self.tool.apply_root(self.tool.root_plan()[0]['fingerprint'])
        self.assertFalse(self.loaded);self.assertFalse(self.plist.exists())
        self.assertEqual(json.loads(self.state.read_bytes())['phase'],'installed_unverified')
        self.restore_failure = False
        result = self.tool.apply_root(self.tool.root_plan()[0]['fingerprint'])
        self.assertEqual(result['status'],'complete')
        self.assertEqual(sum(argv[1] == 'bootout' for argv in self.calls),1)

    def test_old_pending_observer_prevents_restore_until_gone(self):
        self.manifest.update(stop_requested=True, stop_pids=[5151])
        write(self.tool.pf_root/'installation.json', self.manifest, 0o644)
        self.tool.process_gone = lambda pid: pid != 5151
        plan = self.tool.root_plan()[0]
        with patch.object(m.time, 'monotonic', side_effect=[0, 20]):
            with self.assertRaisesRegex(m.RetirementError, 'observer_stop_pending'):
                self.tool.apply_root(plan['fingerprint'])
        self.assertFalse(any(argv[0] == '/usr/bin/python3' for argv in self.calls))
        self.assertTrue(self.plist.exists())
        self.tool.process_gone = lambda pid: True
        self.assertEqual(self.tool.apply_root(self.tool.root_plan()[0]['fingerprint'])['status'], 'complete')
        self.assertEqual(json.loads((self.tool.pf_root/'installation.json').read_bytes())['stop_pids'], [])

    def test_retry_records_attestation_after_restore_already_completed(self):
        self.tool.apply_root(self.tool.root_plan()[0]['fingerprint'])
        journal = self.tool.pf_root/'retirement-status.json'
        write(journal, {'version':1,'status':'partial','pending_pids':[], 'plan_id':self.plan_id}, 0o644)
        commands_before = len(self.calls)
        result = self.tool.apply_root(self.tool.root_plan()[0]['fingerprint'])
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(self.tool.recorded_root_status()['evidence'], 'administrator_record')
        self.assertFalse(any(argv[0] == '/usr/bin/python3' for argv in self.calls[commands_before:]))


class DirectoryTrustTests(unittest.TestCase):
    def test_only_exact_system_run_exception_and_private_store(self):
        tool = m.Retirement()
        def info(path):
            mode = 0o700 if path == tool.pf_store else 0o775 if str(path) == '/private/var/run' else 0o755
            return SimpleNamespace(st_mode=stat.S_IFDIR|mode, st_uid=0, st_gid=1 if str(path)=='/private/var/run' else 0)
        with patch.object(Path, 'lstat', autospec=True, side_effect=info):
            tool.trusted_directory(tool.pf_store)
        for change in ('gid', 'store', 'ancestor'):
            def altered(path):
                result = info(path)
                if change == 'gid' and str(path) == '/private/var/run':result.st_gid = 20
                if change == 'store' and path == tool.pf_store:result.st_mode = stat.S_IFDIR|0o755
                if change == 'ancestor' and str(path) == '/private/var':result.st_mode = stat.S_IFDIR|0o775
                return result
            with self.subTest(change=change), patch.object(Path, 'lstat', autospec=True, side_effect=altered):
                with self.assertRaises(m.RetirementError):tool.trusted_directory(tool.pf_store)


class LockCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name).resolve()
        self.tool = m.Retirement(home=self.base/'home', pf_root=self.base/'pf', root_uid=os.getuid())
        self.path = self.tool.root/'installation.lock'
        write(self.path, b'', 0o644)
        self.tool.root.chmod(0o700)

    def tearDown(self):self.temp.cleanup()

    def test_legacy_user_0644_lock_is_accepted_without_changing_mode(self):
        with self.tool.lock('user'):pass
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o644)

    def test_other_user_lock_modes_are_rejected(self):
        for mode in (0o664, 0o666, 0o640, 0o700):
            with self.subTest(mode=oct(mode)):
                self.path.chmod(mode)
                with self.assertRaisesRegex(m.RetirementError, 'untrusted_lock'):
                    with self.tool.lock('user'):self.fail('untrusted lock acquired')

    def test_foreign_user_lock_is_rejected(self):
        original = m.os.fstat
        def foreign(fd):
            info = original(fd)
            return SimpleNamespace(st_mode=info.st_mode, st_uid=info.st_uid+1, st_nlink=info.st_nlink)
        with patch.object(m.os, 'fstat', side_effect=foreign):
            with self.assertRaisesRegex(m.RetirementError, 'untrusted_lock'):
                with self.tool.lock('user'):self.fail('foreign lock acquired')

    def test_hardlinked_user_lock_is_rejected(self):
        os.link(self.path, self.base/'extra-link')
        with self.assertRaisesRegex(m.RetirementError, 'untrusted_lock'):
            with self.tool.lock('user'):self.fail('hardlinked lock acquired')

    def test_symbolic_user_lock_is_rejected(self):
        target = self.path.with_name('original-lock')
        self.path.rename(target)
        self.path.symlink_to(target)
        with self.assertRaises(OSError):
            with self.tool.lock('user'):self.fail('symbolic lock acquired')

    def test_root_0644_lock_remains_rejected(self):
        path = self.tool.pf_root/'install.lock'
        write(path, b'', 0o644)
        with self.assertRaisesRegex(m.RetirementError, 'untrusted_lock'):
            with self.tool.lock('root'):self.fail('root 0644 lock acquired')
        path.chmod(0o600)
        with self.tool.lock('root'):pass


if __name__ == '__main__':unittest.main()
