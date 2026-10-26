"""Offline security/migration regression tests; never run PF or sudo."""
import contextlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import install_sudoers_nopasswd as installer
import claude_protect_privileged as secure


class BoundaryTests(unittest.TestCase):
    def test_sudoers_only_exact_status_commands(self):
        with mock.patch.object(installer.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=501)):
            body = installer.sudoers_body('testuser')
        self.assertEqual(body.splitlines()[1],
                         f'testuser ALL=(root) NOPASSWD: {secure.ENTRY} status')
        self.assertNotIn('*', body)
        self.assertNotIn('/usr/local/', body)

    def test_user_injection_rejected(self):
        for user in ['root\nALL ALL=(ALL) NOPASSWD: ALL', 'x,y', 'x ALL', 'x:1', '-x']:
            with self.assertRaises(ValueError):
                installer.sudoers_body(user)

    def test_allowlist_rejects_extra_arguments_and_general_script_operations(self):
        for args in [[], ['status', 'enable'], ['status', '--journal-dir', '/tmp/x'],
                     ['generate', '--output', '/etc/sudoers'], ['hook', 'restore'],
                     ['apply'], ['unload'], ['unload', '--i-confirm-unload', 'extra']]:
            self.assertFalse(secure.allowed_arguments(args), args)
        self.assertTrue(secure.allowed_arguments(['status']))
        self.assertTrue(secure.allowed_arguments(['hook-status']))
        self.assertTrue(secure.allowed_arguments(['unload', '--i-confirm-unload']))
        args = ['enable', '--conf', '/tmp/rules', '--conf-sha256', 'a'*64,
                '--i-confirm-apply', '--i-confirm-window', secure.WINDOW,
                '--i-acknowledge-network-mutation']
        self.assertTrue(secure.allowed_arguments(args))
        self.assertFalse(secure.allowed_arguments(args + ['--journal-dir', '/tmp/x']))
        args[4] = 'xyz'
        self.assertFalse(secure.allowed_arguments(args))

    def test_nonroot_mutation_rejected_before_loading_installed_code(self):
        with mock.patch.object(secure.os, 'geteuid', return_value=501), \
             mock.patch.object(secure, 'verify_installation') as verify, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(secure.main(['unload', '--i-confirm-unload']), 78)
            verify.assert_not_called()

    def test_native_gate_rejects_user_owned_runtime_before_python_starts(self):
        source = installer.TOOLS / 'claude_protect_launcher.c'
        directory = Path(tempfile.mkdtemp(prefix='protect-native-test-')).resolve()
        binary = directory / 'launcher'
        subprocess.run(['/usr/bin/clang', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-DPYTHON_FRAMEWORK="' + str(directory) + '"',
                        str(source), '-o', str(binary)], check=True, capture_output=True)
        result = subprocess.run([str(binary), '--check-runtime'], capture_output=True, text=True)
        self.assertEqual(result.returncode, 78)
        self.assertIn('untrusted_python_runtime', result.stderr)

    def test_untrusted_owner_permissions_symlinks_and_acls_rejected(self):
        safe_dir = SimpleNamespace(st_uid=0, st_mode=stat.S_IFDIR | 0o755)
        unsafe = [SimpleNamespace(st_uid=501, st_mode=stat.S_IFREG | 0o644),
                  SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o664),
                  SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)]
        for info in unsafe:
            with mock.patch.object(Path, 'lstat', side_effect=[safe_dir, info]), \
                 mock.patch.object(secure.subprocess, 'run', return_value=SimpleNamespace(stdout='')):
                with self.assertRaises(ValueError):
                    secure.trusted_path(Path('/file'))
        with mock.patch.object(Path, 'lstat', return_value=safe_dir), \
             mock.patch.object(secure.subprocess, 'run', return_value=SimpleNamespace(stdout=' 0: user:someone allow write\n')):
            with self.assertRaises(ValueError):
                secure.trusted_path(Path('/file'))


class MigrationTests(unittest.TestCase):
    def setUp(self):
        # Retained temporary fixture for inspectability; no system path writes.
        self.expected = installer.source_manifest_hash(installer.source_snapshot())
        self.temp = Path(tempfile.mkdtemp(prefix='protect-security-test-'))
        self.root = self.temp / 'root'
        self.sudoers = self.temp / 'sudoers'
        self.legacy = self.temp / 'legacy'
        self.sudoers.write_text('# Claude protect — narrow NOPASSWD\ntest ALL=(root) NOPASSWD: /legacy\n')
        self.legacy.write_text('#!/bin/bash\n# Managed by claude-protect sudoers installer.\nexec /repo/script\n')
        self.patches = contextlib.ExitStack()
        for obj, name, value in [(secure, 'ROOT', self.root), (secure, 'ENTRY', self.root/'claude-protect'),
                                 (installer, 'SUDOERS', self.sudoers), (installer, 'LEGACY', (self.legacy,))]:
            self.patches.enter_context(mock.patch.object(obj, name, value))
        self.patches.enter_context(mock.patch.object(secure, 'trusted_path'))
        self.patches.enter_context(mock.patch.object(installer.os, 'fchown'))
        self.patches.enter_context(mock.patch.object(installer, 'check_sudoers'))
        self.patches.enter_context(mock.patch.object(installer.pwd, 'getpwnam', return_value=SimpleNamespace(pw_uid=501)))
        self.patches.enter_context(contextlib.redirect_stdout(io.StringIO()))
        self.addCleanup(self.patches.close)

    def test_migration_snapshots_imports_retires_wrappers_and_preserves_backup(self):
        self.assertEqual(installer.migrate('testuser', expected_source_sha256=self.expected), 0)
        self.assertEqual(self.sudoers.read_text(), installer.sudoers_body('testuser'))
        self.assertEqual(self.legacy.read_text(), installer.RETIRED)
        release = secure.verify_installation()
        self.assertEqual(set(json.loads((release/'manifest.json').read_text())), set(secure.FILES))
        for name in secure.FILES:
            self.assertEqual((release/name).read_bytes(), (installer.TOOLS/name).read_bytes())
        backups = list(self.root.glob('archive-*/previous-sudoers.txt'))
        self.assertEqual(len(backups), 1)
        self.assertIn('/legacy', backups[0].read_text())

    def test_failed_compile_keeps_old_grants_revoked(self):
        with mock.patch.object(installer.subprocess, 'run', side_effect=OSError('compile failed')):
            with self.assertRaises(OSError):
                installer.migrate('testuser', expected_source_sha256=self.expected)
        self.assertEqual(self.sudoers.read_text(), installer.DISABLED)

    def test_source_drift_rejected_before_authorization_changes(self):
        before = self.sudoers.read_bytes()
        with self.assertRaisesRegex(ValueError, 'source_changed'):
            installer.migrate('testuser', expected_source_sha256='0'*64)
        self.assertEqual(self.sudoers.read_bytes(), before)

    def test_untrusted_legacy_path_is_skipped_after_grant_revocation(self):
        def validate(path):
            if path == self.legacy:
                raise ValueError('untrusted_path_permissions')
        with mock.patch.object(secure, 'trusted_path', side_effect=validate):
            self.assertEqual(installer.migrate('testuser', expected_source_sha256=self.expected), 0)
        self.assertIn('exec /repo/script', self.legacy.read_text())
        self.assertEqual(self.sudoers.read_text(), installer.sudoers_body('testuser'))

    def test_unowned_sudoers_not_overwritten(self):
        self.sudoers.write_text('# somebody else\n')
        with self.assertRaises(ValueError):
            installer.migrate('testuser', expected_source_sha256=self.expected)
        self.assertEqual(self.sudoers.read_text(), '# somebody else\n')

    def test_digest_tampering_is_rejected(self):
        installer.migrate('testuser', expected_source_sha256=self.expected)
        release = secure.verify_installation()
        (release/'router_pf_root_hook.py').write_text('altered dependency')
        with self.assertRaisesRegex(ValueError, 'digest'):
            secure.verify_installation()

    def test_uninstall_revokes_authorization_without_pf_calls(self):
        installer.migrate('testuser', expected_source_sha256=self.expected)
        self.assertEqual(installer.migrate('testuser', uninstall=True), 0)
        self.assertEqual(self.sudoers.read_text(), installer.DISABLED)
        self.assertEqual(self.legacy.read_text(), installer.RETIRED)
        self.assertTrue(secure.ENTRY.exists())

    def test_entry_and_manifest_tampering_is_rejected(self):
        installer.migrate('testuser', expected_source_sha256=self.expected)
        release = secure.verify_installation()
        original = secure.ENTRY.read_bytes()
        secure.ENTRY.write_bytes(b'not the installed executable')
        with self.assertRaisesRegex(ValueError, 'entry_changed'):
            secure.verify_installation()
        secure.ENTRY.write_bytes(original)
        manifest = json.loads((release/'manifest.json').read_text())
        manifest['extra.py'] = 'a'*64
        (release/'manifest.json').write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'manifest_files_invalid'):
            secure.verify_installation()

    def test_invalid_release_pointer_is_rejected(self):
        installer.migrate('testuser', expected_source_sha256=self.expected)
        for pointer in ['../escape', 'release-' + 'a'*31, 'release-' + 'z'*32]:
            (self.root/'current-release').write_text(pointer)
            with self.assertRaisesRegex(ValueError, 'invalid_release_path'):
                secure.verify_installation()

    def test_invalid_or_missing_permission_cannot_report_verified(self):
        with mock.patch.object(secure, 'verify_installation'):
            self.assertEqual(installer.main(['verify', '--user', 'testuser']), 78)


if __name__ == '__main__':
    unittest.main()
