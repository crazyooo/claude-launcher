"""Root diagnostic contract with fixture journals/PF; no administrator or network."""
import copy
import io
import json
import os
from pathlib import Path
import stat
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import pf_guard as guard
import pf_policy as policy
import pf_service as service
import pf_service_diagnose as diagnostic
import pf_service_install as installer
import pf_recovery_receipt as recovery
import pf_service_install_tests as fixtures
from pf_service_tests import dns_policy


class ServiceDiagnosticTests(unittest.TestCase):
    def setUp(self):
        fixtures.InstallerTests.setUp(self)
        fixtures.InstallerTests.install(self)
        self.binding = policy.fingerprint(self.plan)
        self.token = 'b' * 32
        self.store.write(self.plan['id'], 'recheck', {'request': self.token, 'plan_sha256': self.binding})
        self.store.write(self.plan['id'], 'service', {
            'request': self.token, 'plan_sha256': self.binding, 'running': True,
            'fault': 'dns_refresh_failed', 'fault_detail': 'destination_evidence_expired',
            'fault_at': time.time()-100, 'private': 'private-secret'})
        self.extra = [patch.object(service, 'trusted_directory'),
                      patch.object(diagnostic, 'JOURNAL_OWNER', os.geteuid()),
                      patch.object(guard, 'DIRECTORY', self.store.directory),
                      patch.object(guard, 'Store', return_value=self.store),
                      patch.object(guard, 'PF', return_value=self.pf)]
        for item in self.extra:
            item.start(); self.addCleanup(item.stop)

    def sample(self):
        return {'policy': dns_policy(), 'dns_attempts': 1, 'prior_expiry': None,
                'proxy_checked_at': time.time(), 'private': 'private-secret'}

    def read_journals(self):
        return {p.name: p.read_bytes() for p in self.store.directory.iterdir()}

    def test_success_only_reads_journals_and_pf_and_keeps_old_failure_distinct(self):
        before = self.read_journals()
        mutations = list(self.pf.mutations)
        with patch.object(service, 'collect', return_value=self.sample()) as collect, \
                patch.object(self.store, 'lock', side_effect=AssertionError('write lock')), \
                patch.object(self.store, 'write', side_effect=AssertionError('write')), \
                patch.object(guard, 'watch_once', side_effect=AssertionError('repair')):
            report = diagnostic.diagnose(self.plan['id'])
        collect.assert_called_once()
        self.assertEqual(report['current_root_probe']['reason'], 'current_sample_and_pf_checks_passed')
        self.assertTrue(report['before']['request_seen_by_service'])
        self.assertEqual(report['before']['fault_detail'], 'destination_evidence_expired')
        self.assertFalse(report['before']['last_manual_attempt_result_available'])
        self.assertFalse(any(report['changed_during_probe'].values()))
        self.assertEqual(self.read_journals(), before); self.assertEqual(self.pf.mutations, mutations)
        for text in ('private-secret', self.token, '160.79.104.10', self.binding):
            self.assertNotIn(text, json.dumps(report))
        for key in ('pf_modified', 'state_modified', 'protection_verified', 'launch_authorized'):
            self.assertFalse(report[key])

    def test_source_runtime_mismatch_refuses_network_and_health(self):
        payload = installer.package(); payload['pf_service.py'] += b'\n# divergent source\n'
        with patch.object(installer, 'package', return_value=payload), \
                patch.object(service, 'collect') as collect, patch.object(guard, 'health') as health:
            with self.assertRaisesRegex(guard.GuardError, 'source_runtime_mismatch'):
                diagnostic.diagnose(self.plan['id'])
        collect.assert_not_called(); health.assert_not_called()

    def test_plan_binding_mismatch_refuses_network(self):
        self.plan['private'] = 'changed'
        self.store.write(self.plan['id'], 'plan', self.plan)
        with patch.object(service, 'collect') as collect:
            with self.assertRaisesRegex(guard.GuardError, 'plan_binding_mismatch'):
                diagnostic.diagnose(self.plan['id'])
        collect.assert_not_called()

    def test_current_failure_is_sanitized_without_replacing_historical_fault(self):
        for error, reason in ((policy.PolicyError('proxy_doh_timeout'), 'proxy_doh_timeout'),
                              (RuntimeError('private-secret'), 'diagnostic_stage_failed')):
            with patch.object(service, 'collect', side_effect=error), patch.object(guard, 'health') as health:
                report = diagnostic.diagnose(self.plan['id'])
            health.assert_not_called()
            self.assertEqual(report['current_root_probe']['reason'], reason)
            self.assertEqual(report['before']['fault_detail'], 'destination_evidence_expired')
            self.assertNotIn('private-secret', json.dumps(report))

    def test_concurrent_changes_are_marked_not_interpreted_as_manual_success(self):
        before = diagnostic.snapshot(self.plan['id'])
        after = copy.deepcopy(before)
        after[0]['recheck']['request'] = 'c' * 32
        after[2]['recheck'] = 'different-digest'
        with patch.object(diagnostic, 'snapshot', side_effect=[before, after]), \
                patch.object(service, 'collect', return_value=self.sample()):
            report = diagnostic.diagnose(self.plan['id'])
        self.assertTrue(report['changed_during_probe']['recheck'])
        self.assertFalse(report['after']['request_seen_by_service'])
        self.assertFalse(report['launch_authorized'])

    def test_post_health_expiry_is_reported_at_that_stage(self):
        with patch.object(service, 'collect', return_value=self.sample()), \
                patch.object(service, 'evidence_deadline', side_effect=policy.PolicyError('proxy_evidence_stale')):
            report = diagnostic.diagnose(self.plan['id'])
        self.assertEqual(report['current_root_probe']['stage'], 'post_health_freshness')
        self.assertEqual(report['current_root_probe']['reason'], 'proxy_evidence_stale')
        self.assertFalse(report['launch_authorized'])

    def test_missing_request_is_not_reported_as_seen(self):
        records, times, _ = diagnostic.snapshot(self.plan['id'])
        records['recheck'] = None
        result = diagnostic.summarize(records, times, self.binding)
        self.assertFalse(result['request_present']); self.assertIsNone(result['request_seen_by_service'])

    def test_non_root_main_does_not_read_or_probe(self):
        with patch.object(diagnostic.os, 'geteuid', return_value=501), \
                patch.object(diagnostic, 'diagnose') as probe, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.main(['--id', self.plan['id']]), 78)
        probe.assert_not_called()
        self.assertEqual(json.loads(output.getvalue())['reason'], 'administrator_required_no_changes')

    def test_system_style_group_writable_parent_allows_private_journal(self):
        parent = self.store.directory.parent
        previous = stat.S_IMODE(parent.stat().st_mode)
        try:
            parent.chmod(0o775)
            records, _, _ = diagnostic.snapshot(self.plan['id'])
            self.assertEqual(records['plan']['id'], self.plan['id'])
        finally:
            parent.chmod(previous)

    def test_private_directory_must_not_be_group_writable(self):
        self.store.directory.chmod(0o770)
        with patch.object(service, 'collect') as collect:
            with self.assertRaisesRegex(guard.GuardError, 'journal_directory_unsafe'):
                diagnostic.diagnose(self.plan['id'])
        collect.assert_not_called()

    def test_final_directory_and_file_symlinks_are_rejected(self):
        link = self.store.directory.parent/'journal-link'
        link.symlink_to(self.store.directory, target_is_directory=True)
        with patch.object(guard, 'DIRECTORY', link):
            with self.assertRaisesRegex(guard.GuardError, 'journal_directory_unreadable'):
                diagnostic.snapshot(self.plan['id'])
        original = self.store.path(self.plan['id'], 'recheck')
        moved = original.with_suffix('.saved')
        original.rename(moved); original.symlink_to(moved)
        with self.assertRaisesRegex(guard.GuardError, 'journal_file_unreadable'):
            diagnostic.snapshot(self.plan['id'])

    def test_directory_descriptor_survives_parent_path_replacement(self):
        real_open = os.open
        renamed = False
        def open_file(path, flags, *args, **kwargs):
            nonlocal renamed
            if 'dir_fd' in kwargs and not renamed:
                renamed = True
                self.store.directory.rename(self.store.directory.with_name('journal-original'))
                self.store.directory.mkdir(mode=0o700)
            return real_open(path, flags, *args, **kwargs)
        with patch.object(diagnostic.os, 'open', side_effect=open_file):
            records, _, _ = diagnostic.snapshot(self.plan['id'])
        self.assertTrue(renamed)
        self.assertEqual(records['plan']['id'], self.plan['id'])
        self.assertEqual(list(self.store.directory.iterdir()), [])

    def test_invalid_json_and_unknown_errors_retain_fixed_stage_without_secrets(self):
        bad = self.store.path(self.plan['id'], 'recheck')
        bad.write_text('private-secret-not-json')
        with self.assertRaisesRegex(guard.GuardError, 'journal_json_invalid') as caught:
            diagnostic.diagnose(self.plan['id'])
        self.assertEqual(caught.exception.diagnostic_stage, 'snapshot_before')
        error = RuntimeError('private-secret')
        error.diagnostic_stage = 'snapshot_before'
        with patch.object(diagnostic.os, 'geteuid', return_value=0), \
                patch.object(diagnostic, 'diagnose', side_effect=error), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(diagnostic.main(['--id', self.plan['id']]), 78)
        report = json.loads(output.getvalue())
        self.assertEqual(report['stage'], 'snapshot_before')
        self.assertNotIn('private-secret', output.getvalue())

    def recovery_record(self, terminal=False):
        binding = {'plan_id': self.plan['id'], 'plan_sha256': self.binding,
                   'runtime_sha256': 'c'*64, 'service_instance': 'd'*32}
        value = recovery.submit(None, request_id='e'*32, expected_revision=0, binding=binding, now=100)
        if terminal:
            args = {'request_id': value['request_id'], 'receipt_revision': 1, 'binding': binding}
            value = recovery.begin(value, generation='f'*32, now=101, **args)
            value = recovery.finish(value, generation='f'*32, status='failed', reason='proxy_probe_failed',
                                    now=102, **args)
        return value

    def test_correlated_result_precedes_legacy_and_is_readonly_and_sanitized(self):
        receipt = self.recovery_record(terminal=True)
        self.store.write(self.plan['id'], 'recovery', receipt)
        state = self.store.read(self.plan['id'], 'service')
        state.update(request=receipt['request_id'], request_revision=receipt['revision'],
                     runtime_sha256=receipt['runtime_sha256'], service_instance=receipt['service_instance'])
        self.store.write(self.plan['id'], 'service', state)
        before = self.read_journals()
        with patch.object(service, 'collect', return_value=self.sample()):
            report = diagnostic.diagnose(self.plan['id'])
        summary = report['before']
        self.assertTrue(summary['last_manual_attempt_result_available'])
        self.assertEqual(summary['request_source'], 'recovery')
        self.assertTrue(summary['request_seen_by_service'])
        self.assertTrue(summary['manual_attempt_same_service_instance'])
        self.assertEqual(summary['manual_attempt']['reason'], 'proxy_probe_failed')
        self.assertEqual(summary['latched_fault'], 'dns_refresh_failed')
        self.assertIsNone(summary['renewal_saved_after_request'])
        for value in (receipt['request_id'], receipt['runtime_sha256'], receipt['service_instance'], self.binding):
            self.assertNotIn(value, json.dumps(report))
        self.assertEqual(before, self.read_journals())

    def test_active_and_previous_instance_receipts_are_not_claimed_as_current_results(self):
        records, times, _ = diagnostic.snapshot(self.plan['id'])
        records['recheck'] = None
        records['recovery'] = self.recovery_record()
        summary = diagnostic.summarize(records, times, self.binding)
        self.assertFalse(summary['last_manual_attempt_result_available'])
        self.assertFalse(summary['request_seen_by_service'])
        self.assertEqual(summary['manual_attempt']['status'], 'received')
        records['recovery'] = self.recovery_record(terminal=True)
        summary = diagnostic.summarize(records, times, self.binding)
        self.assertTrue(summary['last_manual_attempt_result_available'])
        self.assertFalse(summary['manual_attempt_same_service_instance'])
        self.assertFalse(summary['request_seen_by_service'])

    def test_receipt_takes_precedence_over_invalid_legacy_shapes(self):
        records, times, _ = diagnostic.snapshot(self.plan['id'])
        for legacy in ([], 'old-record', 7, False):
            with self.subTest(legacy=legacy):
                records['recheck'] = legacy
                records['recovery'] = self.recovery_record(terminal=True)
                summary = diagnostic.summarize(records, times, self.binding)
                self.assertEqual(summary['request_source'], 'recovery')
                self.assertTrue(summary['last_manual_attempt_result_available'])
                records['recovery'] = None
                with self.assertRaisesRegex(guard.GuardError, 'service_state_invalid'):
                    diagnostic.summarize(records, times, self.binding)

    def test_corrupt_or_foreign_receipt_is_rejected_before_probe(self):
        receipt = self.recovery_record(terminal=True)
        for change in ({'secret': 'private-secret'}, {'plan_id': '9'*32}, {'plan_sha256': '9'*64}):
            self.store.write(self.plan['id'], 'recovery', dict(receipt, **change))
            with patch.object(service, 'collect') as collect, \
                    self.assertRaisesRegex(guard.GuardError, 'diagnostic_recovery_invalid'):
                diagnostic.diagnose(self.plan['id'])
            collect.assert_not_called()


if __name__ == '__main__':
    unittest.main()
