"""Production-context recovery lifecycle. Real private journals, simulated network/PF."""
import copy
import io
import json
import os
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import Mock, patch

import pf_service as service
import pf_recovery_receipt as recovery
import pf_runtime_identity_tests as fixtures
from pf_guard import GuardError


class RecoveryIntegrationTests(unittest.TestCase):
    setUp = fixtures.ControlTests.setUp
    tick = fixtures.ControlTests.tick
    candidate = fixtures.ControlTests.candidate
    production_observer = fixtures.ControlTests.production_observer
    submit = fixtures.ControlTests.submit

    def begin(self):
        self.production_observer()
        self.observer.clear_fault()
        self.observer.latch('proxy_exit_mismatch')
        self.old_fault = copy.deepcopy(self.observer.state)
        self.sent = self.submit()['recovery']
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'checking')
        self.assertFalse(report['recovery_current'])
        return report

    def record(self):
        with self.store.lock():
            return recovery.load_locked(self.store, self.plan['id'])

    def assert_old_fault(self):
        for key in ('fault', 'fault_at', 'fault_detail', 'fault_diagnostic'):
            self.assertEqual(self.observer.state.get(key), self.old_fault.get(key))

    def test_single_journal_submission_and_identity_retry_do_not_create_new_work(self):
        self.production_observer()
        request = {'request_id': 'd'*32, 'expected_revision': 0}
        first = self.submit(**request)
        self.assertFalse(self.store.path(self.plan['id'], 'recheck').exists())
        with patch.object(self.store, 'write', wraps=self.store.write) as write:
            self.assertEqual(self.submit(**request), first)
            write.assert_not_called()
        self.tick()
        generation = self.observer.generation
        retry = self.submit(**request)
        self.assertEqual(retry['reason'], 'recheck_existing_result')
        self.tick()
        self.assertEqual(self.observer.generation, generation)
        with self.assertRaisesRegex(recovery.ReceiptError, 'in_progress'):
            self.submit(request_id='e'*32, expected_revision=1)
        self.candidate()
        passed = self.tick()['recovery']
        self.assertEqual(passed['status'], 'passed')
        self.assertEqual(self.submit(**request)['recovery'], passed)
        next_request = self.submit(request_id='e'*32, expected_revision=1)['recovery']
        self.assertEqual(next_request['revision'], 2)
        with self.assertRaisesRegex(recovery.ReceiptError, 'revision_conflict'):
            self.submit(**request)

    def test_success_is_bound_to_attempt_and_expires_without_replaying(self):
        self.begin()
        self.candidate()
        report = self.tick()
        self.assertEqual(report['status'], 'observed')
        self.assertTrue(report['recovery_current'])
        self.assertEqual(report['recovery']['request_id'], self.sent['request_id'])
        self.assertEqual(report['recovery']['generation'], self.observer.generation)
        self.assertEqual(set(report['recovery']['checks']), recovery.CHECKS)
        self.assertTrue(all(v is True for v in report['recovery']['checks'].values()))
        self.assertEqual(self.record(), report['recovery'])
        self.assertIsNone(self.observer.state['fault'])
        with patch.object(service.time, 'time', return_value=report['recovery']['evidence_expires_at']+1):
            expired = self.tick()
        self.assertEqual(expired['recovery'], report['recovery'])
        self.assertFalse(expired['recovery_current'])
        self.assertEqual(expired['reason'], 'evidence_expired')

    def test_latest_failure_does_not_relabel_first_latched_fault(self):
        self.begin()
        self.candidate(error=service.SampleFailure('dns_refresh_failed', 'proxy_doh_timeout'))
        report = self.tick()
        self.assertEqual(report['reason'], 'proxy_exit_mismatch')
        self.assertEqual(report['recovery']['reason'], 'dns_refresh_failed')
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertFalse(report['recovery_current'])
        self.assert_old_fault()
        self.candidate()
        later = self.tick()
        self.assertEqual(later['recovery'], report['recovery'])
        self.assertEqual(later['reason'], 'proxy_exit_mismatch')

    def test_pf_failure_records_this_attempt_and_no_pass(self):
        self.begin()
        self.candidate()
        with patch.object(self.pf, 'own', side_effect=GuardError('pfctl_rejected')):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'pf_check_failed')
        self.assert_old_fault()

    def test_old_generation_result_cannot_finish_current_attempt(self):
        self.production_observer()
        old_generation = self.observer.generation
        self.submit()
        self.tick()
        self.candidate(generation=old_generation)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'checking')
        self.assertTrue(self.observer.manual_pending)
        self.candidate()
        self.assertEqual(self.tick()['recovery']['status'], 'passed')

    def test_worker_timeout_has_its_own_failed_receipt(self):
        self.begin()
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        self.observer.worker_generation = self.observer.generation
        self.observer.started = time.monotonic()-46
        report = self.tick()
        self.assertEqual(report['recovery']['reason'], 'network_check_timeout')
        self.assert_old_fault()

    def test_expired_received_request_is_terminal_without_begin(self):
        self.production_observer()
        self.sent = self.submit()['recovery']
        with patch.object(service.time, 'time', return_value=self.sent['request_deadline']):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'request_expired')
        self.assertIsNone(report['recovery']['started_at'])
        self.assertFalse(self.observer.manual_pending)
        self.assertIsNone(self.observer.sample)

    def test_checking_request_deadline_invalidates_late_worker(self):
        self.begin()
        generation = self.observer.generation
        self.candidate()
        with patch.object(service.time, 'time', return_value=self.sent['request_deadline']):
            report = self.tick()
        self.assertEqual(report['recovery']['reason'], 'request_expired')
        self.assertNotEqual(generation, self.observer.generation)
        self.assert_old_fault()

    def test_deadline_crossing_inside_begin_is_recorded(self):
        self.production_observer()
        sent = self.submit()['recovery']
        original = recovery.begin
        with patch.object(service.time, 'time', return_value=sent['received_at']) as wall:
            def delayed(current, **kwargs):
                wall.return_value = sent['request_deadline']
                kwargs['now'] = wall.return_value
                return original(current, **kwargs)
            with patch.object(recovery, 'begin', side_effect=delayed):
                report = self.tick()
        self.assertEqual(report['recovery']['reason'], 'request_expired')

    def test_restart_interrupts_active_but_keeps_history_without_replay(self):
        self.production_observer()
        sent = self.submit()['recovery']
        self.production_observer()
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'interrupted')
        self.assertEqual(report['recovery']['service_instance'], sent['service_instance'])
        self.assertFalse(self.observer.manual_pending)
        self.submit()
        self.tick()
        checking = self.record()
        self.production_observer()
        self.assertEqual(self.record()['status'], 'interrupted')
        self.assertEqual(self.record()['request_id'], checking['request_id'])
        self.submit()
        self.tick()
        self.candidate()
        passed = self.tick()['recovery']
        self.production_observer()
        report = self.tick()
        self.assertEqual(report['recovery'], passed)
        self.assertFalse(report['recovery_current'])
        self.assertEqual(report['reason'], 'service_restarted')

    def test_signal_is_io_free_and_stop_records_received_or_checking(self):
        self.production_observer()
        self.submit()
        before = self.record()
        service.request_stop(self.observer)
        self.assertEqual(self.record(), before)
        with self.store.lock():
            self.observer.interrupt_recovery('service_stopped')
        self.assertEqual(self.record()['reason'], 'service_stopped')
        self.production_observer()
        self.submit()
        self.tick()
        with self.store.lock():
            self.observer.interrupt_recovery('service_stopped')
        self.assertEqual(self.record()['status'], 'interrupted')

    def test_expiry_at_each_durable_boundary_never_clears_old_fault(self):
        # Each subcase has its own fixture so future fake timestamps cannot
        # contaminate the following request's ordering checks.
        for boundary in ('renewal', 'before_pass', 'passed_receipt', 'cleared_state'):
            case = RecoveryIntegrationTests()
            case.setUp()
            try:
                case.begin()
                case.candidate()
                generation, sample, error = case.observer.results.get_nowait()
                now = time.time()
                for item in sample['policy']['entries'] + sample['policy']['queries']:
                    item['expires_at'] = now+1
                case.observer.results.put((generation, sample, error))
                original = case.store.write
                triggered = []
                with patch.object(service.time, 'time', return_value=now) as wall:
                    def slow(plan_id, kind, value, **kwargs):
                        original(plan_id, kind, value, **kwargs)
                        hit = ((boundary == 'renewal' and kind == 'renewal') or
                               (boundary == 'before_pass' and kind == 'service') or
                               (boundary == 'passed_receipt' and kind == 'recovery' and value['status'] == 'passed') or
                               (boundary == 'cleared_state' and kind == 'service' and value['fault'] is None))
                        if hit and not triggered:
                            triggered.append(True)
                            wall.return_value = now+2
                    with patch.object(case.store, 'write', side_effect=slow):
                        report = case.tick()
                with self.subTest(boundary=boundary):
                    self.assertTrue(triggered)
                    self.assertFalse(report['recovery_current'])
                    self.assertFalse(report['evidence_fresh'])
                    self.assertIsNone(case.observer.sample)
                    case.assert_old_fault()
                    self.assertEqual(report['recovery']['status'],
                                     'checking' if boundary in ('renewal', 'before_pass') else 'passed')
                    if boundary in ('renewal', 'before_pass'):
                        self.assertTrue(case.observer.manual_pending)
                        self.assertEqual(case.observer.cycle.ticket.attempt, 2)
                    else:
                        self.assertFalse(case.observer.manual_pending)
            finally:
                case.doCleanups()

    def test_receipt_write_failure_before_or_after_replace_never_clears_fault(self):
        for after in (False, True):
            case = RecoveryIntegrationTests()
            case.setUp()
            try:
                case.begin()
                case.candidate()
                original = case.store.write
                def failed(plan_id, kind, value, **kwargs):
                    if kind == 'recovery' and value['status'] == 'passed':
                        if after:
                            original(plan_id, kind, value, **kwargs)
                        raise OSError('private-fsync-failure')
                    return original(plan_id, kind, value, **kwargs)
                before = len(case.messages)
                with patch.object(case.store, 'write', side_effect=failed), \
                        self.assertRaisesRegex(recovery.ReceiptError, 'write_outcome_unknown'):
                    case.tick()
                case.assert_old_fault()
                self.assertEqual(len(case.messages), before)
                self.assertEqual(case.record()['status'], 'passed' if after else 'checking')
                case.production_observer()
                report = case.tick()
                self.assertFalse(report['recovery_current'])
                self.assertEqual(report['recovery']['status'], 'passed' if after else 'interrupted')
            finally:
                case.doCleanups()

    def test_unknown_submission_output_preserves_retry_identity(self):
        self.production_observer()
        original = self.store.write
        def failed(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'recovery':
                raise OSError('private-fsync-failure')
        with patch.object(self.store, 'write', side_effect=failed), self.assertRaises(recovery.ReceiptError) as caught:
            self.submit()
        retry = caught.exception.request_identity
        same = self.submit(**retry)
        self.assertEqual(same['recovery'], self.record())
        output = io.StringIO()
        with patch.object(service.os, 'geteuid', return_value=0), \
                patch.object(service, 'submit_recheck', side_effect=caught.exception), redirect_stdout(output):
            self.assertEqual(service.main(['recheck', '--id', self.plan['id']]), 78)
        error = json.loads(output.getvalue())
        self.assertEqual(error['request_id'], retry['request_id'])
        self.assertEqual(error['expected_revision'], retry['expected_revision'])
        self.assertNotIn('private', output.getvalue())

    def test_malformed_candidate_and_missing_rules_cannot_pass(self):
        self.begin()
        self.candidate()
        generation, sample, error = self.observer.results.get_nowait()
        sample['sample_seconds'] = float('nan')
        self.observer.results.put((generation, sample, error))
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'dns_refresh_failed')
        self.assert_old_fault()
        self.submit()
        self.tick()
        self.pf.own_rules = 'block out from any to 1.1.1.1'
        self.candidate()
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'rules_missing_or_changed')

    def test_request_expiring_during_prepass_save_is_not_success(self):
        self.begin()
        self.candidate()
        current = self.record()
        now = time.time()
        original = self.store.write
        with patch.object(service.time, 'time', return_value=now) as wall:
            def slow(plan_id, kind, value, **kwargs):
                original(plan_id, kind, value, **kwargs)
                if kind == 'service':
                    wall.return_value = current['request_deadline']
            with patch.object(self.store, 'write', side_effect=slow):
                report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'request_expired')
        self.assert_old_fault()

    def test_cleared_service_write_error_restores_memory_and_restart_blocks(self):
        self.begin()
        self.candidate()
        original = self.store.write
        def failed(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'service' and value['fault'] is None:
                raise OSError('after-service-replace')
        before = len(self.messages)
        with patch.object(self.store, 'write', side_effect=failed), self.assertRaises(OSError):
            self.tick()
        self.assert_old_fault()
        self.assertEqual(len(self.messages), before)
        self.assertEqual(self.record()['status'], 'passed')
        self.production_observer()
        self.assertEqual(self.tick()['reason'], 'service_restarted')
        self.assertFalse(self.messages[-1]['recovery_current'])

    def test_cas_change_and_foreign_active_binding_cannot_execute(self):
        self.begin()
        checking = self.record()
        foreign = dict(checking, service_instance='f'*32)
        self.store.write(self.plan['id'], 'recovery', foreign)
        with self.assertRaisesRegex(recovery.ReceiptError, 'receipt_changed'):
            self.tick()
        self.assertEqual(self.record(), foreign)
        self.assert_old_fault()

    def test_main_graceful_stop_publishes_correlated_interruption(self):
        self.production_observer()
        messages = []
        def one_iteration(observer, store):
            with store.lock():
                current = recovery.load_locked(store, self.plan['id'])
                value = recovery.submit(current, request_id='f'*32,
                    expected_revision=current['revision'] if current else 0,
                    binding=observer.recovery_binding(), now=time.time())
                recovery.commit_locked(store, self.plan['id'], current, value)
                observer.tick()
            service.request_stop(observer)
        root_os = Mock(wraps=os)
        root_os.geteuid.return_value = 0
        with patch.object(service, 'os', root_os), patch.object(service, 'trusted_directory'), \
                patch.object(service, 'Store', return_value=self.store), patch.object(service, 'PF', return_value=self.pf), \
                patch.object(service.runtime_identity, 'installed_for_plan', return_value=self.installation), \
                patch.object(service, 'publish', side_effect=messages.append), \
                patch.object(service.Observer, 'tick', autospec=True), \
                patch.object(service, 'run_iteration', side_effect=one_iteration), patch.object(service.signal, 'signal'):
            self.assertEqual(service.main(['run', '--id', self.plan['id']]), 0)
        self.assertEqual(messages[-1]['status'], 'stopped')
        self.assertEqual(messages[-1]['recovery']['reason'], 'service_stopped')
        self.assertFalse(messages[-1]['recovery_current'])

    def test_expiry_at_final_receipt_timestamp_is_a_failed_check_not_daemon_error(self):
        self.begin()
        self.candidate()
        generation, sample, error = self.observer.results.get_nowait()
        now = time.time()
        for item in sample['policy']['entries'] + sample['policy']['queries']:
            item['expires_at'] = now+1
        self.observer.results.put((generation, sample, error))
        original = self.observer.end_recovery
        with patch.object(service.time, 'time', return_value=now) as wall:
            def delayed(status, reason, **kwargs):
                if status == 'passed':
                    wall.return_value = now+1
                return original(status, reason, **kwargs)
            with patch.object(self.observer, 'end_recovery', side_effect=delayed):
                report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'evidence_expired')
        self.assert_old_fault()


if __name__ == '__main__':
    unittest.main()
