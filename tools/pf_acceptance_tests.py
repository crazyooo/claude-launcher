"""Full acceptance-cycle retries with production receipts, fake PF and no network."""
import copy
import threading
import time
import unittest
from unittest.mock import Mock, patch

import pf_service as service
import pf_policy as policy
import pf_recovery_integration_tests as recovery_fixtures
import pf_service_tests as fixtures


class AcceptanceTests(unittest.TestCase):
    tick = fixtures.ObserverTests.tick
    production_observer = recovery_fixtures.RecoveryIntegrationTests.production_observer
    submit = recovery_fixtures.RecoveryIntegrationTests.submit
    record = recovery_fixtures.RecoveryIntegrationTests.record
    assert_old_fault = recovery_fixtures.RecoveryIntegrationTests.assert_old_fault
    begin = recovery_fixtures.RecoveryIntegrationTests.begin

    def setUp(self):
        recovery_fixtures.RecoveryIntegrationTests.setUp(self)
        self.wall = time.time() + .01
        self.mono = time.monotonic()
        for name, fn in [('time', lambda: self.wall), ('monotonic', lambda: self.mono)]:
            clock = patch.object(service.time, name, side_effect=fn)
            clock.start(); self.addCleanup(clock.stop)
        self.begin()
        self.initial_request = copy.deepcopy(self.observer.active_recovery)
        self.initial_ticket = self.observer.worker_ticket
        self.observer.collector = Mock(wraps=service.collect_once)

    def advance(self, seconds):
        self.wall += seconds
        self.mono += seconds

    def queue_round(self, ttl=60, changed=False, ticket=None, batch=None):
        sample = fixtures.dns_policy()
        for item in sample['entries'] + sample['queries']:
            item.update(observed_at=self.wall - 2, expires_at=self.wall + ttl)
        if changed:
            sample['entries'][0]['cidr'] = '1.1.1.1/32'
        with patch.object(service, 'collect_round', return_value=(sample, self.wall if batch is None else batch, self.wall)):
            self.observer.worker_run(ticket or self.observer.worker_ticket)

    def assert_retry(self, report, phase):
        self.assertEqual(report['recovery']['status'], 'checking')
        self.assertEqual(report['recovery'], self.initial_request)
        self.assertFalse(report['evidence_fresh'])
        self.assertFalse(report['recovery_current'])
        self.assert_old_fault()
        self.assertTrue(self.observer.manual_pending)
        self.assertEqual(self.observer.cycle.ticket.attempt, 2)
        self.assertEqual(self.observer.cycle.ticket.cycle, self.initial_ticket.cycle)
        self.assertEqual(self.observer.cycle.prior_expiry['phase'], phase)

    def finish_second(self, phase):
        self.queue_round()
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'passed')
        self.assertEqual(report['recovery']['request_id'], self.initial_request['request_id'])
        self.assertEqual(report['recovery']['generation'], self.initial_request['generation'])
        self.assertTrue(report['recovery_current'])
        self.assertEqual(report['sampling_diagnostic']['dns_attempts'], 2)
        self.assertEqual(report['sampling_diagnostic']['prior_expiry']['phase'], phase)
        self.assertEqual(self.observer.collector.call_count, 2)
        return report

    def test_queue_expiry_retries_same_request_then_accepts_second_full_round(self):
        self.queue_round(ttl=1)
        self.advance(2)
        self.assert_retry(self.tick(), 'worker_queue')
        self.finish_second('worker_queue')

    def test_query_return_expiry_is_preserved_by_single_round_collector(self):
        self.queue_round(ttl=-.5)
        self.assert_retry(self.tick(), 'query_return')
        self.finish_second('query_return')

    def test_exit_wait_expiry_is_not_mislabelled_as_queue_delay(self):
        # Query and DNS batch complete before expiry; the full round ends later.
        self.queue_round(ttl=1)
        ticket, sample, error = self.observer.results.get_nowait()
        self.advance(2)
        sample['round_completed_at'] = self.wall
        self.observer.results.put((ticket, sample, error))
        self.assert_retry(self.tick(), 'exit_wait')
        self.finish_second('exit_wait')

    def test_pf_check_expiry_retries_after_readonly_rule_revalidation(self):
        self.queue_round(ttl=1)
        original = service.watch_once
        def slow(*args, **kwargs):
            observed = original(*args, **kwargs)
            self.advance(2)
            return observed
        with patch.object(service, 'watch_once', side_effect=slow):
            self.assert_retry(self.tick(), 'pf_check')
        self.finish_second('pf_check')

    def test_known_renewal_write_expiry_retries_without_accepting_saved_candidate(self):
        self.queue_round(ttl=1)
        original = self.store.write
        def slow(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'renewal':
                self.advance(2)
        with patch.object(self.store, 'write', side_effect=slow):
            self.assert_retry(self.tick(), 'publication')
        self.assertIsNone(self.observer.sample)
        self.assertLess(self.store.read(self.plan['id'], 'renewal')['expires_at'], self.wall)
        self.finish_second('publication')

    def test_service_save_before_receipt_can_retry_but_cannot_clear_fault(self):
        self.queue_round(ttl=1)
        original = self.store.write
        advanced = []
        def slow(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'service' and not advanced:
                advanced.append(True); self.advance(2)
        with patch.object(self.store, 'write', side_effect=slow):
            self.assert_retry(self.tick(), 'publication')
        self.finish_second('publication')

    def test_two_expired_rounds_end_request_without_third_round(self):
        self.queue_round(ttl=-.5)
        self.tick()
        second = self.observer.worker_ticket
        self.queue_round(ttl=-.5)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(self.observer.collector.call_count, 2)
        self.assertFalse(self.observer.manual_pending)
        self.assertIsNone(self.observer.cycle)
        self.assertIsNone(self.observer.worker_ticket)
        self.assertEqual(second.attempt, 2)

    def test_changed_expired_first_round_is_not_hidden_by_later_success(self):
        self.queue_round(ttl=-.5, changed=True)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(self.observer.collector.call_count, 1)
        self.assertIsNone(self.observer.cycle)
        self.assertFalse(report['evidence_fresh'])

    def test_old_round_result_cannot_finish_or_release_new_round(self):
        self.queue_round(ttl=-.5)
        self.tick()
        live = self.observer.worker
        second = self.observer.worker_ticket
        self.queue_round(ticket=self.initial_ticket)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'checking')
        self.assertIs(self.observer.worker, live)
        self.assertEqual(self.observer.worker_ticket, second)
        self.queue_round()
        self.assertEqual(self.tick()['recovery']['status'], 'passed')

    def test_full_cycle_budget_includes_queue_wait_and_reports_timeout(self):
        self.queue_round()
        self.advance(45)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'network_check_timeout')
        self.assertFalse(report['evidence_fresh'])

    def test_retry_not_started_after_thirty_seconds_even_with_fresh_proxy(self):
        self.advance(30)
        self.queue_round(ttl=-.5)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(self.observer.collector.call_count, 1)

    def test_rule_change_prevents_retry_of_expired_candidate(self):
        self.queue_round(ttl=-.5)
        self.pf.own_rules = 'block out from any to 1.1.1.1'
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertIsNone(self.observer.cycle)
        self.assertEqual(self.pf.own_rules, 'block out from any to 1.1.1.1')

    def test_pf_repair_closes_retry_before_any_mutation(self):
        self.queue_round(ttl=1)
        self.pf.own_rules = ''
        original = service.watch_once
        def slow(*args, **kwargs):
            result = original(*args, **kwargs)
            self.assertTrue(self.observer.cycle.retry_closed)
            self.advance(2)
            return result
        with patch.object(service, 'watch_once', side_effect=slow):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(self.observer.collector.call_count, 1)
        self.assertEqual(self.pf.own_rules, self.plan['own_rules'])

    def test_unknown_renewal_write_does_not_retry_or_pass(self):
        self.queue_round()
        original = self.store.write
        def uncertain(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'renewal':
                raise OSError('fixture fsync failed after replace')
        with patch.object(self.store, 'write', side_effect=uncertain):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'pf_check_failed')
        self.assertIsNone(self.observer.cycle)
        self.assertFalse(report['evidence_fresh'])

    def test_previous_evidence_expiry_during_second_round_cannot_be_repaired(self):
        self.queue_round(ttl=5)
        first = self.tick()
        self.assertTrue(first['evidence_fresh'])
        self.observer.next_sample = 0
        self.tick()  # Starts automatic renewal, keeps accepted sample.
        self.queue_round(ttl=1)
        self.advance(2)
        report = self.tick()
        self.assertTrue(report['evidence_fresh'])  # Only the original sample is still valid.
        self.assertEqual(self.observer.cycle.ticket.attempt, 2)
        self.advance(4)
        self.queue_round()
        report = self.tick()
        self.assertFalse(report['evidence_fresh'])
        self.assertEqual(report['reason'], 'evidence_expired')
        self.assertEqual(report['fault_diagnostic']['phase'], 'active_evidence')
        self.assertEqual(report['recovery'], first['recovery'])
        self.assertIsNone(self.observer.sample)

    def test_previous_evidence_must_bridge_service_save_not_just_renewal(self):
        self.queue_round(ttl=3)
        self.tick()
        self.observer.next_sample = 0
        self.tick()
        self.queue_round()
        original = self.store.write
        def slow(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'service':
                self.advance(4)
        with patch.object(self.store, 'write', side_effect=slow):
            report = self.tick()
        self.assertFalse(report['evidence_fresh'])
        self.assertEqual(report['fault_diagnostic']['phase'], 'active_evidence')
        self.assertIsNone(self.observer.sample)

    def test_budget_crossing_in_pf_check_is_a_timeout_not_rule_failure(self):
        self.queue_round()
        original = service.watch_once
        def slow(*args, **kwargs):
            observed = original(*args, **kwargs)
            self.mono += 45  # DNS stays fresh; the monotonic operation budget does not.
            return observed
        with patch.object(service, 'watch_once', side_effect=slow):
            report = self.tick()
        self.assertEqual(report['recovery']['reason'], 'network_check_timeout')
        self.assertEqual(report['recovery']['status'], 'failed')

    def test_retry_rule_read_cannot_push_second_round_past_start_budget(self):
        self.queue_round(ttl=-.5)
        original = service.health
        def slow(*args, **kwargs):
            result = original(*args, **kwargs)
            self.mono += 30
            return result
        with patch.object(service, 'health', side_effect=slow):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(self.observer.collector.call_count, 1)

    def test_expiry_between_queue_validation_and_pf_check_gets_candidate_retry(self):
        self.queue_round(ttl=1)
        original = service.evidence_deadline
        hit = []
        def late(plan, sample, phase='active_evidence'):
            if not hit and phase == 'worker_queue':
                hit.append(True); self.advance(2)
            return original(plan, sample, phase)
        with patch.object(service, 'evidence_deadline', side_effect=late):
            self.assert_retry(self.tick(), 'worker_queue')
        self.assertTrue(hit)
        self.finish_second('worker_queue')

    def test_already_resampled_collector_cannot_get_two_more_rounds(self):
        self.queue_round(ttl=1)
        ticket, sample, error = self.observer.results.get_nowait()
        sample.update(dns_attempts=2, prior_expiry={'phase': 'query_return', 'evidence_kind': 'dns'})
        self.observer.results.put((ticket, sample, error))
        self.advance(2)
        report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertIsNone(self.observer.cycle)

    def test_terminal_receipt_expiry_never_reopens_request_or_extends_history(self):
        self.queue_round(ttl=1)
        original = self.store.write
        saved = []
        def delayed(plan_id, kind, value, **kwargs):
            original(plan_id, kind, value, **kwargs)
            if kind == 'recovery' and value['status'] == 'passed':
                saved.append(copy.deepcopy(value)); self.advance(2)
        with patch.object(self.store, 'write', side_effect=delayed):
            report = self.tick()
        self.assertEqual(len(saved), 1)
        self.assertEqual(report['recovery'], saved[0])
        self.assertEqual(self.record(), saved[0])
        self.assertFalse(report['recovery_current'])
        self.assertFalse(report['evidence_fresh'])
        self.assertFalse(self.observer.manual_pending)
        # Periodic observation may start a different cycle, but it cannot
        # reopen the terminal request or clear the latched manual fault.
        if self.observer.cycle is not None:
            self.assertNotEqual(self.observer.cycle.ticket.cycle, self.initial_ticket.cycle)
            self.queue_round()
            later = self.tick()
            self.assertEqual(later['recovery'], saved[0])
            self.assertFalse(later['evidence_fresh'])
        self.assert_old_fault()

    def test_wait_observes_whole_cycle_deadline_while_worker_is_live(self):
        self.mono = self.observer.cycle.started + 44.9
        self.observer.worker.is_alive.return_value = True
        with patch.object(self.observer, 'tick'), patch.object(self.observer.wake, 'wait') as wait:
            service.run_iteration(self.observer, self.store)
        self.assertAlmostEqual(wait.call_args.args[0], .1, places=5)

    def test_two_real_workers_publish_to_same_request_without_extra_collection(self):
        self.thread.stop()  # Use actual threads/queue; only network answers are fixtures.
        answers = []
        for ttl in (-.5, 60):
            sample = fixtures.dns_policy()
            for item in sample['entries'] + sample['queries']:
                item.update(observed_at=self.wall - 2, expires_at=self.wall + ttl)
            answers.append((sample, self.wall, self.wall))
        first = threading.Thread(target=self.observer.worker_run, args=(self.initial_ticket,))
        self.observer.worker = first
        with patch.object(service, 'collect_round', side_effect=answers) as rounds:
            first.start(); first.join(2)
            self.assertFalse(first.is_alive())
            self.assert_retry(self.tick(), 'query_return')
            second = self.observer.worker
            self.assertIsNot(first, second)
            second.join(2)
            self.assertFalse(second.is_alive())
            report = self.tick()
            self.assertEqual(report['recovery']['status'], 'passed')
            self.assertEqual(report['recovery']['request_id'], self.initial_request['request_id'])
            self.assertEqual(rounds.call_count, 2)
            self.assertEqual(self.observer.collector.call_count, 2)

    def test_budget_expires_immediately_before_terminal_write_records_timeout(self):
        self.queue_round()
        original = self.observer.end_recovery
        def delayed(status, reason, **evidence):
            if status == 'passed':
                self.mono += 45
            return original(status, reason, **evidence)
        with patch.object(self.observer, 'end_recovery', side_effect=delayed):
            report = self.tick()
        self.assertEqual(report['recovery']['status'], 'failed')
        self.assertEqual(report['recovery']['reason'], 'network_check_timeout')
        self.assertFalse(report['recovery_current'])
        self.assert_old_fault()


if __name__ == '__main__':
    unittest.main()
