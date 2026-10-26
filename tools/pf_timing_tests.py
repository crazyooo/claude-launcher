"""Stage-specific expiry and real queue wakeups, without PF or external traffic."""
import copy
import json
import subprocess
import threading
import time
import unittest
from unittest.mock import Mock, patch

import pf_policy as p
import pf_service as s
from pf_guard import GuardError
import pf_service_tests as fixtures
from pf_service_tests import dns_policy


class TimingDiagnosticTests(unittest.TestCase):
    def test_query_return_expiry_keeps_reason_and_bounded_timing(self):
        host = p.HOSTS[0]
        body = {'Status': 0, 'TC': False, 'Question': [{'name': host + '.', 'type': 1}],
                'Answer': [{'name': host + '.', 'type': 1, 'TTL': 1, 'data': '160.79.104.10'}],
                'private': 'cookie-secret'}
        response = b'HTTP/2 200\r\nContent-Type: application/json\r\n\r\n' + json.dumps(body).encode()
        with patch.object(p.time, 'time', side_effect=[100.0, 102.0, 102.0]), \
                patch.object(p, 'bounded_http_request', return_value=response):
            with self.assertRaises(p.PolicyError) as caught:
                p.discover_query(1082, host, 1)
        self.assertEqual(str(caught.exception), 'destination_evidence_expired')
        timing = caught.exception.diagnostic
        self.assertEqual(timing['phase'], 'query_return')
        self.assertEqual(timing['lifetime_seconds'], 1)
        self.assertEqual(timing['request_seconds'], 2)
        self.assertEqual(timing['remaining_seconds'], -1)
        self.assertNotIn('cookie-secret', json.dumps(timing))
        self.assertNotIn('160.79.104.10', json.dumps(timing))

    def test_complete_batch_can_expire_after_early_fresh_return(self):
        value = dns_policy()
        now = time.time()
        value['entries'][0].update(observed_at=now-5, expires_at=now-1)
        value['queries'][0].update(observed_at=now-5, completed_at=now-4, expires_at=now-1)
        jobs = [(host, kind) for host in p.HOSTS for kind in (1, 28)]
        def query(port, host, kind):
            index = jobs.index((host, kind))
            return [value['entries'][index]], value['queries'][index]
        with patch.object(p, 'discover_query', side_effect=query):
            with self.assertRaises(p.PolicyError) as caught:
                p.discover()
        self.assertEqual(caught.exception.diagnostic['phase'], 'dns_batch')
        self.assertEqual(caught.exception.diagnostic['request_seconds'], 1)
        self.assertLess(caught.exception.diagnostic['remaining_seconds'], 0)

    def test_exit_wait_can_expire_successful_dns_batch(self):
        now = time.time()
        original = dns_policy()
        sample = copy.deepcopy(original)
        for entry in sample['entries'] + sample['queries']:
            entry['expires_at'] = now + 1
        with patch.object(s, 'discover_for_plan', return_value=(sample, now)), \
                patch.object(s, 'probe_exit', return_value=now), \
                patch.object(p.time, 'time', return_value=now + 2):
            with self.assertRaises(p.PolicyError) as caught:
                s.collect({'policy': original})
        self.assertEqual(caught.exception.diagnostic['phase'], 'exit_wait')

    def test_nested_checks_preserve_first_failure_phase(self):
        error = p.PolicyError('destination_evidence_expired')
        with self.assertRaises(p.PolicyError):
            with p.evidence_phase(dns_policy(), 'exit_wait'):
                with p.evidence_phase(dns_policy(), 'dns_batch'):
                    raise error
        self.assertEqual(error.diagnostic['phase'], 'dns_batch')

    def test_proxy_expiry_reports_proxy_age_not_dns_ttl(self):
        policy = dns_policy()
        now = time.time()
        sample = {'policy': policy, 'proxy_checked_at': now - 46}
        with self.assertRaises(p.PolicyError) as caught:
            s.evidence_deadline({'policy': policy}, sample, phase='pf_check')
        self.assertEqual(str(caught.exception), 'proxy_evidence_stale')
        timing = caught.exception.diagnostic
        self.assertEqual(timing['evidence_kind'], 'proxy')
        self.assertEqual(timing['phase'], 'pf_check')
        self.assertGreaterEqual(timing['age_seconds'], 46)
        self.assertEqual(timing['lifetime_seconds'], 45)
        self.assertNotIn('host', timing)

    def test_sanitization_rejects_labels_and_discards_unbounded_or_private_values(self):
        for value in (None, [], 'secret', {'phase': []}, {'phase': 'secret', 'evidence_kind': 'dns'},
                      {'phase': 'dns_batch', 'evidence_kind': ['secret']}):
            self.assertIsNone(p.safe_diagnostic(value))
        for number in (float('nan'), float('inf'), True, 'secret', 1000000):
            value = p.safe_diagnostic({'phase': 'dns_batch', 'evidence_kind': 'dns',
                                       'request_seconds': number, 'response': 'secret',
                                       'host': 'secret', 'record_type': 1})
            self.assertEqual(value, {'phase': 'dns_batch', 'evidence_kind': 'dns'})
        policy = {'queries': [{'observed_at': True}, None, 'secret']}
        self.assertEqual(p.timing_diagnostic(policy, 'dns_batch')['phase'], 'dns_batch')


class ObserverTimingTests(unittest.TestCase):
    # Reuse only fixture helpers; do not rerun the inherited regression suite.
    setUp = fixtures.ObserverTests.setUp
    tick = fixtures.ObserverTests.tick
    candidate = fixtures.ObserverTests.candidate
    request = fixtures.ObserverTests.request

    def test_queue_expiry_is_diagnosed_and_never_persisted_as_renewal(self):
        self.candidate()
        generation, result, error = self.observer.results.get_nowait()
        now = time.time()
        for entry in result['policy']['entries'] + result['policy']['queries']:
            entry['expires_at'] = now + 0.5
        self.observer.results.put((generation, result, error))
        with patch.object(s.time, 'time', return_value=now + 1):
            report = self.tick()
        self.assertEqual(report['fault_diagnostic']['phase'], 'worker_queue')
        self.assertEqual(report['status'], 'fault')
        with self.assertRaises(FileNotFoundError):
            self.store.read(self.plan['id'], 'renewal')

    def test_pf_expiry_does_not_claim_rule_loss_or_clear_manual_fault(self):
        self.candidate()
        now = time.time()
        original = s.watch_once
        clock = patch.object(s.time, 'time', return_value=now + 46)
        def slow_pf(*args, **kwargs):
            result = original(*args, **kwargs)
            clock.start()
            return result
        try:
            with patch.object(s, 'watch_once', side_effect=slow_pf):
                report = self.tick()
            self.assertEqual(report['fault_diagnostic']['phase'], 'pf_check')
            self.assertEqual(report['fault_diagnostic']['evidence_kind'], 'proxy')
            self.assertTrue(report['rules_observed'])
        finally:
            clock.stop()

    def test_fault_timing_survives_success_until_manual_recheck(self):
        diagnostic = {'phase': 'dns_batch', 'evidence_kind': 'dns', 'remaining_seconds': -1}
        self.observer.latch('dns_refresh_failed', 'destination_evidence_expired', diagnostic)
        self.candidate()
        self.assertEqual(self.tick()['fault_diagnostic'], diagnostic)
        self.request(); self.candidate()
        self.assertIsNone(self.tick()['fault_diagnostic'])
        self.assertNotIn('fault_diagnostic', self.store.read(self.plan['id'], 'service'))

    def test_expiry_inside_pf_inspection_preserves_rule_observation(self):
        self.candidate()
        now = time.time()
        original = self.pf.own
        clock = patch.object(s.time, 'time', return_value=now + 130)
        started = []
        def slow_read(*args):
            result = original(*args)
            if not started:
                clock.start()
                started.append(True)
            return result
        try:
            with patch.object(self.pf, 'own', side_effect=slow_read):
                report = self.tick()
            self.assertEqual(report['reason'], 'evidence_expired')
            self.assertEqual(report['fault_diagnostic']['phase'], 'pf_check')
            self.assertEqual(report['fault_diagnostic']['evidence_kind'], 'dns')
            self.assertTrue(report['rules_observed'])
            self.assertFalse(report['evidence_fresh'])
            self.assertFalse(self.observer.manual_pending)
            with self.assertRaises(FileNotFoundError):
                self.store.read(self.plan['id'], 'renewal')
        finally:
            clock.stop()

    def test_pf_health_stale_boolean_also_latches_with_timing(self):
        self.candidate()
        now = time.time()
        original = s.watch_once
        clock = patch.object(s.time, 'time', return_value=now + 130)
        def slow_final_check(*args, **kwargs):
            result = original(*args, **kwargs)
            clock.start()
            result['checks']['evidence_fresh'] = False
            result['rules_present_and_fresh'] = False
            return result
        try:
            with patch.object(s, 'watch_once', side_effect=slow_final_check):
                report = self.tick()
            self.assertEqual(report['reason'], 'evidence_expired')
            self.assertEqual(report['fault_diagnostic']['phase'], 'pf_check')
            self.assertTrue(report['rules_observed'])
        finally:
            clock.stop()

    def test_invalid_persisted_timing_is_rejected(self):
        self.observer.latch('dns_refresh_failed')
        self.observer.save()
        state = self.store.read(self.plan['id'], 'service')
        for value in ({'phase': 'secret'}, {'phase': 'dns_batch', 'evidence_kind': 'dns', 'raw': 'secret'},
                      {'phase': 'dns_batch', 'evidence_kind': 'dns', 'age_seconds': True}):
            self.store.write(self.plan['id'], 'service', dict(state, fault_diagnostic=value))
            with self.assertRaisesRegex(GuardError, 'service_state_invalid'):
                s.Observer(self.plan, self.pf, self.store, self.messages.append)

    def test_worker_error_is_sanitized_and_wakes_consumer(self):
        failure = p.PolicyError('destination_evidence_expired')
        failure.diagnostic = {'phase': 'dns_batch', 'evidence_kind': 'dns', 'raw': 'secret'}
        self.observer.collector = Mock(side_effect=failure)
        self.observer.worker_run(self.observer.generation)
        self.assertTrue(self.observer.wake.is_set())
        report = self.tick()
        self.assertNotIn('secret', json.dumps(report))
        self.assertEqual(report['fault_diagnostic'], {'phase': 'dns_batch', 'evidence_kind': 'dns'})

    def test_real_worker_wakes_wait_for_short_lived_complete_sample(self):
        self.thread.stop()  # Use a real worker and real Event, no external traffic.
        permit_collection = threading.Event()
        class Wake(threading.Event):
            def wait(wake, timeout=None):
                wake.requested_timeout = timeout
                permit_collection.set()
                wake.notified = super().wait(timeout)
                return wake.notified
        self.observer.wake = Wake()
        def collect(plan):
            if not permit_collection.wait(2):
                raise RuntimeError('test consumer never waited')
            policy = dns_policy()
            for entry in policy['entries'] + policy['queries']:
                entry['expires_at'] = time.time() + 1
            return {'version': 1, 'plan_sha256': self.observer.binding, 'policy': policy,
                    'proxy_checked_at': time.time(), 'sample_seconds': 0.01}
        self.observer.collector = collect
        self.observer.next_sample = 0
        s.run_iteration(self.observer, self.store)
        self.observer.worker.join(timeout=2)
        self.assertFalse(self.observer.worker.is_alive())
        self.assertGreater(self.observer.wake.requested_timeout, 2)
        self.assertTrue(self.observer.wake.notified)
        with patch.object(s.threading, 'Thread'):
            self.assertEqual(self.tick()['status'], 'observed')

    def test_completed_collection_does_not_wait_for_notification_thread_exit(self):
        self.thread.stop()
        tail_entered, release_tail = threading.Event(), threading.Event()

        class DelayedNotification(threading.Event):
            def set(wake):
                super().set()
                tail_entered.set()
                release_tail.wait(5)

        self.observer.wake = DelayedNotification()

        def collect(plan):
            value = dns_policy()
            for entry in value['entries'] + value['queries']:
                entry['expires_at'] = time.time() + 2.5
            return {'version': 1, 'plan_sha256': self.observer.binding, 'policy': value,
                    'proxy_checked_at': time.time(), 'sample_seconds': 2.0}

        self.observer.collector = collect
        self.observer.worker_generation = self.observer.generation
        worker = threading.Thread(target=self.observer.worker_run, args=(self.observer.generation,))
        self.observer.worker = worker
        self.observer.started = time.monotonic()
        worker.start()
        try:
            self.assertTrue(tail_entered.wait(2), 'collection did not finish')
            self.assertTrue(worker.is_alive())
            with patch.object(s.threading, 'Thread') as replacement, \
                    patch.object(self.observer.wake, 'wait'):
                s.run_iteration(self.observer, self.store)
                self.assertEqual(self.messages[-1]['status'], 'observed')
                replacement.assert_called_once()
                replacement.return_value.start.assert_called_once()
                self.assertTrue(worker.is_alive(), 'test must hold the old notification tail')
        finally:
            release_tail.set()
            worker.join(timeout=2)
        self.assertFalse(worker.is_alive())

    def test_unrelated_result_does_not_release_current_collection_slot(self):
        live = Mock()
        live.is_alive.return_value = True
        self.observer.worker = live
        self.observer.worker_generation = self.observer.generation
        self.observer.started = time.monotonic()
        self.candidate(generation='old-generation')
        self.tick()
        self.assertIs(self.observer.worker, live)


class EventLoopTests(unittest.TestCase):
    def test_idle_loop_wakes_at_earlier_scheduled_sample(self):
        store = Mock()
        store.lock.return_value.__enter__ = Mock()
        store.lock.return_value.__exit__ = Mock(return_value=False)
        observer = Mock(closed=False, worker=None, next_sample=10.25, published_deadline=120)
        with patch.object(s.time, 'monotonic', return_value=10), \
                patch.object(s.time, 'time', return_value=100):
            s.run_iteration(observer, store)
        observer.wake.wait.assert_called_once_with(.25)

    def test_active_collection_does_not_spin_on_overdue_next_sample(self):
        store = Mock()
        store.lock.return_value.__enter__ = Mock()
        store.lock.return_value.__exit__ = Mock(return_value=False)
        observer = Mock(closed=False, next_sample=9, published_deadline=120)
        observer.worker.is_alive.return_value = True
        with patch.object(s.time, 'monotonic', return_value=10), \
                patch.object(s.time, 'time', return_value=100):
            s.run_iteration(observer, store)
        observer.wake.wait.assert_called_once_with(3)

    def test_signal_stop_only_sets_flag_without_acquiring_event_lock(self):
        observer = Mock(closed=False)
        s.request_stop(observer)
        self.assertTrue(observer.closed)
        self.assertEqual(observer.wake.mock_calls, [])

    def test_clear_precedes_tick_and_arrival_during_tick_is_not_lost(self):
        wake = threading.Event()
        observer = Mock(wake=wake, closed=False)
        observer.tick.side_effect = wake.set
        store = Mock()
        store.lock.return_value.__enter__ = Mock()
        store.lock.return_value.__exit__ = Mock(return_value=False)
        with patch.object(wake, 'wait', wraps=wake.wait) as wait:
            s.run_iteration(observer, store)
        self.assertTrue(wake.is_set())
        self.assertTrue(wait.call_args.args[0] > 2)

    def test_periodic_wait_remains_bounded_and_stop_skips_wait(self):
        observer = Mock(closed=False)
        store = Mock()
        store.lock.return_value.__enter__ = Mock()
        store.lock.return_value.__exit__ = Mock(return_value=False)
        with patch.object(s.time, 'monotonic', side_effect=[10, 10.25]):
            s.run_iteration(observer, store)
        observer.wake.wait.assert_called_once_with(2.75)
        observer.wake.wait.reset_mock()
        observer.tick.side_effect = lambda: setattr(observer, 'closed', True)
        s.run_iteration(observer, store)
        observer.wake.wait.assert_not_called()


if __name__ == '__main__':
    unittest.main()
