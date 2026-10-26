"""Observer regression tests: real private journals, simulated PF/network only."""
import copy
import json
import subprocess
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import time
import unittest
import uuid
from unittest.mock import Mock, patch

import pf_guard as g
import pf_policy as p
import pf_service as s
from pf_guard_tests import FakePF


def dns_policy():
    now = time.time()
    value = {'version': 1, 'proxy_port': 1082, 'confirmed_exit': '203.0.113.43',
             'transport_exclusions': [], 'entries': [], 'queries': []}
    for host in p.HOSTS:
        for kind, address in ((1, '160.79.104.10/32'), (28, '2607:6bc0::10/128')):
            value['entries'].append({'cidr': address, 'source': 'dns.google ' + host,
                                     'observed_at': now - 1, 'expires_at': now + 120})
            value['queries'].append({'host': host, 'type': kind, 'addresses': 1,
                                     'observed_at': now - 1, 'completed_at': now,
                                     'expires_at': now + 120})
    return value


class DNSDiagnosticTests(unittest.TestCase):
    def test_failures_are_specific_and_never_echo_remote_text(self):
        for body, expected in [(b'secret', 'json_invalid'), (b'x' * 65537, 'too_large')]:
            response = b'HTTP/2 200\r\nContent-Type: application/json\r\n\r\n' + body
            with patch.object(p, 'bounded_http_request', return_value=response):
                with self.assertRaises(p.PolicyError) as caught:
                    p.discover_query(1082, p.HOSTS[0], 1)
            self.assertEqual(str(caught.exception), 'proxy_doh_' + expected)
            self.assertNotIn('secret', str(caught.exception))



class RenewalTests(unittest.TestCase):
    def test_renewal_preserves_original_and_exact_per_owner_sets(self):
        original = dns_policy()
        before = p.fingerprint(original)
        self.assertEqual(len(p.same_destinations(original, dns_policy())['cidrs']), 2)
        changed = dns_policy()
        changed['entries'][0]['cidr'] = '1.1.1.1/32'
        with self.assertRaisesRegex(p.PolicyError, 'policy_changed'):
            p.same_destinations(original, changed)
        self.assertEqual(p.fingerprint(original), before)

    def test_same_union_with_changed_owner_rejected(self):
        original = dns_policy()
        original['entries'][0]['cidr'] = '1.1.1.1/32'
        changed = copy.deepcopy(original)
        changed['entries'][0]['cidr'], changed['entries'][2]['cidr'] = (
            changed['entries'][2]['cidr'], changed['entries'][0]['cidr'])
        self.assertEqual(p.validate(original)['cidrs'], p.validate(changed)['cidrs'])
        with self.assertRaises(p.PolicyError):
            p.same_destinations(original, changed)

    def test_queries_must_be_complete_unique_and_fresh(self):
        for mutate in (lambda v: v['queries'].pop(),
                       lambda v: v['queries'].__setitem__(0, v['queries'][1]),
                       lambda v: v['queries'].__setitem__(0, []),
                       lambda v: v['queries'][0].update(expires_at=time.time()-1),
                       lambda v: v['queries'][0].update(addresses=0),
                       lambda v: v['queries'][0].update(completed_at=float('nan'))):
            value = dns_policy(); mutate(value)
            with self.assertRaises(p.PolicyError):
                p.dns_evidence(value)

    def test_zero_answer_expiry_is_part_of_evidence(self):
        value = dns_policy()
        value['entries'].pop(1)
        value['queries'][1].update(addresses=0, expires_at=time.time()+5)
        self.assertLess(p.dns_evidence(value)[1]['expires_at'], time.time()+6)
        value['queries'][1]['expires_at'] = time.time()-0.1
        with self.assertRaises(p.PolicyError):
            p.dns_evidence(value)

    def test_proxy_baseline_cannot_change(self):
        original = dns_policy()
        for key, value in [('proxy_port', 1083), ('confirmed_exit', '1.1.1.1'),
                           ('transport_exclusions', ['8.8.8.8'])]:
            sample = dns_policy(); sample[key] = value
            with self.assertRaises(p.PolicyError):
                p.same_destinations(original, sample)


class ObserverTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.store = g.Store(Path(temporary.name))
        self.pf = FakePF()
        with self.store.lock():
            self.plan = g.stage(dns_policy(), self.pf, self.store)
            g.apply(self.plan, p.fingerprint(self.plan), self.pf, self.store)
        self.messages = []
        self.observer = s.Observer(self.plan, self.pf, self.store, self.messages.append)
        self.observer.next_sample = float('inf')
        self.thread = patch.object(s.threading, 'Thread')
        self.thread.start(); self.addCleanup(self.thread.stop)

    def tick(self):
        with self.store.lock():
            self.observer.tick()
        report = self.messages[-1]
        self.assertFalse(report['launch_authorized'])
        self.assertFalse(report['protection_verified'])
        return report

    def test_fault_detail_survives_auto_success_and_clears_manually(self):
        self.observer.collector = Mock(side_effect=p.PolicyError('proxy_doh_timeout'))
        self.observer.worker_run(self.observer.generation)
        report = self.tick()
        self.assertEqual(report['reason'], 'dns_refresh_failed')
        self.assertEqual(report['fault_detail'], 'proxy_doh_timeout')
        self.observer.latch('dns_refresh_failed', 'dns_ttl_invalid')
        self.candidate(); self.assertEqual(self.tick()['fault_detail'], 'proxy_doh_timeout')
        self.request(); self.candidate(); report = self.tick()
        self.assertEqual(report['status'], 'observed'); self.assertIsNone(report['fault_detail'])
        self.assertNotIn('fault_detail', self.store.read(self.plan['id'], 'service'))

    def test_unknown_details_never_persist_and_invalid_journal_rejected(self):
        self.observer.collector = Mock(side_effect=p.PolicyError('private-secret'))
        self.observer.worker_run(self.observer.generation)
        report = self.tick(); self.assertIsNone(report['fault_detail'])
        self.assertNotIn('private-secret', json.dumps(report))
        state = self.store.read(self.plan['id'], 'service')
        # Old journal remains valid without detail.
        s.Observer(self.plan, self.pf, self.store, self.messages.append)
        for detail in ['private-secret', [], {'secret': 'x'}]:
            self.store.write(self.plan['id'], 'service', dict(state, fault_detail=detail))
            with self.assertRaisesRegex(g.GuardError, 'service_state_invalid'):
                s.Observer(self.plan, self.pf, self.store, self.messages.append)
        self.store.write(self.plan['id'], 'service', state)

    def candidate(self, error=None, generation=None):
        sample = dns_policy()
        value = {'version': 1, 'plan_sha256': p.fingerprint(self.plan), 'policy': sample,
                 'expires_at': p.same_destinations(self.plan['policy'], sample)['expires_at'],
                 'proxy_checked_at': time.time(), 'sample_seconds': 4.0}
        ticket = self.observer.cycle.ticket if self.observer.cycle is not None else self.observer.generation
        self.observer.results.put((generation or ticket, value, error))

    def request(self):
        self.store.write(self.plan['id'], 'recheck', {'plan_sha256': p.fingerprint(self.plan),
                                                   'request': uuid.uuid4().hex})
        self.tick()

    def test_initial_requires_fresh_network_then_preserves_plan(self):
        self.assertEqual(self.tick()['status'], 'checking')
        self.candidate()
        self.assertEqual(self.tick()['status'], 'observed')
        self.assertEqual(self.store.read(self.plan['id'], 'plan'), self.plan)
        self.assertEqual(self.store.read(self.plan['id'], 'renewal')['plan_sha256'], p.fingerprint(self.plan))

    def test_fault_remains_until_successful_manual_attempt(self):
        self.candidate(error='proxy_exit_mismatch')
        self.assertEqual(self.tick()['status'], 'fault')
        self.candidate()
        self.assertEqual(self.tick()['status'], 'fault')
        self.request(); self.candidate()
        self.assertEqual(self.tick()['status'], 'observed')

    def test_failed_manual_attempt_not_cleared_by_later_automatic_sample(self):
        self.observer.latch('proxy_exit_mismatch')
        self.request(); self.candidate(error='proxy_probe_failed'); self.tick()
        self.assertFalse(self.observer.manual_pending)
        self.candidate()
        self.assertEqual(self.tick()['status'], 'fault')

    def test_automatic_empty_anchor_repair_still_latches(self):
        self.candidate(); self.tick()
        self.pf.own_rules = ''
        report = self.tick()
        self.assertEqual(self.pf.own_rules, self.plan['own_rules'])
        self.assertEqual(report['reason'], 'rules_missing_or_changed')
        self.assertTrue(report['manual_recheck_required'])

    def test_manual_request_waits_then_repairs_empty_anchor(self):
        self.pf.own_rules = ''
        self.tick(); self.request()
        self.assertTrue(self.observer.manual_pending)
        self.candidate()
        self.assertEqual(self.tick()['status'], 'observed')
        self.assertEqual(self.pf.own_rules, self.plan['own_rules'])

    def test_old_worker_timeout_does_not_cancel_new_request(self):
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        self.observer.worker_generation = self.observer.generation
        old = self.observer.generation
        self.observer.started = time.monotonic()-100
        self.request()
        self.assertTrue(self.observer.manual_pending)
        self.candidate(generation=old)
        self.tick()
        self.assertIsNone(self.observer.sample)
        self.assertTrue(self.observer.manual_pending)

    def test_current_worker_timeout_latches_and_invalidates_generation(self):
        old = self.observer.generation
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        self.observer.worker_generation = old
        self.observer.started = time.monotonic()-46
        self.assertEqual(self.tick()['reason'], 'network_check_timeout')
        self.candidate(generation=old)
        self.assertEqual(self.tick()['status'], 'fault')

    def test_restart_latches_until_new_request(self):
        self.candidate(); self.tick()
        self.observer = s.Observer(self.plan, self.pf, self.store, self.messages.append)
        self.observer.next_sample = float('inf')
        self.candidate()
        self.assertEqual(self.tick()['reason'], 'service_restarted')
        self.request(); self.candidate()
        self.assertEqual(self.tick()['status'], 'observed')

    def test_stale_proxy_sample_fails(self):
        self.candidate(); self.tick()
        self.observer.sample['proxy_checked_at'] -= 46
        self.assertEqual(self.tick()['reason'], 'evidence_expired')

    def test_expired_query_evidence_latches_even_with_fresh_proxy(self):
        self.candidate(); self.tick()
        self.observer.sample['policy']['queries'][0]['expires_at'] = time.time()-1
        self.assertEqual(self.tick()['reason'], 'evidence_expired')

    def test_manual_pf_exception_consumes_attempt(self):
        self.observer.latch('proxy_exit_mismatch')
        self.request(); self.candidate()
        with patch.object(self.pf, 'own', side_effect=g.GuardError('pfctl_rejected')):
            self.tick()
        self.assertFalse(self.observer.manual_pending)
        self.candidate()
        self.assertEqual(self.tick()['status'], 'fault')

    def test_short_ttl_schedules_renewal_before_expiry(self):
        self.candidate()
        generation, candidate, error = self.observer.results.get_nowait()
        for entry in candidate['policy']['entries'] + candidate['policy']['queries']:
            entry['expires_at'] = time.time()+20
        candidate['expires_at'] = p.same_destinations(self.plan['policy'], candidate['policy'])['expires_at']
        self.observer.results.put((generation, candidate, error))
        self.tick()
        # Less than the reserved budget remains: start renewal immediately.
        self.observer.worker.start.assert_called_once_with()

    def test_proxy_deadline_limits_public_report_and_next_sample(self):
        self.candidate()
        generation, candidate, error = self.observer.results.get_nowait()
        candidate['proxy_checked_at'] -= 25
        candidate['sample_seconds'] = 25.0
        self.observer.results.put((generation, candidate, error))
        # Keep a worker alive so the immediate-renewal deadline is inspectable.
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        report = self.tick()
        self.assertEqual(report['status'], 'observed')
        self.assertEqual(report['evidence_expires_at'], candidate['proxy_checked_at'] + 45)
        self.assertLessEqual(self.observer.next_sample, time.monotonic())

    def test_invalid_sample_duration_never_persisted(self):
        for duration in (float('nan'), float('inf'), -1, 46, True, None):
            self.candidate()
            generation, candidate, error = self.observer.results.get_nowait()
            candidate['sample_seconds'] = duration
            self.observer.results.put((generation, candidate, error))
            self.assertEqual(self.tick()['status'], 'fault')
            with self.assertRaises(FileNotFoundError):
                self.store.read(self.plan['id'], 'renewal')

    def test_expiry_during_pf_check_cannot_clear_manual_fault(self):
        self.observer.latch('service_stopped')
        self.request(); self.candidate()
        future = time.time() + 46
        original = s.watch_once
        clock = patch.object(s.time, 'time', return_value=future)
        def slow_check(*args, **kwargs):
            result = original(*args, **kwargs)
            clock.start()
            return result
        try:
            with patch.object(s, 'watch_once', side_effect=slow_check):
                self.assertEqual(self.tick()['status'], 'fault')
            self.assertEqual(self.observer.state['fault'], 'service_stopped')
        finally:
            clock.stop()

    def test_pf_check_delay_reports_expiry_without_marking_rules_missing(self):
        self.candidate()
        future = time.time() + 46
        original = s.watch_once
        clock = patch.object(s.time, 'time', return_value=future)
        def slow_check(*args, **kwargs):
            result = original(*args, **kwargs)
            clock.start()
            return result
        try:
            with patch.object(s, 'watch_once', side_effect=slow_check):
                report = self.tick()
            self.assertEqual(report['reason'], 'evidence_expired')
            self.assertTrue(report['rules_observed'])
        finally:
            clock.stop()

    def test_multiple_slow_fast_cycles_finish_before_prior_deadlines(self):
        # Drive the real tick logic with simulated network completion and 3s ticks.
        base = time.time()
        current = [base]
        mono_base = time.monotonic()
        def monotonic():
            return mono_base + current[0] - base
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        with patch.object(s.time, 'time', side_effect=lambda: current[0]), \
                patch.object(s.time, 'monotonic', side_effect=monotonic):
            previous_deadline = None
            for duration in (23, 4, 18, 5, 9, 3):
                started = current[0]
                policy = dns_policy()
                while current[0] < started + duration:
                    current[0] = min(started + duration, current[0] + 3)
                    if previous_deadline is not None:
                        self.assertLess(current[0], previous_deadline)
                        self.assertEqual(self.tick()['status'], 'observed')
                for query in policy['queries']:
                    query['completed_at'] = current[0]
                self.observer.results.put((self.observer.generation, {
                    'version': 1, 'plan_sha256': self.observer.binding, 'policy': policy,
                    'expires_at': p.dns_evidence(policy)[1]['expires_at'],
                    'proxy_checked_at': started, 'sample_seconds': duration}, None))
                self.assertEqual(self.tick()['status'], 'observed')
                deadline = self.messages[-1]['evidence_expires_at']
                previous_deadline = deadline
                scheduled = self.observer.next_sample
                while monotonic() < scheduled:
                    current[0] += 3
                    self.assertEqual(self.tick()['status'], 'observed')
                self.assertLess(current[0], deadline)
                # Emulate worker start; tick itself normally sets this ceiling.
                self.observer.next_sample = monotonic() + 30
            current[0] += 46
            self.assertEqual(self.tick()['reason'], 'evidence_expired')

    def test_expiry_while_collection_in_flight_stays_latched_after_success(self):
        base = time.time()
        current = [base]
        self.observer.worker = Mock()
        self.observer.worker.is_alive.return_value = True
        with patch.object(s.time, 'time', side_effect=lambda: current[0]):
            self.candidate(); self.tick()
            current[0] += 24
            self.assertEqual(self.tick()['status'], 'observed')
            started = current[0]
            policy = dns_policy()
            for step in range(1, 9):
                current[0] = started + step * 3
                report = self.tick()
                self.assertEqual(report['status'], 'observed' if current[0] < base + 45 else 'fault')
            self.observer.results.put((self.observer.generation, {
                'version': 1, 'plan_sha256': self.observer.binding, 'policy': policy,
                'expires_at': p.dns_evidence(policy)[1]['expires_at'],
                'proxy_checked_at': started, 'sample_seconds': 24}, None))
            self.assertEqual(self.tick()['reason'], 'evidence_expired')
            self.assertTrue(self.messages[-1]['manual_recheck_required'])

    def test_restored_plan_never_repaired_or_observed(self):
        with self.store.lock():
            g.recover(self.plan, self.pf, self.store)
        mutations = list(self.pf.mutations)
        self.request(); self.candidate()
        self.assertEqual(self.tick()['status'], 'fault')
        self.assertEqual(self.pf.mutations, mutations)

    def test_foreign_rules_not_overwritten_and_manual_attempt_consumed(self):
        self.pf.own_rules = 'block out from any to 1.1.1.1'
        self.request(); self.candidate()
        self.assertEqual(self.tick()['status'], 'fault')
        self.assertFalse(self.observer.manual_pending)
        self.assertEqual(self.pf.own_rules, 'block out from any to 1.1.1.1')


class PublicFileTests(unittest.TestCase):
    def test_safe_read_rejects_symlink_hardlink_and_writable_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root/'status.json'
            s.atomic(path, b'{}', 0o644)
            self.assertEqual(s.safe_read(path, owner=os.geteuid()), b'{}')
            link = root/'link'; link.symlink_to(path)
            with self.assertRaises(OSError):
                s.safe_read(link, owner=os.geteuid())
            os.link(path, root/'hardlink')
            with self.assertRaises(g.GuardError):
                s.safe_read(path, owner=os.geteuid())
            other = root/'writable'; other.write_bytes(b'{}'); other.chmod(0o666)
            with self.assertRaises(g.GuardError):
                s.safe_read(other, owner=os.geteuid())


class StartupTests(unittest.TestCase):
    def store(self, errors):
        store = Mock()
        @contextmanager
        def acquire():
            outcome = errors.pop(0) if errors else None
            if outcome:
                raise g.GuardError(outcome)
            yield
        store.lock.side_effect = acquire
        return store

    def test_contention_retries_but_body_failures_do_not(self):
        store = self.store(['guard_operation_in_progress', None])
        with patch.object(s.time, 'sleep') as sleep:
            with self.assertRaisesRegex(g.GuardError, 'body_failure'):
                with s.startup_lock(store):
                    raise g.GuardError('body_failure')
        self.assertEqual(store.lock.call_count, 2)
        sleep.assert_called_once_with(0.2)

    def test_unknown_error_and_retry_limit_stop(self):
        for errors, reason, calls in [(['unsafe_journal_directory'], 'unsafe_journal_directory', 1),
                                     (['guard_operation_in_progress']*3, 'startup_lock_timeout', 3)]:
            store = self.store(errors)
            with patch.object(s.time, 'sleep'), self.assertRaisesRegex(g.GuardError, reason):
                with s.startup_lock(store, attempts=3):
                    self.fail('must not initialize')
            self.assertEqual(store.lock.call_count, calls)


if __name__ == '__main__':
    unittest.main()
