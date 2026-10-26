"""Renewal continuity and bounded resampling; no real PF or external traffic."""
import copy
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import pf_service as service
import pf_policy as policy
import pf_service_tests as fixtures


class ContinuityTests(unittest.TestCase):
    setUp = fixtures.ObserverTests.setUp
    tick = fixtures.ObserverTests.tick
    candidate = fixtures.ObserverTests.candidate
    request = fixtures.ObserverTests.request

    def test_queued_fresh_candidate_cannot_hide_expired_previous_evidence(self):
        self.candidate()
        first = self.tick()
        saved = self.store.read(self.plan['id'], 'renewal')
        with patch.object(service.time, 'time', return_value=first['evidence_expires_at'] + 1):
            self.candidate()
            report = self.tick()
        self.assertEqual(report['reason'], 'evidence_expired')
        self.assertEqual(report['fault_diagnostic']['phase'], 'active_evidence')
        self.assertTrue(report['manual_recheck_required'])
        self.assertIsNone(self.observer.sample)
        self.assertEqual(self.store.read(self.plan['id'], 'renewal'), saved)
        self.assertIsNone(self.observer.published_deadline)

    def test_expired_previous_evidence_does_not_prevent_explicit_manual_recheck(self):
        self.candidate()
        first = self.tick()
        with patch.object(service.time, 'time', return_value=first['evidence_expires_at'] + 1):
            self.request()
            self.candidate()
            report = self.tick()
        self.assertEqual(report['status'], 'observed')
        self.assertFalse(report['manual_recheck_required'])
        self.assertEqual(self.observer.published_deadline, report['evidence_expires_at'])

    def prepare_short_previous(self):
        self.candidate()
        self.tick()
        self.candidate()
        now = time.time()
        for item in self.observer.sample['policy']['entries'] + self.observer.sample['policy']['queries']:
            item['expires_at'] = now + 1
        return now

    def test_pf_processing_cannot_bridge_expired_previous_evidence(self):
        now = self.prepare_short_previous()
        saved = self.store.read(self.plan['id'], 'renewal')
        original = service.watch_once
        with patch.object(service.time, 'time', return_value=now) as wall:
            def slow_pf(*args, **kwargs):
                result = original(*args, **kwargs)
                wall.return_value = now + 2
                return result
            with patch.object(service, 'watch_once', side_effect=slow_pf):
                report = self.tick()
        self.assertEqual(report['reason'], 'evidence_expired')
        self.assertEqual(report['fault_diagnostic']['phase'], 'active_evidence')
        self.assertEqual(self.store.read(self.plan['id'], 'renewal'), saved)
        self.assertIsNone(self.observer.sample)
        self.assertFalse(report['evidence_fresh'])

    def test_durable_write_cannot_bridge_expired_previous_evidence(self):
        now = self.prepare_short_previous()
        original = self.store.write
        with patch.object(service.time, 'time', return_value=now) as wall:
            def slow_write(plan_id, kind, value, **kwargs):
                original(plan_id, kind, value, **kwargs)
                if kind == 'renewal':
                    wall.return_value = now + 2
            with patch.object(self.store, 'write', side_effect=slow_write):
                report = self.tick()
        self.assertEqual(report['reason'], 'evidence_expired')
        self.assertEqual(report['fault_diagnostic']['phase'], 'active_evidence')
        self.assertIsNone(self.observer.sample)
        self.assertIsNone(self.observer.published_deadline)
        # The candidate was durably saved, but is NOT an accepted/published renewal.
        self.assertGreater(policy.dns_evidence(self.store.read(self.plan['id'], 'renewal')['policy'])[1]['expires_at'], now+2)

    def test_manual_fault_not_cleared_when_candidate_expires_during_write(self):
        self.observer.latch('proxy_exit_mismatch')
        fault_at = self.observer.state['fault_at']
        self.request()
        self.candidate()
        generation, candidate, error = self.observer.results.get_nowait()
        now = time.time()
        for item in candidate['policy']['entries'] + candidate['policy']['queries']:
            item['expires_at'] = now + 1
        self.observer.results.put((generation, candidate, error))
        original = self.store.write
        with patch.object(service.time, 'time', return_value=now) as wall:
            def slow_write(plan_id, kind, value, **kwargs):
                original(plan_id, kind, value, **kwargs)
                if kind == 'renewal':
                    wall.return_value = now + 2
            with patch.object(self.store, 'write', side_effect=slow_write):
                report = self.tick()
        self.assertEqual(report['reason'], 'proxy_exit_mismatch')
        self.assertEqual(self.observer.state['fault_at'], fault_at)
        self.assertFalse(report['evidence_fresh'])
        self.assertTrue(self.observer.manual_pending)
        self.assertEqual(self.observer.cycle.ticket.attempt, 2)
        self.assertIsNone(self.observer.sample)

    def test_loop_wait_stops_at_evidence_deadline_without_minimum_overshoot(self):
        store = Mock()
        store.lock.return_value.__enter__ = Mock()
        store.lock.return_value.__exit__ = Mock(return_value=False)
        for deadline, expected in ((100.01, .01), (100, 0), (99, 0), (110, 3)):
            observer = Mock(closed=False, published_deadline=deadline)
            with patch.object(service.time, 'time', return_value=100), \
                    patch.object(service.time, 'monotonic', return_value=10):
                service.run_iteration(observer, store)
            self.assertAlmostEqual(observer.wake.wait.call_args.args[0], expected)


class ResamplingTests(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.plan = {'policy': fixtures.dns_policy()}

    def round(self, expired=False):
        value = copy.deepcopy(self.plan['policy'])
        for entry in value['entries'] + value['queries']:
            entry.update(observed_at=self.now-5, expires_at=self.now-1 if expired else self.now+60)
        for query in value['queries']:
            query['completed_at'] = self.now
        return value, self.now, self.now

    def test_only_full_same_address_expiry_gets_one_new_batch(self):
        old, fresh = self.round(True), self.round()
        with patch.object(service, 'collect_round', side_effect=[old, fresh]) as collect:
            result = service.collect(self.plan)
        self.assertEqual(collect.call_count, 2)
        self.assertIs(result['policy'], fresh[0])
        self.assertEqual(result['expires_at'], self.now+60)
        self.assertEqual(result['dns_attempts'], 2)
        self.assertEqual(result['prior_expiry']['phase'], 'query_return')

    def test_fresh_sample_needs_only_one_batch(self):
        with patch.object(service, 'collect_round', return_value=self.round()) as collect:
            result = service.collect(self.plan)
        self.assertEqual(collect.call_count, 1)
        self.assertEqual(result['dns_attempts'], 1)
        self.assertIsNone(result['prior_expiry'])

    def test_expired_changed_address_never_hidden_by_fresh_retry(self):
        old = self.round(True)
        old[0]['entries'][0]['cidr'] = '1.1.1.1/32'
        with patch.object(service, 'collect_round', side_effect=[old, self.round()]) as collect:
            with self.assertRaisesRegex(policy.PolicyError, 'address_or_proxy_policy_changed'):
                service.collect(self.plan)
        self.assertEqual(collect.call_count, 1)

    def test_expired_malformed_or_incomplete_sample_is_never_retried(self):
        mutations = [lambda v: v['queries'].pop(),
                     lambda v: v['queries'][0].update(completed_at=float('nan')),
                     lambda v: v['queries'][0].update(completed_at=self.now-10),
                     lambda v: v['queries'][0].update(observed_at=self.now+10),
                     lambda v: v['queries'][0].update(addresses=0),
                     lambda v: v.update(proxy_port=1083)]
        for mutate in mutations:
            old = self.round(True); mutate(old[0])
            with patch.object(service, 'collect_round', return_value=old) as collect:
                with self.assertRaises(policy.PolicyError):
                    service.collect(self.plan)
            self.assertEqual(collect.call_count, 1)

    def test_two_expired_batches_fail_without_third_attempt(self):
        with patch.object(service, 'collect_round', return_value=self.round(True)) as collect:
            with self.assertRaises(policy.PolicyError):
                service.collect(self.plan)
        self.assertEqual(collect.call_count, 2)

    def test_exit_and_transport_errors_are_never_retried(self):
        for error in (service.GuardError('proxy_exit_mismatch'),
                      service.GuardError('proxy_probe_failed'), policy.PolicyError('proxy_doh_timeout')):
            with patch.object(service, 'collect_round', side_effect=error) as collect:
                with self.assertRaises(type(error)):
                    service.collect(self.plan)
            self.assertEqual(collect.call_count, 1)

    def test_budget_exhaustion_does_not_start_another_batch(self):
        with patch.object(service, 'collect_round', return_value=self.round(True)) as collect, \
                patch.object(service.time, 'monotonic', side_effect=[0, 30]):
            with self.assertRaises(policy.PolicyError):
                service.collect(self.plan)
        self.assertEqual(collect.call_count, 1)

    def test_attempt_metadata_cannot_include_remote_text(self):
        for bad in ({'dns_attempts': True}, {'dns_attempts': 3},
                    {'dns_attempts': 1, 'prior_expiry': {}},
                    {'dns_attempts': 2, 'prior_expiry': {'phase': 'query_return', 'evidence_kind': 'dns', 'body': 'secret'}}):
            with self.assertRaises(service.GuardError):
                service.sampling_diagnostic(bad)

    def test_future_entry_is_rejected_independently_of_valid_query_times(self):
        sample = copy.deepcopy(self.plan['policy'])
        sample['entries'][0].update(observed_at=self.now+10, expires_at=self.now+20)
        policy.validate(sample, fresh=False)  # Historical rule recovery is independent.
        with self.assertRaisesRegex(policy.PolicyError, 'invalid_evidence_interval'):
            policy.dns_evidence(sample, fresh=False)


class DiscoveryPipelineTests(unittest.TestCase):
    """Exercise HTTP parsing, raw collection, comparison and retry together."""

    def run_pipeline(self, changed):
        counts, lock = {}, threading.Lock()

        def response(command):
            params = parse_qs(urlsplit(command[-1]).query)
            host, kind = params['name'][0], int(params['type'][0])
            key = (host, kind)
            with lock:
                counts[key] = counts.get(key, 0) + 1
                attempt = counts[key]
            ttl, age = (1, 2) if attempt == 1 else (60, 0)
            address = '160.79.104.10' if kind == 1 else '2607:6bc0::10'
            # The changed answer exists only in the expired first batch. If an
            # improper retry hides it, the otherwise matching second batch passes.
            if changed and attempt == 1 and key == (policy.HOSTS[0], 1):
                address = '1.1.1.1'
            body = {'Status': 0, 'TC': False,
                    'Question': [{'name': host+'.', 'type': kind}],
                    'Answer': [{'name': host+'.', 'type': kind, 'TTL': ttl, 'data': address}]}
            return (b'HTTP/2 200\r\nContent-Type: application/json\r\nAge: ' +
                    str(age).encode() + b'\r\n\r\n' + json.dumps(body).encode())

        with patch.object(policy.time, 'time', return_value=1000):
            plan = {'policy': fixtures.dns_policy()}
            with patch.object(policy, 'bounded_http_request', side_effect=response), \
                    patch.object(service, 'probe_exit', return_value=1000):
                if changed:
                    with self.assertRaisesRegex(policy.PolicyError, 'address_or_proxy_policy_changed'):
                        service.collect(plan)
                    result = None
                else:
                    result = service.collect(plan)
        self.assertEqual(set(counts), {(host, kind) for host in policy.HOSTS for kind in (1, 28)})
        return result, counts

    def test_full_raw_batch_retains_expired_answers_and_retries_once(self):
        result, counts = self.run_pipeline(changed=False)
        self.assertEqual(set(counts.values()), {2})
        self.assertEqual(result['dns_attempts'], 2)
        self.assertEqual(result['expires_at'], 1060)
        self.assertEqual(result['prior_expiry']['phase'], 'query_return')
        self.assertEqual(result['prior_expiry']['http_age_seconds'], 2)

    def test_expired_changed_answer_cannot_be_hidden_by_retry(self):
        _, counts = self.run_pipeline(changed=True)
        self.assertEqual(set(counts.values()), {1})


if __name__ == '__main__':
    unittest.main()
