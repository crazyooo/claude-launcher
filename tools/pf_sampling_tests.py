"""Exercise bounded production sampling with synchronized fake transports."""
import json
import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import pf_policy as p
import pf_service as s
from pf_service_tests import dns_policy


class SamplingTests(unittest.TestCase):
    def test_all_dns_queries_overlap_and_retain_owner_order(self):
        barrier = threading.Barrier(10, timeout=3)
        requests = []
        lock = threading.Lock()
        def request(command, **kwargs):
            query = parse_qs(urlparse(command[-1]).query)
            host, kind = query['name'][0], int(query['type'][0])
            with lock:
                requests.append((host, kind, time.time()))
            self.assertEqual(command[command.index('--proxy') + 1], 'http://127.0.0.1:1082')
            self.assertIn('--include', command)
            self.assertIn('--suppress-connect-headers', command)
            self.assertNotIn('--location', command)
            barrier.wait()
            body = {'Status': 0, 'TC': False, 'Question': [{'name': host+'.', 'type': kind}],
                    'Answer': [{'name': host+'.', 'type': kind, 'TTL': 60,
                                'data': '160.79.104.10' if kind == 1 else '2607:6bc0::10'}]}
            return b'HTTP/2 200\r\nContent-Type: application/json\r\n\r\n' + json.dumps(body).encode()
        with patch.object(p, 'bounded_http_request', side_effect=request):
            result = p.discover()
        self.assertEqual([(q['host'], q['type']) for q in result['queries']],
                         [(host, kind) for host in p.HOSTS for kind in (1, 28)])
        starts = {(host, kind): stamp for host, kind, stamp in requests}
        for query in result['queries']:
            self.assertLessEqual(query['observed_at'], starts[query['host'], query['type']])
            self.assertEqual(query['expires_at'], query['observed_at'] + 60)

    def test_failed_query_prevents_partial_policy(self):
        with patch.object(p, 'bounded_http_request', side_effect=p.PolicyError('proxy_doh_failed')):
            with self.assertRaisesRegex(p.PolicyError, 'proxy_doh_failed'):
                p.discover()

    def test_batch_rejects_expired_early_answer(self):
        policy = dns_policy()
        def query(port, host, kind):
            index = [(h, k) for h in p.HOSTS for k in (1, 28)].index((host, kind))
            entry, evidence = policy['entries'][index], policy['queries'][index]
            if index == 0:
                entry['expires_at'] = time.time() - 0.1
            return [entry], evidence
        with patch.object(p, 'discover_query', side_effect=query):
            with self.assertRaisesRegex(p.PolicyError, 'destination_evidence_expired'):
                p.discover()

    def test_discovery_and_both_traces_overlap_with_earliest_trace_time(self):
        barrier = threading.Barrier(3, timeout=3)
        policy = dns_policy()
        observed = []
        def discover(original):
            barrier.wait()
            return policy, time.time()
        def request(command, **kwargs):
            observed.append(time.time())
            barrier.wait()
            return SimpleNamespace(returncode=0, stdout=b'ip=203.0.113.43\n')
        with patch.object(s, 'discover_for_plan', side_effect=discover), \
                patch.object(s.subprocess, 'run', side_effect=request):
            result = s.collect({'policy': policy})
        self.assertLessEqual(result['proxy_checked_at'], min(observed))
        self.assertGreaterEqual(result['sample_seconds'], 0)
        self.assertEqual(result['expires_at'], p.dns_evidence(policy)[1]['expires_at'])

    def test_wrong_exit_never_yields_complete_sample(self):
        policy = dns_policy()
        with patch.object(s, 'discover_for_plan', return_value=(policy, time.time())), \
                patch.object(s.subprocess, 'run', return_value=SimpleNamespace(
                    returncode=0, stdout=b'ip=1.1.1.1\n')):
            with self.assertRaisesRegex(s.GuardError, 'proxy_exit_mismatch'):
                s.collect({'policy': policy})


if __name__ == '__main__':
    unittest.main()
