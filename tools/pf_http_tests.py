"""HTTP cache framing, timing and real bounded child processes; no networking."""
import copy
import io
import json
import subprocess
import sys
import time
import unittest
from unittest.mock import Mock, patch

import pf_policy as policy
from pf_service_tests import dns_policy


def wire(body=b'{}', headers=b'', status=b'HTTP/2 200'):
    return status + b'\r\nContent-Type: application/json\r\n' + headers + b'\r\n' + body


class HeaderTests(unittest.TestCase):
    def test_only_final_response_age_counts(self):
        response = b'HTTP/1.1 103 Early Hints\r\nAge: 100\r\n\r\n' + wire(headers=b'Age: 20\r\n')
        self.assertEqual(policy.decode_doh_http(response), (b'{}', 20))
        self.assertEqual(policy.decode_doh_http(wire()), (b'{}', 0))

    def test_bad_or_duplicate_age_is_rejected_without_raw_content(self):
        for age in (b'-1', b'+1', b'1, 2', b'', b'2147483649', b'9999999999999', b'1\x00secret'):
            with self.assertRaises(policy.PolicyError) as caught:
                policy.decode_doh_http(wire(headers=b'Age: '+age+b'\r\n'))
            self.assertNotIn('secret', str(caught.exception))
        with self.assertRaisesRegex(policy.PolicyError, 'age_invalid'):
            policy.decode_doh_http(wire(headers=b'Age: 1\r\naGE: 2\r\n'))

    def test_proxy_handshake_redirect_and_informational_overflow_are_rejected(self):
        responses = [b'HTTP/1.1 200 Connection established\r\nAge: 999\r\n\r\n'+wire(),
                     wire(status=b'HTTP/2 301'), wire(status=b'HTTP/2 304'),
                     wire(status=b'HTTP/1.1 101 Switching Protocols'),
                     b'HTTP/2 103\r\n\r\n'*5+wire(),
                     b'HTTP/2 200\r\n\r\n{}',
                     wire(headers=b' Content-Type: application/json\r\n'),
                     wire(headers=b'Content-Type: application/json\r\n'),
                     wire(headers=b'Content-Encoding: gzip\r\n')]
        for response in responses:
            with self.assertRaises(policy.PolicyError):
                policy.decode_doh_http(response)

    def test_headers_and_body_have_independent_and_combined_limits(self):
        for response in (wire(headers=b'X-Fill: '+b'x'*policy.MAX_HTTP_HEADERS+b'\r\n'),
                         wire(body=b'x'*(policy.MAX_DOH_BODY+1)), b'x'*(policy.MAX_DOH_WIRE+1)):
            with self.assertRaisesRegex(policy.PolicyError, 'too_large'):
                policy.decode_doh_http(response)


class CacheTimingTests(unittest.TestCase):
    def response(self, ttl=60, age=20):
        host = policy.HOSTS[0]
        body = {'Status': 0, 'TC': False, 'Question': [{'name': host+'.', 'type': 1}],
                'Answer': [{'name': host+'.', 'type': 1, 'TTL': ttl, 'data': '160.79.104.10'}]}
        return wire(json.dumps(body).encode(), ('Age: '+str(age)+'\r\n').encode())

    def test_cache_age_reduces_lifetime_without_inflating_request_duration(self):
        with patch.object(policy, 'bounded_http_request', return_value=self.response()), \
                patch.object(policy.time, 'time', side_effect=[100, 102, 102]):
            entries, query = policy.discover_query(1082, policy.HOSTS[0], 1)
            timing = policy.timing_diagnostic({'queries': [query]}, 'query_return')
        self.assertEqual(query['observed_at'], 80)
        self.assertEqual(query['request_started_at'], 100)
        self.assertEqual(entries[0]['expires_at'], 140)
        self.assertEqual(timing['remaining_seconds'], 38)
        self.assertEqual(timing['request_seconds'], 2)
        self.assertEqual(timing['http_age_seconds'], 20)

    def test_stale_cache_retains_raw_address_but_strict_interface_refuses(self):
        with patch.object(policy, 'bounded_http_request', return_value=self.response(ttl=1, age=20)), \
                patch.object(policy.time, 'time', side_effect=[100, 102]):
            entries, query = policy._discover_query_raw(1082, policy.HOSTS[0], 1)
        self.assertEqual(entries[0]['cidr'], '160.79.104.10/32')
        self.assertLess(query['expires_at'], query['request_started_at'])
        with patch.object(policy, 'bounded_http_request', return_value=self.response(ttl=1, age=20)), \
                patch.object(policy.time, 'time', side_effect=[100, 102, 102]):
            with self.assertRaisesRegex(policy.PolicyError, 'destination_evidence_expired'):
                policy.discover_query(1082, policy.HOSTS[0], 1)

    def test_legacy_queries_work_but_partial_or_inconsistent_cache_metadata_never_does(self):
        original = dns_policy()
        self.assertEqual(len(policy.dns_evidence(original, fresh=False)[0]), 10)
        changes = [{'http_age_seconds': 0}, {'request_started_at': time.time()},
                   {'http_age_seconds': True, 'request_started_at': 100},
                   {'http_age_seconds': -1, 'request_started_at': 100},
                   {'http_age_seconds': 1.5, 'request_started_at': 100},
                   {'http_age_seconds': 0, 'request_started_at': float('nan')},
                   {'http_age_seconds': 20, 'request_started_at': original['queries'][0]['observed_at']},
                   {'http_age_seconds': 20, 'request_started_at': original['queries'][0]['observed_at']+20}]
        for change in changes:
            sample = copy.deepcopy(original); sample['queries'][0].update(change)
            with self.assertRaises(policy.PolicyError):
                policy.dns_evidence(sample, fresh=False)

    def test_json_tail_and_non_utf8_are_rejected(self):
        for body in (b'{} HTTP/2 200', b'\xff'):
            with patch.object(policy, 'bounded_http_request', return_value=wire(body)):
                with self.assertRaisesRegex(policy.PolicyError, 'json_invalid'):
                    policy.discover_query(1082, policy.HOSTS[0], 1)


class BoundedProcessTests(unittest.TestCase):
    def invoke(self, source, **kwargs):
        return policy.bounded_http_request([sys.executable, '-c', source])

    def test_real_child_output_and_clean_environment(self):
        source = 'import os,sys;sys.stdout.write(os.environ["PATH"]+"|"+os.environ["LC_ALL"])'
        self.assertEqual(self.invoke(source), b'/usr/bin:/bin|C')

    def test_real_exit_codes_are_fixed_and_stderr_is_not_exposed(self):
        for code, reason in ((7, 'connect_failed'), (22, 'http_failed'), (28, 'timeout'),
                             (60, 'tls_failed'), (63, 'too_large'), (99, 'failed')):
            with self.assertRaises(policy.PolicyError) as caught:
                self.invoke('import sys;sys.stderr.write("private-secret");sys.exit('+str(code)+')')
            self.assertEqual(str(caught.exception), 'proxy_doh_'+reason)

    def test_overflow_and_timeout_kill_and_reap_own_process(self):
        original = subprocess.Popen
        children = []
        def start(*args, **kwargs):
            child = original(*args, **kwargs); children.append(child); return child
        with patch.object(policy.subprocess, 'Popen', side_effect=start):
            with self.assertRaisesRegex(policy.PolicyError, 'too_large'):
                self.invoke('import sys,time;sys.stdout.buffer.write(b"x"*100000);sys.stdout.flush();time.sleep(30)')
            with patch.object(policy.selectors, 'DefaultSelector') as selector:
                selector.return_value.__enter__.return_value.select.return_value = []
                with self.assertRaisesRegex(policy.PolicyError, 'timeout'):
                    self.invoke('import time;time.sleep(30)')
        self.assertEqual(len(children), 2)
        self.assertTrue(all(child.poll() is not None and child.stdout.closed for child in children))

    def test_spawn_failure_is_sanitized(self):
        with patch.object(policy.subprocess, 'Popen', side_effect=OSError('private-secret')):
            with self.assertRaisesRegex(policy.PolicyError, '^proxy_doh_exec_failed$'):
                self.invoke('')

    def test_uncertain_cleanup_closes_pipe_and_returns_only_fixed_failure(self):
        for operation in ('kill', 'wait'):
            with self.subTest(operation=operation):
                child = Mock(stdout=io.BytesIO())
                child.poll.return_value = None
                failure = (OSError('private-command') if operation == 'kill' else
                           subprocess.TimeoutExpired(['private-command'], 2, output=b'private-body'))
                getattr(child, operation).side_effect = failure
                with patch.object(policy.subprocess, 'Popen', return_value=child), \
                        patch.object(policy.selectors, 'DefaultSelector') as selector:
                    selector.return_value.__enter__.return_value.select.return_value = []
                    with self.assertRaises(policy.PolicyError) as caught:
                        self.invoke('')
                self.assertEqual(str(caught.exception), 'proxy_doh_cleanup_failed')
                self.assertTrue(caught.exception.__suppress_context__)
                self.assertIn(str(caught.exception), policy.DNS_DIAGNOSTICS)
                self.assertTrue(child.stdout.closed)
                child.kill.assert_called_once()
                if operation == 'wait':
                    child.wait.assert_called_once_with(timeout=2)


if __name__ == '__main__':
    unittest.main()
