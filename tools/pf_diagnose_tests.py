"""Read-only diagnostic contract; no real network or administrator access."""
import io
import json
import threading
import time
import unittest
from contextlib import redirect_stdout, redirect_stderr
from unittest.mock import patch

import pf_diagnose as d
import pf_policy as p


def query(host, kind, expiry=None):
    now = time.time()
    return {'host': host, 'type': kind, 'addresses': 1,
            'observed_at': now - 2, 'completed_at': now - 1,
            'expires_at': now + 60 if expiry is None else expiry}


class DiagnosticToolTests(unittest.TestCase):
    def test_invalid_options_never_reach_network(self):
        with patch.object(d, 'sample_round') as sample:
            for samples, interval in ((0, 0), (6, 0), (True, 1), (1, -1), (1, 31), (1, False)):
                with self.assertRaises(ValueError):
                    d.diagnose(samples, interval)
            sample.assert_not_called()
        with patch.object(d, 'diagnose') as diagnose, redirect_stderr(io.StringIO()):
            for args in (['--samples', '6'], ['--samples', 'secret'], ['--interval', '31']):
                with self.assertRaises(SystemExit):
                    d.main(args)
            diagnose.assert_not_called()

    def test_queries_overlap_and_raw_responses_never_reach_report(self):
        barrier = threading.Barrier(10, timeout=3)
        def transport(port, host, kind):
            self.assertEqual(port, 1082)
            barrier.wait()
            record = query(host, kind)
            record['secret'] = 'cookie-secret'
            return [{'cidr': '160.79.104.10/32', 'secret': 'token-secret'}], record
        with patch.object(d, 'discover_query', side_effect=transport):
            report = d.diagnose()
        self.assertEqual(report['summary']['returned_with_remaining_lifetime'], 10)
        self.assertEqual(len(report['observations'][0]['queries']), 10)
        text = json.dumps(report, allow_nan=False)
        for value in ('cookie-secret', 'token-secret', '160.79.104.10'):
            self.assertNotIn(value, text)
        self.assertFalse(report['pf_modified'])
        self.assertFalse(report['launch_authorized'])
        self.assertFalse(report['protection_verified'])

    def test_failed_query_keeps_other_slots_and_fixed_reason(self):
        def transport(port, host, kind):
            if host == p.HOSTS[0] and kind == 1:
                raise RuntimeError('private-response-secret')
            return [], query(host, kind)
        with patch.object(d, 'discover_query', side_effect=transport):
            report = d.diagnose()
        self.assertEqual(report['summary']['query_failed'], 1)
        self.assertEqual(report['summary']['returned_with_remaining_lifetime'], 9)
        self.assertNotIn('private-response-secret', json.dumps(report))

    def test_query_expiry_and_batch_expiry_are_distinct(self):
        def transport(port, host, kind):
            if host == p.HOSTS[0] and kind == 1:
                error = p.PolicyError('destination_evidence_expired')
                error.diagnostic = {'phase': 'query_return', 'evidence_kind': 'dns',
                                    'remaining_seconds': -0.5, 'secret': 'private'}
                raise error
            return [], query(host, kind, expiry=time.time() - 0.5)
        with patch.object(d, 'discover_query', side_effect=transport):
            report = d.diagnose()
        self.assertEqual(report['summary']['query_expired'], 1)
        self.assertEqual(report['summary']['batch_expired'], 9)
        self.assertNotIn('private', json.dumps(report))

    def test_all_errors_still_produce_bounded_json_without_acceptance(self):
        with patch.object(d, 'discover_query', side_effect=p.PolicyError('secret')), \
                patch.object(d.time, 'sleep') as sleep, redirect_stdout(io.StringIO()) as output:
            self.assertEqual(d.main(['--samples', '2', '--interval', '3']), 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report['summary']['query_failed'], 20)
        self.assertFalse(report['launch_authorized'])
        self.assertNotIn('secret', output.getvalue())
        sleep.assert_called_once_with(3)


if __name__ == '__main__':
    unittest.main()
