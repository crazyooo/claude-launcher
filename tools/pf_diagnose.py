#!/usr/bin/env python3
"""Read-only DNS timing through the confirmed HTTP 127.0.0.1:1082 proxy.

This tool neither reads accounts nor touches PF, launchd, proxy settings or clients.
It does not approve DNS destinations or determine protected-launch eligibility.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import time

from pf_policy import (DNS_DIAGNOSTICS, EXPIRY_CODES, HOSTS, PolicyError,
                       discover_query, safe_diagnostic, timing_diagnostic)

PROXY_PORT = 1082


def query_timing(host, record_type):
    started = time.monotonic()
    try:
        _, query = discover_query(PROXY_PORT, host, record_type)
        return query, None, timing_diagnostic({'queries': [query]}, 'query_return')
    except Exception as error:
        reason = str(error) if isinstance(error, PolicyError) else None
        if reason not in DNS_DIAGNOSTICS:
            reason = 'diagnostic_query_failed'
        timing = safe_diagnostic(getattr(error, 'diagnostic', None))
        if timing is None:
            timing = safe_diagnostic({'phase': 'query_return', 'evidence_kind': 'dns',
                                      'request_seconds': time.monotonic() - started})
        return None, reason, timing


def sample_round():
    started_at, started = time.time(), time.monotonic()
    jobs = [(host, kind) for host in HOSTS for kind in (1, 28)]
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = [pool.submit(query_timing, *job) for job in jobs]
        results = [future.result() for future in futures]
    rows = []
    for (host, kind), (query, reason, returned) in zip(jobs, results):
        batch_timing = timing_diagnostic({'queries': [query]}, 'dns_batch') if query else None
        if query is None:
            outcome = 'query_expired' if reason in EXPIRY_CODES else 'query_failed'
        elif batch_timing.get('remaining_seconds', 0) <= 0:
            outcome = 'batch_expired'
            reason = 'destination_evidence_expired' if query['addresses'] else 'query_evidence_expired_or_invalid'
        else:
            outcome, reason = 'returned_with_remaining_lifetime', None
        rows.append({'host': host, 'record_type': kind, 'outcome': outcome, 'reason': reason,
                     'query_return': safe_diagnostic(returned),
                     'batch_complete': safe_diagnostic(batch_timing)})
    return {'started_at': started_at, 'completed_at': time.time(),
            'duration_seconds': time.monotonic() - started, 'queries': rows}


def diagnose(samples=1, interval=2):
    if (type(samples) is not int or not 1 <= samples <= 5 or
            type(interval) is not int or not 0 <= interval <= 30):
        raise ValueError('invalid_sampling_options')
    observations = []
    for index in range(samples):
        if index:
            time.sleep(interval)
        observations.append(sample_round())
    outcomes = [query['outcome'] for sample in observations for query in sample['queries']]
    return {'version': 1, 'mode': 'readonly_dns_timing', 'proxy_port': PROXY_PORT,
            'observations': observations,
            'summary': {key: outcomes.count(key) for key in
                        ('returned_with_remaining_lifetime', 'query_expired', 'batch_expired', 'query_failed')},
            'scope': 'DNS timing only; no destination comparison, exit identity or client acceptance',
            'lifetime_note': 'CNAME/address lifetime starts at request start minus HTTP Age; '
                             'zero-answer lifetime is a local cap, not authoritative DNS TTL',
            'pf_modified': False, 'protection_verified': False, 'launch_authorized': False}


def bounded_integer(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError('integer_required') from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError('value_out_of_range')
        return number
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=bounded_integer(1, 5), default=1)
    parser.add_argument('--interval', type=bounded_integer(0, 30), default=2)
    args = parser.parse_args(argv)
    try:
        report = diagnose(args.samples, args.interval)
    except KeyboardInterrupt:
        print(json.dumps({'reason': 'sampling_interrupted', 'pf_modified': False,
                          'protection_verified': False, 'launch_authorized': False}))
        return 130
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
