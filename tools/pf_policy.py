#!/usr/bin/env python3
"""Generate a bounded destination policy; never changes PF or proxy settings."""
import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import selectors
import subprocess
import time

HOSTS = ('claude.ai', 'api.anthropic.com', 'platform.claude.com',
         'console.anthropic.com', 'files.claudeusercontent.com')
SCOPE = 'all processes to listed public destinations; DNS snapshot is incomplete coverage'


# Only these stable, non-secret codes may cross the observer boundary.
DNS_DIAGNOSTICS = frozenset({
    'proxy_doh_failed', 'proxy_doh_timeout', 'proxy_doh_connect_failed',
    'proxy_doh_tls_failed', 'proxy_doh_http_failed', 'proxy_doh_too_large',
    'proxy_doh_json_invalid', 'proxy_doh_exec_failed',
    'proxy_doh_headers_invalid', 'proxy_doh_age_invalid', 'proxy_doh_cleanup_failed',
    'dns_question_or_status_invalid', 'dns_answers_invalid', 'dns_cname_loop',
    'dns_owner_ambiguous', 'dns_ttl_invalid', 'dns_address_invalid',
    'dns_family_mismatch', 'dns_cname_invalid', 'dns_cname_too_deep',
    'destination_evidence_expired', 'query_evidence_expired_or_invalid',
    'incomplete_query_evidence', 'query_answer_count_mismatch',
    'unexpected_dns_source', 'renewal_requires_host_addresses', 'proxy_evidence_stale',
})
DOH_FAILURES = {5: 'connect_failed', 6: 'connect_failed', 7: 'connect_failed',
                22: 'http_failed', 28: 'timeout', 35: 'tls_failed',
                60: 'tls_failed', 63: 'too_large'}


class PolicyError(Exception):
    """Fixed public diagnostic, without raw remote response."""

    def __init__(self, code):
        super().__init__(code)
        self.diagnostic = None


EVIDENCE_PHASES = frozenset({'query_return', 'dns_batch', 'exit_wait',
                             'worker_queue', 'pf_check', 'active_evidence', 'publication'})
EXPIRY_CODES = frozenset({'destination_evidence_expired',
                          'query_evidence_expired_or_invalid', 'proxy_evidence_stale'})
TIMING_FIELDS = frozenset({'lifetime_seconds', 'request_seconds', 'remaining_seconds',
                           'age_seconds', 'checked_at', 'http_age_seconds'})


MAX_HTTP_HEADERS = 16 * 1024
MAX_DOH_BODY = 64 * 1024
MAX_DOH_WIRE = MAX_HTTP_HEADERS + MAX_DOH_BODY
MAX_HTTP_AGE = 2147483648
HTTP_STATUS = re.compile(rb'HTTP/(?:1\.0|1\.1|2|3) ([0-9]{3})(?: [^\r\n]*)?')
HEADER_NAME = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")


def safe_diagnostic(value):
    """Copy only fixed labels and finite timing numbers, never remote text."""
    if not isinstance(value, dict):
        return None
    phase, kind = value.get('phase'), value.get('evidence_kind')
    if (not isinstance(phase, str) or phase not in EVIDENCE_PHASES or
            not isinstance(kind, str) or kind not in ('dns', 'proxy')):
        return None
    result = {'phase': phase, 'evidence_kind': kind}
    for key in TIMING_FIELDS:
        number = value.get(key)
        if key == 'http_age_seconds':
            if type(number) is int and 0 <= number <= MAX_HTTP_AGE:
                result[key] = number
            continue
        bound = 100_000_000_000 if key == 'checked_at' else 86400
        if type(number) in (int, float) and math.isfinite(number) and -bound <= number <= bound:
            result[key] = number
    host, record_type = value.get('host'), value.get('record_type')
    if isinstance(host, str) and host in HOSTS and type(record_type) is int and record_type in (1, 28):
        result.update(host=host, record_type=record_type)
    return result


def timing_diagnostic(policy, phase, proxy_checked_at=None):
    """Earliest DNS deadline, or the independent proxy deadline, at rejection.

    This records where freshness was checked, not why an upstream returned a TTL.
    A zero-answer lifetime is our existing local observation cap, not a DNS TTL.
    """
    now = time.time()
    result = {'phase': phase, 'evidence_kind': 'dns', 'checked_at': now}
    if proxy_checked_at is not None:
        result['evidence_kind'] = 'proxy'
        if type(proxy_checked_at) in (int, float) and math.isfinite(proxy_checked_at):
            result.update(lifetime_seconds=45, age_seconds=now - proxy_checked_at,
                          remaining_seconds=proxy_checked_at + 45 - now)
        return safe_diagnostic(result)
    queries = policy.get('queries', []) if isinstance(policy, dict) else []
    candidates = []
    if isinstance(queries, list):
        for query in queries[:10]:
            if not isinstance(query, dict):
                continue
            observed, completed, expires = (query.get(key) for key in
                                             ('observed_at', 'completed_at', 'expires_at'))
            if (all(type(v) in (int, float) and math.isfinite(v) for v in (observed, completed, expires))
                    and observed <= completed and 0 < expires - observed <= 86400):
                candidates.append(query)
    if candidates:
        query = min(candidates, key=lambda q: q['expires_at'])
        result.update(host=query.get('host'), record_type=query.get('type'),
                      lifetime_seconds=query['expires_at'] - query['observed_at'],
                      age_seconds=now - query['observed_at'],
                      remaining_seconds=query['expires_at'] - now)
        requested = query.get('request_started_at', query['observed_at'])
        if type(requested) in (int, float) and math.isfinite(requested) and query['observed_at'] <= requested <= query['completed_at']:
            result['request_seconds'] = query['completed_at'] - requested
        result['http_age_seconds'] = query.get('http_age_seconds', 0)
    return safe_diagnostic(result)


@contextmanager
def evidence_phase(policy, phase):
    """Annotate expiry without changing the rejection or overwriting its origin."""
    try:
        yield
    except PolicyError as error:
        if str(error) in EXPIRY_CODES and error.diagnostic is None:
            error.diagnostic = timing_diagnostic(policy, phase)
        raise


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def validate(policy, now=None, fresh=True):
    now = time.time() if now is None else now
    if not isinstance(policy, dict) or policy.get('version') != 1:
        raise PolicyError('unsupported_policy')
    entries = policy.get('entries')
    if not isinstance(entries, list) or not 1 <= len(entries) <= 256:
        raise PolicyError('bounded_destination_list_required')
    exclusions = policy.get('transport_exclusions', [])
    if not isinstance(exclusions, list) or len(exclusions) > 64 or any(not isinstance(ip, str) for ip in exclusions):
        raise PolicyError('invalid_transport_exclusions')
    try:
        exclusions = [ipaddress.ip_address(ip) for ip in exclusions]
    except ValueError:
        raise PolicyError('invalid_transport_exclusions') from None
    networks = set()
    expiries = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise PolicyError('invalid_entry')
        try:
            network = ipaddress.ip_network(entry['cidr'], strict=True)
        except (ValueError, KeyError, TypeError):
            raise PolicyError('invalid_cidr') from None
        # Deliberately small explicit scope: do not expand a DNS answer to an ASN/CDN.
        if (network.prefixlen < (24 if network.version == 4 else 64) or
                not network.is_global or not network.network_address.is_global or
                not network.broadcast_address.is_global or network.is_multicast):
            raise PolicyError('nonpublic_or_overbroad_cidr')
        if any(ip in network for ip in exclusions):
            raise PolicyError('policy_overlaps_proxy_transport')
        if not isinstance(entry.get('source'), str) or not re.fullmatch(r'[A-Za-z0-9_. -]{1,100}', entry['source']):
            raise PolicyError('invalid_provenance_label')
        observed, expires = entry.get('observed_at'), entry.get('expires_at')
        if any(type(n) not in (int, float) or not math.isfinite(n) for n in (observed, expires)):
            raise PolicyError('invalid_evidence_time')
        # Recovery compiles historical rules without depending on the live clock.
        if (fresh and observed > now) or not observed < expires or expires - observed > 86400:
            raise PolicyError('invalid_evidence_interval')
        if fresh and expires <= now:
            raise PolicyError('destination_evidence_expired')
        networks.add(str(network))
        expiries.append(expires)
    lines = [f'block drop out quick {"inet6" if ":" in cidr else "inet"} from any to {cidr}'
             for cidr in sorted(networks)]
    return {'cidrs': sorted(networks), 'rules': '\n'.join(lines) + '\n',
            'observed_at': max(entry['observed_at'] for entry in entries),
            'expires_at': min(expiries), 'scope': SCOPE}


def parse_answer(body, host, kind, observed):
    if (not isinstance(body, dict) or body.get('Status') != 0 or body.get('TC') is not False or
            body.get('Question') != [{'name': host + '.', 'type': kind}]):
        raise PolicyError('dns_question_or_status_invalid')
    answers = body.get('Answer', [])
    if not isinstance(answers, list) or len(answers) > 64:
        raise PolicyError('dns_answers_invalid')
    # Follow only CNAMEs connected to the requested owner; ignore unrelated answers.
    owner, visited, lifetime = host, set(), 86400
    entries = []
    for _ in range(16):
        if owner in visited:
            raise PolicyError('dns_cname_loop')
        visited.add(owner)
        relevant = [a for a in answers if isinstance(a, dict) and
                    str(a.get('name', '')).rstrip('.').lower() == owner]
        aliases = [a for a in relevant if a.get('type') == 5]
        addresses = [a for a in relevant if a.get('type') == kind]
        if len(aliases) > 1 or (aliases and addresses):
            raise PolicyError('dns_owner_ambiguous')
        for record in aliases + addresses:
            ttl = record.get('TTL')
            if type(ttl) is not int or not 1 <= ttl <= 2147483647:
                raise PolicyError('dns_ttl_invalid')
        for record in addresses:
            try:
                address = ipaddress.ip_address(record['data'])
            except (ValueError, KeyError, TypeError):
                raise PolicyError('dns_address_invalid') from None
            if address.version != (4 if kind == 1 else 6):
                raise PolicyError('dns_family_mismatch')
            entries.append({'cidr': str(address) + ('/32' if kind == 1 else '/128'),
                            'source': 'dns.google ' + host,
                            'observed_at': observed,
                            'expires_at': observed + min(lifetime, record['TTL'], 86400)})
        if not aliases:
            return entries
        owner = str(aliases[0].get('data', '')).rstrip('.').lower()
        if not re.fullmatch(r'[a-z0-9.-]{1,253}', owner):
            raise PolicyError('dns_cname_invalid')
        lifetime = min(lifetime, aliases[0]['TTL'])
    raise PolicyError('dns_cname_too_deep')


def bounded_http_request(command):
    """Bound response output and reject failures, including uncertain cleanup."""
    process = None
    deadline = time.monotonic() + 14
    output = bytearray()
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise PolicyError('proxy_doh_timeout')
                part = os.read(process.stdout.fileno(), min(4096, MAX_DOH_WIRE + 1 - len(output)))
                if not part:
                    break
                output.extend(part)
                if len(output) > MAX_DOH_WIRE:
                    raise PolicyError('proxy_doh_too_large')
        code = process.wait(timeout=max(0, deadline - time.monotonic()))
        if code:
            raise PolicyError('proxy_doh_' + DOH_FAILURES.get(code, 'failed'))
        return bytes(output)
    except subprocess.TimeoutExpired:
        raise PolicyError('proxy_doh_timeout') from None
    except OSError:
        raise PolicyError('proxy_doh_exec_failed') from None
    finally:
        if process is not None:
            try:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=2)
                finally:
                    process.stdout.close()
            except (OSError, subprocess.TimeoutExpired):
                # Do not leak command/remote output through a cleanup traceback,
                # or claim this child was reaped when that could not be verified.
                raise PolicyError('proxy_doh_cleanup_failed') from None


def decode_doh_http(wire):
    """curl removes transfer framing and suppresses proxy CONNECT headers.

    Accept at most four informational blocks and one final 200 JSON response.
    Never search past an unexpected final response for a later usable body.
    """
    if not isinstance(wire, bytes) or len(wire) > MAX_DOH_WIRE:
        raise PolicyError('proxy_doh_too_large')
    offset = 0
    for _ in range(5):
        end = wire.find(b'\r\n\r\n', offset)
        if end < 0:
            raise PolicyError('proxy_doh_headers_invalid')
        body_start = end + 4
        if body_start > MAX_HTTP_HEADERS:
            raise PolicyError('proxy_doh_too_large')
        lines = wire[offset:end].split(b'\r\n')
        status = HTTP_STATUS.fullmatch(lines[0])
        if status is None:
            raise PolicyError('proxy_doh_headers_invalid')
        headers = {}
        for line in lines[1:]:
            name, separator, value = line.partition(b':')
            if (not separator or HEADER_NAME.fullmatch(name) is None or
                    any((byte < 32 and byte != 9) or byte == 127 for byte in value)):
                raise PolicyError('proxy_doh_headers_invalid')
            headers.setdefault(name.lower(), []).append(value.strip(b' \t'))
        code = int(status.group(1))
        if code in (100, 102, 103):
            offset = body_start
            continue
        if code != 200:
            raise PolicyError('proxy_doh_http_failed')
        types = headers.get(b'content-type', [])
        if (len(types) != 1 or types[0].split(b';', 1)[0].strip().lower()
                not in (b'application/json', b'application/dns-json')):
            raise PolicyError('proxy_doh_headers_invalid')
        encodings = headers.get(b'content-encoding', [])
        if encodings and (len(encodings) != 1 or encodings[0].lower() != b'identity'):
            raise PolicyError('proxy_doh_headers_invalid')
        ages = headers.get(b'age', [])
        if len(ages) > 1 or (ages and re.fullmatch(rb'[0-9]{1,10}', ages[0]) is None):
            raise PolicyError('proxy_doh_age_invalid')
        age = int(ages[0]) if ages else 0
        if age > MAX_HTTP_AGE:
            raise PolicyError('proxy_doh_age_invalid')
        body = wire[body_start:]
        if len(body) > MAX_DOH_BODY:
            raise PolicyError('proxy_doh_too_large')
        return body, age
    raise PolicyError('proxy_doh_headers_invalid')


def query_request_time(query):
    """Legacy queries lack cache metadata; new fields must appear as a pair."""
    if ('request_started_at' in query) != ('http_age_seconds' in query):
        raise PolicyError('query_evidence_expired_or_invalid')
    observed = query.get('observed_at')
    requested = query.get('request_started_at', observed)
    age = query.get('http_age_seconds', 0)
    if (any(type(v) not in (int, float) or not math.isfinite(v) for v in (requested, observed))
            or type(age) is not int or not 0 <= age <= MAX_HTTP_AGE or observed != requested - age):
        raise PolicyError('query_evidence_expired_or_invalid')
    return requested


def _discover_query_raw(port, host, kind):
    requested = time.time()
    command = ['/usr/bin/curl', '-q', '--proxy', f'http://127.0.0.1:{port}',
               '--noproxy', '', '--connect-timeout', '5', '--max-time', '12',
               '--max-filesize', '65536', '--proto', '=https', '--fail', '--silent',
               '--include', '--suppress-connect-headers',
               '--show-error', f'https://dns.google/resolve?name={host}&type={kind}']
    payload, age = decode_doh_http(bounded_http_request(command))
    try:
        body = json.loads(payload.decode('utf-8'))
    except (ValueError, UnicodeError):
        raise PolicyError('proxy_doh_json_invalid') from None
    # observed_at is the conservative cache origin, not the request wall time.
    observed = requested - age
    entries = parse_answer(body, host, kind, observed)
    query = {'host': host, 'type': kind, 'addresses': len(entries),
             'observed_at': observed, 'completed_at': time.time(),
             'request_started_at': requested, 'http_age_seconds': age,
             'expires_at': min([e['expires_at'] for e in entries] or [observed + 30])}
    return entries, query


def discover_query(port, host, kind):
    entries, query = _discover_query_raw(port, host, kind)
    with evidence_phase({'queries': [query]}, 'query_return'):
        if query['expires_at'] <= query['completed_at']:
            raise PolicyError('destination_evidence_expired' if entries else 'query_evidence_expired_or_invalid')
    return entries, query


def _discover_batch(port, query_function):
    if type(port) is not int or not 1 <= port <= 65535:
        raise PolicyError('invalid_proxy_port')
    policy = {'version': 1, 'proxy_port': port, 'transport_exclusions': [],
              'confirmed_exit': '203.0.113.43', 'proxy_transport_endpoints_verified': False,
              'scope': SCOPE, 'entries': [], 'queries': []}
    jobs = [(host, kind) for host in HOSTS for kind in (1, 28)]
    # One bounded batch; retain owner/family order and publish only complete evidence.
    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        pending = [pool.submit(query_function, port, host, kind) for host, kind in jobs]
        for future in pending:
            entries, query = future.result()
            policy['entries'].extend(entries)
            policy['queries'].append(query)
    return policy, time.time()


def discover(port=1082):
    policy, _ = _discover_batch(port, discover_query)
    with evidence_phase(policy, 'dns_batch'):
        dns_evidence(policy)
    return policy


def discover_for_plan(original):
    """Private full sample, including expired answers; comparison is mandatory.

    This function does not grant freshness. It preserves every requested
    owner/family so a changed address cannot disappear behind a later retry.
    """
    policy, completed_at = _discover_batch(original.get('proxy_port', 1082), _discover_query_raw)
    same_destinations(original, policy, fresh=False)
    return policy, completed_at


def dns_evidence(policy, fresh=True):
    """Match each requested owner/family, including explicit zero-answer queries."""
    compiled = validate(policy, fresh=fresh)
    # Stale DNS comparison is still a live check, unlike historical PF recovery.
    # Validate entry timestamps independently of the query timestamps below.
    if compiled['observed_at'] > time.time():
        raise PolicyError('invalid_evidence_interval')
    expected = {(host, kind) for host in HOSTS for kind in (1, 28)}
    queries, addresses = {}, {key: set() for key in expected}
    counts = {key: 0 for key in expected}
    raw_queries = policy.get('queries')
    if not isinstance(raw_queries, list) or len(raw_queries) != len(expected):
        raise PolicyError('incomplete_query_evidence')
    for query in raw_queries:
        if (not isinstance(query, dict) or not isinstance(query.get('host'), str) or
                type(query.get('type')) is not int):
            raise PolicyError('incomplete_query_evidence')
        key = (query.get('host'), query.get('type'))
        count = query.get('addresses')
        if key not in expected or key in queries or type(count) is not int or not 0 <= count <= 64:
            raise PolicyError('incomplete_query_evidence')
        queries[key] = query
        requested = query_request_time(query)
        observed, completed, expiry = (query.get(k) for k in ('observed_at', 'completed_at', 'expires_at'))
        if (any(type(v) not in (int, float) or not math.isfinite(v) for v in (observed, completed, expiry)) or
                not observed <= requested <= completed <= time.time() or not 0 < expiry - observed <= 86400 or
                (count == 0 and expiry - observed > 30)):
            raise PolicyError('query_evidence_expired_or_invalid')
        if fresh and expiry <= time.time():
            raise PolicyError('query_evidence_expired_or_invalid')
        compiled['expires_at'] = min(compiled['expires_at'], expiry)
    if set(queries) != expected:
        raise PolicyError('incomplete_query_evidence')
    for entry in policy['entries']:
        network = ipaddress.ip_network(entry['cidr'])
        if network.prefixlen != network.max_prefixlen:
            raise PolicyError('renewal_requires_host_addresses')
        key = (entry['source'].removeprefix('dns.google '), 1 if network.version == 4 else 28)
        if not entry['source'].startswith('dns.google ') or key not in expected:
            raise PolicyError('unexpected_dns_source')
        counts[key] += 1
        addresses[key].add(str(network))
    if any(counts[key] != queries[key]['addresses'] for key in expected):
        raise PolicyError('query_answer_count_mismatch')
    return addresses, compiled


def same_destinations(original, sample, fresh=True):
    old, _ = dns_evidence(original, fresh=False)
    new, compiled = dns_evidence(sample, fresh=fresh)
    if (old != new or original.get('transport_exclusions', []) != sample.get('transport_exclusions', []) or
            original.get('confirmed_exit') != sample.get('confirmed_exit') or
            original.get('proxy_port', 1082) != sample.get('proxy_port', 1082)):
        raise PolicyError('address_or_proxy_policy_changed')
    return compiled


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy-port', type=int, default=1082)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        policy = discover(args.proxy_port)
        compiled = validate(policy)
        args.output.write_text(json.dumps(policy, indent=2) + '\n')
        print(json.dumps({'policy_sha256': fingerprint(policy), **compiled,
                          'protection_verified': False}, indent=2))
        return 0
    except (PolicyError, OSError) as error:
        print(json.dumps({'reason': str(error) if isinstance(error, PolicyError) else 'policy_write_failed',
                          'protection_verified': False}))
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
