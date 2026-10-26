#!/usr/bin/env python3
"""Root observer: same-address evidence renewal, scoped repair, public status."""
import argparse
import copy
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import ExitStack, contextmanager
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import re
import signal
import stat
import subprocess
import threading
import time
import uuid
from typing import NamedTuple, Optional
import pf_runtime_identity as runtime_identity
import pf_recovery_receipt as recovery

from pf_guard import PF, Store, GuardError, LabError, check_plan, health, identity, watch_once
from pf_policy import DNS_DIAGNOSTICS, PolicyError, discover_for_plan, dns_evidence, fingerprint, same_destinations
from pf_policy import EXPIRY_CODES, evidence_phase, safe_diagnostic, timing_diagnostic

ROOT = Path('/Library/Application Support/Claude Launcher PF')
PUBLIC = ROOT / 'status.json'
CHECKS = ('installed', 'pf_enabled', 'root_matches', 'destinations_match', 'evidence_fresh')
FAULTS = {'address_or_proxy_policy_changed', 'proxy_exit_mismatch', 'proxy_probe_failed',
          'dns_refresh_failed', 'network_check_timeout', 'pf_check_failed', 'rules_missing_or_changed',
          'evidence_expired', 'service_stopped', 'service_restarted', 'waiting_for_plan', 'service_state_invalid'}


class SampleFailure(NamedTuple):
    reason: str
    detail: Optional[str]
    diagnostic: Optional[dict] = None


class SamplingTicket(NamedTuple):
    generation: str
    cycle: str
    attempt: int


@dataclass
class AcceptanceCycle:
    ticket: SamplingTicket
    started: float
    previous: Optional[dict]
    prior_expiry: Optional[dict] = None
    retry_closed: bool = False


class RetryCandidate(Exception):
    """Internal control flow: preserve the original operation and resample once."""


RETRY_PHASES = {'query_return', 'dns_batch', 'exit_wait', 'worker_queue', 'pf_check', 'publication'}


def safe_detail(value):
    return value if isinstance(value, str) and value in DNS_DIAGNOSTICS else None


def policy_detail(error):
    return safe_detail(str(error)) if isinstance(error, PolicyError) else None


@contextmanager
def startup_lock(store, attempts=25):
    """Allow launchd to start while its installer finishes the activation lock."""
    with ExitStack() as held:
        for attempt in range(attempts):
            try:
                held.enter_context(store.lock())
                break
            except GuardError as error:
                if str(error) != 'guard_operation_in_progress':
                    raise
                if attempt + 1 == attempts:
                    raise GuardError('startup_lock_timeout') from None
                time.sleep(0.2)
        yield


def trusted_directory(path, owner=0):
    """Check every component; no symlink or group/world-writable ancestor."""
    for component in [*reversed(path.parents), path]:
        info = component.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
            raise GuardError('untrusted_service_directory')


def safe_read(path, owner=0, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022 or
                info.st_nlink != 1 or info.st_size > limit):
            raise GuardError('untrusted_service_file')
        data = stream.read(limit + 1)
        if len(data) > limit:
            raise GuardError('service_file_too_large')
        return data


def atomic(path, value, mode=0o600, staging_directory=None):
    temporary = (staging_directory or path.parent) / ('.pending-' + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, mode)
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish(value):
    trusted_directory(ROOT)
    atomic(PUBLIC, json.dumps(value, sort_keys=True).encode(), 0o644)


def probe_exit(port, host, expected):
    observed = time.time()
    try:
        result = subprocess.run(
            ['/usr/bin/curl', '-q', '--proxy', f'http://127.0.0.1:{port}', '--noproxy', '',
             '--connect-timeout', '5', '--max-time', '10', '--max-filesize', '8192',
             '--proto', '=https', '--fail', '--silent', '--show-error', f'https://{host}/cdn-cgi/trace'],
            capture_output=True, timeout=12, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
        if result.returncode or len(result.stdout) > 8192:
            raise GuardError('proxy_probe_failed')
        ips = re.findall(rb'^ip=([^\r\n]+)\r?$', result.stdout, re.M)
        if len(ips) != 1 or str(ipaddress.ip_address(ips[0].decode('ascii'))) != expected:
            raise GuardError('proxy_exit_mismatch')
    except (OSError, subprocess.TimeoutExpired, ValueError):
        raise GuardError('proxy_probe_failed') from None
    return observed


def collect_round(plan):
    """All DNS questions and both exit identities must complete successfully."""
    port = plan['policy'].get('proxy_port', 1082)
    expected = str(ipaddress.ip_address(plan['policy']['confirmed_exit']))
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = {pool.submit(discover_for_plan, plan['policy']): 'dns'}
        jobs.update({pool.submit(probe_exit, port, host, expected): host
                     for host in ('claude.ai', 'api.anthropic.com')})
        results = {jobs[future]: future.result() for future in as_completed(jobs)}
    policy, batch_completed_at = results['dns']
    return policy, batch_completed_at, min(results['claude.ai'], results['api.anthropic.com'])


def expiry_origin(policy, batch_completed_at):
    returned_expired = [q for q in policy['queries'] if q['expires_at'] <= q['completed_at']]
    if returned_expired:
        return 'query_return', {'queries': returned_expired}
    if any(q['expires_at'] <= batch_completed_at for q in policy['queries']):
        return 'dns_batch', policy
    return 'exit_wait', policy


def sampling_diagnostic(sample):
    """Accept old single-attempt samples, or validate our bounded attempt record."""
    attempts = sample.get('dns_attempts', 1)
    prior = sample.get('prior_expiry')
    if type(attempts) is not int or attempts not in (1, 2):
        raise GuardError('service_state_invalid')
    if attempts == 1:
        if prior is not None:
            raise GuardError('service_state_invalid')
    elif (prior is None or safe_diagnostic(prior) != prior or prior.get('evidence_kind') != 'dns'
          or prior.get('phase') not in RETRY_PHASES):
        raise GuardError('service_state_invalid')
    return {'dns_attempts': attempts, 'prior_expiry': prior}


def collect(plan):
    started = time.monotonic()
    prior_expiry = None
    for attempt in (1, 2):
        policy, batch_completed_at, checked_at = collect_round(plan)
        # Compare the entire sample before any retry decision, independently of
        # the collector adapter; malformed or changed evidence always escapes.
        stale = same_destinations(plan['policy'], policy, fresh=False)
        phase, diagnostic_policy = expiry_origin(policy, batch_completed_at)
        try:
            with evidence_phase(diagnostic_policy, phase):
                compiled = same_destinations(plan['policy'], policy)
        except PolicyError as error:
            if (str(error) not in EXPIRY_CODES or stale['expires_at'] > time.time()
                    or attempt != 1 or time.monotonic() - started >= 30):
                raise
            prior_expiry = safe_diagnostic(error.diagnostic)
            continue
        elapsed = time.monotonic() - started
        if elapsed > 45:
            raise GuardError('network_check_timeout')
        result = {'version': 1, 'plan_sha256': fingerprint(plan), 'policy': policy,
                  'expires_at': compiled['expires_at'], 'proxy_checked_at': checked_at,
                  'sample_seconds': elapsed, 'dns_attempts': attempt, 'prior_expiry': prior_expiry}
        sampling_diagnostic(result)
        return result
    raise GuardError('network_check_timeout')


def collect_once(plan):
    """One complete raw round. Observer owns the whole acceptance retry budget."""
    started = time.monotonic()
    policy, batch_completed_at, checked_at = collect_round(plan)
    compiled = same_destinations(plan['policy'], policy, fresh=False)
    return {'version': 1, 'plan_sha256': fingerprint(plan), 'policy': policy,
            'expires_at': compiled['expires_at'], 'proxy_checked_at': checked_at,
            'sample_seconds': time.monotonic() - started, 'batch_completed_at': batch_completed_at,
            'round_completed_at': time.time()}


def evidence_deadline(plan, sample, phase='active_evidence'):
    with evidence_phase(sample['policy'], phase):
        compiled = same_destinations(plan['policy'], sample['policy'])
    checked = sample['proxy_checked_at']
    if (type(checked) not in (int, float) or not math.isfinite(checked) or
            not 0 <= time.time() - checked < 45):
        error = PolicyError('proxy_evidence_stale')
        error.diagnostic = timing_diagnostic(None, phase, proxy_checked_at=checked)
        # Invalid/missing timestamps must not be labelled as DNS evidence.
        if checked is None:
            error.diagnostic = safe_diagnostic({'phase': phase, 'evidence_kind': 'proxy'})
        raise error
    return min(compiled['expires_at'], checked + 45)


class Observer:
    def __init__(self, plan, pf, store, publisher=publish, collector=collect_once, installation=None):
        check_plan(plan, pf)
        dns_evidence(plan['policy'], fresh=False)
        self.plan, self.pf, self.store = plan, pf, store
        self.publisher, self.collector = publisher, collector
        self.binding = fingerprint(plan)
        self.installation = installation
        self.recovery = None
        self.active_recovery = None
        self.attempt_failure = None
        try:
            self.state = store.read(plan['id'], 'service')
            restarting = True
        except FileNotFoundError:
            self.state = {'version': 1, 'plan_sha256': self.binding, 'fault': None, 'request': None}
            restarting = False
        if (not isinstance(self.state, dict) or self.state.get('version') != 1 or
                self.state.get('plan_sha256') != self.binding or
                self.state.get('fault') not in FAULTS | {None}):
            raise GuardError('service_state_invalid')
        detail = self.state.get('fault_detail')
        if detail is not None and (safe_detail(detail) is None or self.state['fault'] is None):
            raise GuardError('service_state_invalid')
        diagnostic = self.state.get('fault_diagnostic')
        if diagnostic is not None and (self.state['fault'] is None or
                                       safe_diagnostic(diagnostic) != diagnostic):
            raise GuardError('service_state_invalid')
        self.generation = uuid.uuid4().hex
        self.results = queue.Queue(maxsize=1)
        self.wake = threading.Event()
        self.worker = None
        self.worker_generation = None
        self.worker_ticket = None
        self.cycle = None
        self.started = 0.0
        self.next_sample = 0.0
        self.sample = None  # Every process restart requires fresh network evidence.
        self.published_deadline = None
        self.sample_durations = []
        self.manual_pending = False
        self.closed = False
        if restarting:
            self.latch('service_restarted')
        if installation is not None:
            if (not runtime_identity.hex_value(installation.get('runtime_sha256'), 64) or
                    type(installation.get('service_pid')) is not int or installation['service_pid'] != os.getpid()):
                raise GuardError('service_state_invalid')
            self.state.update(service_instance=uuid.uuid4().hex, service_pid=os.getpid(),
                              runtime_sha256=installation['runtime_sha256'])
            previous = recovery.load_locked(store, plan['id'])
            if previous is not None:
                if previous['plan_sha256'] != self.binding:
                    raise recovery.ReceiptError('recovery_plan_mismatch')
                interrupted = recovery.interrupt_on_restart(previous,
                    new_service_instance=self.state['service_instance'], now=time.time())
                self.recovery = recovery.commit_locked(store, plan['id'], previous, interrupted)
        self.state['running'] = True
        self.save()  # A crash after this point cannot erase the need for recheck.

    def latch(self, reason, detail=None, diagnostic=None):
        if self.cycle is not None:
            self.cycle.retry_closed = True
        if self.active_recovery is not None and self.attempt_failure is None:
            self.attempt_failure = reason if reason in recovery.REASONS['failed'] else 'check_failed'
        if self.state['fault'] is None:
            self.state.update(fault=reason if reason in FAULTS else 'dns_refresh_failed', fault_at=time.time())
            self.state.pop('fault_detail', None)
            self.state.pop('fault_diagnostic', None)
            if safe_detail(detail) is not None:
                self.state['fault_detail'] = detail
            clean = safe_diagnostic(diagnostic)
            if clean is not None:
                self.state['fault_diagnostic'] = clean

    def save(self):
        self.store.write(self.plan['id'], 'service', self.state)

    def recovery_binding(self):
        return {'plan_id': self.plan['id'], 'plan_sha256': self.binding,
                'runtime_sha256': self.state['runtime_sha256'], 'service_instance': self.state['service_instance']}

    def public_control_context(self):
        if self.installation is None or self.closed or self.state.get('running') is not True:
            return None
        return dict(self.recovery_binding(), version=1,
                    receipt_revision=self.recovery['revision'] if self.recovery is not None else 0)

    def recovery_identity(self, value, now=None):
        return {'request_id': value['request_id'], 'receipt_revision': value['revision'],
                'binding': self.recovery_binding(), 'now': time.time() if now is None else now}

    def end_recovery(self, status, reason, **evidence):
        current = self.active_recovery
        if current is None:
            return
        if status == 'passed' and current['generation'] != self.generation:
            raise recovery.ReceiptError('recovery_binding_mismatch')
        finishing = self.recovery_identity(current)
        if status == 'passed' and finishing['now'] >= evidence['evidence_expires_at']:
            raise PolicyError('destination_evidence_expired')
        if status == 'passed':
            self.check_cycle_budget()
        if self.cycle is not None:
            self.cycle.retry_closed = True  # Before any terminal write, including an unknown result.
        value = recovery.finish(current, generation=current['generation'], status=status, reason=reason,
                                **evidence, **finishing)
        self.recovery = recovery.commit_locked(self.store, self.plan['id'], current, value)
        self.active_recovery = None
        self.attempt_failure = None

    def poll_recovery(self):
        current = recovery.load_locked(self.store, self.plan['id'])
        if self.active_recovery is not None and current != self.active_recovery:
            raise recovery.ReceiptError('recovery_receipt_changed')
        self.recovery = current
        if current is None:
            return
        if current['plan_sha256'] != self.binding:
            raise recovery.ReceiptError('recovery_plan_mismatch')
        if current['status'] not in recovery.ACTIVE:
            return  # History never starts a check or clears a fault.
        recovery.matching(current, **self.recovery_identity(current))
        if time.time() >= current['request_deadline']:
            self.active_recovery = current
            self.latch('network_check_timeout')
            self.end_recovery('failed', 'request_expired')
            self.manual_pending = False
            self.sample = None
            self.generation = uuid.uuid4().hex
            return
        if current['status'] == 'received':
            generation = uuid.uuid4().hex
            try:
                checking = recovery.begin(current, generation=generation, **self.recovery_identity(current))
            except recovery.ReceiptError as error:
                if str(error) != 'recovery_request_expired':
                    raise
                self.active_recovery = current
                self.latch('network_check_timeout')
                self.end_recovery('failed', 'request_expired')
                self.manual_pending = False
                self.sample = None
                self.generation = uuid.uuid4().hex
                return
            self.recovery = recovery.commit_locked(self.store, self.plan['id'], current, checking)
            self.active_recovery = self.recovery
            self.attempt_failure = None
            self.generation = generation
            self.state['request'] = current['request_id']
            self.state['request_revision'] = current['revision']
            self.manual_pending = True
            self.sample = None
            self.next_sample = 0.0
            self.save()
        elif self.active_recovery is None or current['generation'] != self.generation:
            raise recovery.ReceiptError('recovery_binding_mismatch')

    def interrupt_recovery(self, reason):
        if self.installation is None:
            return
        current = recovery.load_locked(self.store, self.plan['id'])
        self.recovery = current
        if current is not None and current['status'] in recovery.ACTIVE:
            recovery.matching(current, **self.recovery_identity(current))
            self.active_recovery = current
            self.end_recovery('interrupted', reason)
        self.manual_pending = False
        self.sample = None

    def clear_fault(self):
        self.state['fault'] = None
        for key in ('fault_at', 'fault_detail', 'fault_diagnostic'):
            self.state.pop(key, None)

    def finish_recovery(self, checks):
        """Persist the check result; only fresh success may clear a prior fault.

        A durable passed receipt is historical. Any subsequent write/expiry
        failure keeps the service blocked, even if that receipt is on disk.
        Return the old state for the final publication freshness check.
        """
        current = self.active_recovery
        if current is None:
            return None
        if time.time() >= current['request_deadline']:
            self.latch('network_check_timeout')
            self.attempt_failure = 'request_expired'
        if self.attempt_failure is not None or not self.manual_pending:
            self.end_recovery('failed', self.attempt_failure or 'check_failed')
            self.manual_pending = False
            self.sample = None
            self.generation = uuid.uuid4().hex
            return None
        if not self.manual_pending or self.sample is None or not all(checks.values()):
            return None
        previous = copy.deepcopy(self.state)
        try:
            deadline = evidence_deadline(self.plan, self.sample, phase='publication')
            checked = time.time()
            if checked >= deadline:
                raise PolicyError('destination_evidence_expired')
            self.end_recovery('passed', 'checks_passed', checks=checks, checked_at=checked,
                              evidence_expires_at=deadline)
            # fsync can outlast the accepted evidence or the request budget.
            evidence_deadline(self.plan, self.sample, phase='publication')
            if time.time() >= current['request_deadline']:
                raise recovery.ReceiptError('recovery_request_expired')
            self.clear_fault()
            self.manual_pending = False
            self.save()
            evidence_deadline(self.plan, self.sample, phase='publication')
            if time.time() >= current['request_deadline']:
                raise recovery.ReceiptError('recovery_request_expired')
            return previous
        except PolicyError as error:
            self.state = previous
            self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
            if self.active_recovery is not None:
                self.end_recovery('failed', 'evidence_expired')
            self.manual_pending = False
            self.sample = None
            self.save()
            return None
        except recovery.ReceiptError as error:
            self.state = previous
            if str(error) != 'recovery_request_expired':
                raise
            self.latch('network_check_timeout')
            self.end_recovery('failed', 'request_expired')
            self.manual_pending = False
            self.sample = None
            self.save()
            return None
        except GuardError as error:
            self.state = previous
            if str(error) != 'network_check_timeout':
                raise
            self.latch('network_check_timeout')
            self.end_recovery('failed', 'network_check_timeout')
            self.manual_pending = False
            self.sample = None
            self.save()
            return None
        except Exception:
            self.state = previous
            # The receipt or service write may already have replaced its file.
            # Exit through the daemon failure path; never publish observed.
            raise

    def begin_cycle(self):
        self.cycle = AcceptanceCycle(SamplingTicket(self.generation, uuid.uuid4().hex, 1),
                                     time.monotonic(), copy.deepcopy(self.sample))
        return self.cycle.ticket

    def close_retry(self):
        if self.cycle is not None:
            self.cycle.retry_closed = True

    def check_cycle_budget(self):
        cycle = self.cycle
        if cycle is not None and cycle.ticket.generation == self.generation:
            if not cycle.started <= time.monotonic() < cycle.started + 45:
                raise GuardError('network_check_timeout')
        if self.active_recovery is not None and time.time() >= self.active_recovery['request_deadline']:
            raise GuardError('network_check_timeout')

    def retry_candidate(self, candidate, error):
        """Only a complete, unchanged DNS candidate may get a second full round.

        Never retry lost continuity, proxy evidence, mutation uncertainty, or a
        terminal receipt. Retain the original accepted sample through all writes.
        """
        cycle = self.cycle
        diagnostic = safe_diagnostic(getattr(error, 'diagnostic', None))
        if (candidate is None or cycle is None or cycle.retry_closed or cycle.ticket.attempt != 1
                or cycle.ticket.generation != self.generation or not isinstance(error, PolicyError)
                or str(error) not in EXPIRY_CODES or diagnostic is None
                or diagnostic.get('evidence_kind') != 'dns' or diagnostic.get('phase') not in RETRY_PHASES
                or not cycle.started <= time.monotonic() < cycle.started + 30
                or candidate.get('dns_attempts', 1) != 1
                or (self.state['fault'] is not None and not self.manual_pending)):
            return
        try:
            self.check_cycle_budget()
            compiled = same_destinations(self.plan['policy'], candidate['policy'], fresh=False)
            checked = candidate['proxy_checked_at']
            if (compiled['expires_at'] > time.time() or type(checked) not in (int, float)
                    or not math.isfinite(checked) or not 0 <= time.time() - checked < 45):
                return
            if cycle.previous is not None:
                evidence_deadline(self.plan, cycle.previous, phase='active_evidence')
            # Even queue expiry must not hide a concurrent PF rule change.
            observed = health(self.plan, self.pf, self.store)
            if not all(observed['checks'][key] is True for key in CHECKS if key != 'evidence_fresh'):
                return
            # Read-only PF calls consume time too; do not start a second round
            # based on the budget or continuity observed before those calls.
            self.check_cycle_budget()
            if (not cycle.started <= time.monotonic() < cycle.started + 30
                    or not 0 <= time.time() - checked < 45):
                return
            if cycle.previous is not None:
                evidence_deadline(self.plan, cycle.previous, phase='active_evidence')
        except (GuardError, LabError, PolicyError, OSError, KeyError, ValueError, TypeError):
            return
        cycle.prior_expiry = diagnostic
        cycle.ticket = SamplingTicket(cycle.ticket.generation, cycle.ticket.cycle, 2)
        self.sample = copy.deepcopy(cycle.previous)
        self.next_sample = time.monotonic()
        raise RetryCandidate()

    def worker_run(self, ticket):
        try:
            result = self.collector(self.plan)
            error = None
        except (GuardError, PolicyError) as exc:
            result, error = None, SampleFailure(
                str(exc) if str(exc) in FAULTS else 'dns_refresh_failed', policy_detail(exc),
                safe_diagnostic(getattr(exc, 'diagnostic', None)))
        except Exception:
            result, error = None, 'dns_refresh_failed'
        self.results.put((ticket, result, error))
        self.wake.set()

    def tick(self):
        try:
            self._tick()
        except RetryCandidate:
            # The failed candidate never publishes a pass. Re-enter once to
            # observe existing rules/evidence and schedule round two. No I/O is
            # performed recursively by the network collector.
            self._tick()

    def _tick(self):
        now, monotonic = time.time(), time.monotonic()
        if self.installation is not None:
            self.poll_recovery()
            control = None
        else:
            # Legacy .recheck is retained only for independent test adapters.
            # Production main always supplies a verified installation.
            try:
                control = self.store.read(self.plan['id'], 'recheck')
            except FileNotFoundError:
                control = None
        if control is not None:
            if (control.get('plan_sha256') != self.binding or
                    not re.fullmatch('[a-f0-9]{32}', str(control.get('request', '')))):
                raise GuardError('service_state_invalid')
            if control['request'] != self.state['request']:
                self.state['request'] = control['request']
                self.generation = uuid.uuid4().hex
                self.manual_pending = True
                self.sample = None
                self.next_sample = 0.0
                self.save()
        # Automatic renewal must not conceal an interval without valid evidence.
        # An explicit request above discards the old sample and starts a new check.
        if self.sample is not None:
            try:
                evidence_deadline(self.plan, self.sample)
            except (PolicyError, ValueError, KeyError, TypeError) as error:
                self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
                self.sample = None
        candidate = None
        result = None
        completed_cycle = False
        previous_accepted = self.sample
        try:
            ticket, result, error = self.results.get_nowait()
            generation = ticket.generation if isinstance(ticket, SamplingTicket) else ticket
            scoped = (self.cycle is not None and ticket == self.cycle.ticket)
            unscoped = self.cycle is None and isinstance(ticket, str)
            if ((self.worker_ticket is not None and self.worker_ticket == ticket) or
                    (self.worker_ticket is None and unscoped and self.worker_generation == generation)):
                # All collection and cleanup precede queue publication. Retire
                # that collection here, even if its thread is still signalling
                # wake; notification-tail lifetime must not delay renewal.
                self.worker_generation = None
                self.worker_ticket = None
                self.worker = None
            if generation == self.generation and (scoped or unscoped):
                completed_cycle = scoped
                if error:
                    if isinstance(error, SampleFailure):
                        self.latch(error.reason, error.detail, error.diagnostic)
                    else:
                        self.latch(error)
                    self.manual_pending = False
                    self.sample = None
                else:
                    if not isinstance(result, dict) or result.get('plan_sha256') != self.binding:
                        raise GuardError('service_state_invalid')
                    # Compare all stale answers first: a changed expired answer
                    # must not disappear behind a later retry.
                    same_destinations(self.plan['policy'], result['policy'], fresh=False)
                    sampling_diagnostic(result)
                    duration = result.get('sample_seconds')
                    if (type(duration) not in (int, float) or not math.isfinite(duration) or
                            not 0 <= duration <= 45):
                        raise GuardError('service_state_invalid')
                    self.check_cycle_budget()
                    if scoped:
                        if self.cycle.ticket.attempt == 2 and result.get('dns_attempts', 1) != 1:
                            raise GuardError('service_state_invalid')
                        if self.cycle.ticket.attempt == 2:
                            result = dict(result, dns_attempts=2, prior_expiry=self.cycle.prior_expiry)
                        elif result.get('dns_attempts', 1) == 2:
                            self.close_retry()  # A custom collector already spent both rounds.
                    phase, diagnostic_policy = 'worker_queue', result['policy']
                    if 'batch_completed_at' in result:
                        batch = result['batch_completed_at']
                        ended = result.get('round_completed_at')
                        if (type(batch) not in (int, float) or not math.isfinite(batch)
                                or type(ended) not in (int, float) or not math.isfinite(ended)
                                or not 0 <= batch <= ended <= time.time()):
                            raise GuardError('service_state_invalid')
                        if any(q['expires_at'] <= batch for q in result['policy']['queries']):
                            phase, diagnostic_policy = expiry_origin(result['policy'], batch)
                        elif any(q['expires_at'] <= ended for q in result['policy']['queries']):
                            phase = 'exit_wait'
                    with evidence_phase(diagnostic_policy, phase):
                        same_destinations(self.plan['policy'], result['policy'])
                    if self.state['fault'] is None or self.manual_pending:
                        candidate = result
        except queue.Empty:
            pass
        except (GuardError, PolicyError, ValueError, KeyError, TypeError) as error:
            self.retry_candidate(result, error)
            self.latch('network_check_timeout' if str(error) == 'network_check_timeout' else 'dns_refresh_failed',
                       policy_detail(error), getattr(error, 'diagnostic', None))
            self.sample = None
            self.manual_pending = False
        if (self.worker and self.worker.is_alive() and self.worker_generation == self.generation and
                monotonic - self.started > 45):
            self.latch('network_check_timeout')
            self.generation = uuid.uuid4().hex
            self.sample = None
            self.manual_pending = False
        if self.cycle is not None and self.cycle.ticket.generation == self.generation:
            try:
                self.check_cycle_budget()
            except GuardError:
                self.latch('network_check_timeout')
                self.generation = uuid.uuid4().hex
                candidate = self.sample = None
                self.manual_pending = False
        current = candidate or self.sample
        evidence = None
        if current:
            try:
                evidence_deadline(self.plan, current, phase='worker_queue' if candidate is not None else 'active_evidence')
                evidence = current['policy']
            except (PolicyError, ValueError, KeyError, TypeError) as error:
                self.retry_candidate(candidate, error)
                self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
                current = candidate = self.sample = None
                self.manual_pending = False
        accepting_candidate = candidate is not None
        try:
            # Only a fresh complete candidate can authorize restoration of an empty
            # owned anchor. This never repairs root hooks, enables PF, or changes scope.
            if evidence is not None and (self.state['fault'] is None or self.manual_pending):
                try:
                    with evidence_phase(evidence, 'pf_check'):
                        observed = watch_once(self.plan, self.pf, self.store, evidence=evidence,
                                              before_repair=self.close_retry)
                except PolicyError as error:
                    if str(error) not in EXPIRY_CODES:
                        raise
                    self.retry_candidate(candidate, error)
                    self.latch('evidence_expired', policy_detail(error), error.diagnostic)
                    candidate = self.sample = None
                    self.manual_pending = False
                    # Read rules without stale network evidence; this fallback must
                    # never repair rules, clear a fault or permit renewal.
                    observed = health(self.plan, self.pf, self.store)
                    observed['checks']['evidence_fresh'] = False
                    observed['rules_present_and_fresh'] = False
            else:
                observed = health(self.plan, self.pf, self.store)
            checks = observed['checks']
            if set(checks) != set(CHECKS) or any(type(v) is not bool for v in checks.values()):
                raise GuardError('pf_check_failed')
            if not all(checks[key] for key in CHECKS if key != 'evidence_fresh'):
                self.latch('rules_missing_or_changed')
                candidate = None
                if accepting_candidate:
                    self.manual_pending = False
            if observed.get('empty_owned_anchor_repaired') and not self.manual_pending:
                self.latch('rules_missing_or_changed')
                candidate = None
            if candidate is not None:
                # PF verification can take time: revalidate before saving/clearing a fault.
                # health() can report stale evidence without throwing; classify
                # that expiry too, rather than silently dropping a manual attempt.
                try:
                    self.check_cycle_budget()
                    deadline = evidence_deadline(self.plan, candidate, phase='pf_check')
                except PolicyError as error:
                    self.retry_candidate(candidate, error)
                    self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
                    candidate = self.sample = None
                    self.manual_pending = False
            if candidate is not None and observed['rules_present_and_fresh']:
                # Automatic renewal must bridge the entire PF/write interval.
                # A saved candidate is only a sample, not an accepted renewal.
                previous = self.sample
                try:
                    if previous is not None:
                        evidence_deadline(self.plan, previous, phase='active_evidence')
                    self.store.write(self.plan['id'], 'renewal', candidate)
                    if previous is not None:
                        evidence_deadline(self.plan, previous, phase='active_evidence')
                    deadline = evidence_deadline(self.plan, candidate, phase='publication')
                    self.check_cycle_budget()
                except PolicyError as error:
                    if str(error) not in EXPIRY_CODES:
                        raise
                    self.retry_candidate(candidate, error)
                    self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
                    candidate = self.sample = None
                    self.manual_pending = False
            if candidate is not None and observed['rules_present_and_fresh']:
                self.sample = candidate
                self.sample_durations = (self.sample_durations + [candidate['sample_seconds']])[-5:]
                # Reserve recent collection cost plus two PF tick intervals. A
                # short-lived answer triggers immediate renewal, never a longer TTL.
                budget = max(15.0, max(self.sample_durations)) + 6.0
                delay = max(0.0, min(30.0, deadline - time.time() - budget))
                self.next_sample = min(self.next_sample, time.monotonic() + delay)
        except (GuardError, LabError, PolicyError, OSError, ValueError, KeyError, TypeError) as error:
            checks = {key: False for key in CHECKS}
            self.latch('network_check_timeout' if str(error) == 'network_check_timeout' else 'pf_check_failed')
            if accepting_candidate:
                self.manual_pending = False
        deadline = None
        if self.sample is not None:
            try:
                if candidate is not None and previous_accepted is not None:
                    evidence_deadline(self.plan, previous_accepted, phase='active_evidence')
                deadline = evidence_deadline(self.plan, self.sample, phase='publication')
            except (PolicyError, ValueError, KeyError, TypeError) as error:
                self.retry_candidate(candidate, error)
                self.latch('evidence_expired', policy_detail(error), getattr(error, 'diagnostic', None))
                self.sample = None
                self.manual_pending = False
        self.save()
        # This save still contains the old manual fault. A known successful
        # write may be followed by one fresh round, but never after a terminal
        # receipt has begun. Unknown writes propagate out of the observer.
        if candidate is not None and self.sample is not None:
            try:
                if previous_accepted is not None:
                    evidence_deadline(self.plan, previous_accepted, phase='active_evidence')
                evidence_deadline(self.plan, candidate, phase='publication')
                self.check_cycle_budget()
            except (PolicyError, GuardError) as error:
                self.retry_candidate(candidate, error)
                self.latch('network_check_timeout' if isinstance(error, GuardError) else 'evidence_expired',
                           policy_detail(error), getattr(error, 'diagnostic', None))
                candidate = self.sample = None
                self.manual_pending = False
                self.save()
        if candidate is not None:
            self.close_retry()
        recovered_state = self.finish_recovery(checks) if self.installation is not None else None
        # Service and receipt writes are part of the acceptance interval too.
        if self.sample is not None:
            try:
                if candidate is not None and previous_accepted is not None:
                    evidence_deadline(self.plan, previous_accepted, phase='active_evidence')
                deadline = evidence_deadline(self.plan, self.sample, phase='publication')
                if candidate is not None:
                    self.check_cycle_budget()
            except (GuardError, PolicyError, ValueError, KeyError, TypeError) as error:
                if recovered_state is not None:
                    self.state = recovered_state
                self.latch('network_check_timeout' if isinstance(error, GuardError) else 'evidence_expired',
                           policy_detail(error), getattr(error, 'diagnostic', None))
                self.sample = None
                self.manual_pending = False
                self.save()
        if self.manual_pending and self.installation is None and self.sample is not None and all(checks.values()):
            previous_state = copy.deepcopy(self.state)
            self.clear_fault()
            self.manual_pending = False
            self.save()
            try:
                deadline = evidence_deadline(self.plan, self.sample, phase='publication')
                self.check_cycle_budget()
            except (PolicyError, GuardError) as error:
                self.state = previous_state
                self.latch('network_check_timeout' if isinstance(error, GuardError) else 'evidence_expired',
                           policy_detail(error), getattr(error, 'diagnostic', None))
                self.sample = None
                self.save()
        ready = (self.sample is not None and self.state['fault'] is None and not self.manual_pending and
                 all(checks.values()))
        self.published_deadline = deadline if ready else None
        receipt_current = (ready and self.recovery is not None and recovery.evidence_current(
            self.recovery, generation=self.generation, **self.recovery_identity(self.recovery)))
        self.publisher({'version': 1, 'plan_id': self.plan['id'], 'checked_at': time.time(),
                        'service_running': True, 'rules_observed': all(checks[k] for k in CHECKS if k != 'evidence_fresh'),
                        'evidence_fresh': ready, 'manual_recheck_required': self.state['fault'] is not None,
                        'status': 'observed' if ready else 'fault' if self.state['fault'] else 'checking',
                        'reason': ('same_addresses_observed' if ready else
                                   self.state['fault'] or 'waiting_for_network_evidence'),
                        'fault_detail': safe_detail(self.state.get('fault_detail')) if self.state['fault'] else None,
                        'fault_diagnostic': safe_diagnostic(self.state.get('fault_diagnostic')) if self.state['fault'] else None,
                        'evidence_expires_at': deadline if ready else None,
                        'sampling_diagnostic': sampling_diagnostic(self.sample) if ready else None,
                        'recovery': self.recovery, 'recovery_current': receipt_current,
                        'control_context': self.public_control_context(),
                        'protection_verified': False, 'launch_authorized': False})
        if completed_cycle:
            self.cycle = None
        if time.monotonic() >= self.next_sample and not (self.worker and self.worker.is_alive()):
            if self.cycle is None or self.cycle.ticket.generation != self.generation:
                self.begin_cycle()
            self.started = time.monotonic()
            self.next_sample = self.started + 30
            self.worker_generation = self.generation
            self.worker_ticket = self.cycle.ticket
            self.worker = threading.Thread(target=self.worker_run, args=(self.worker_ticket,), daemon=True)
            self.worker.start()


def run_iteration(observer, store, interval=3):
    """Periodic PF checks, with immediate consumption of completed network work.

    Clear before draining the queue: a result arriving during tick must wake the
    following wait. Clearing after tick would discard precisely that notification.
    """
    observer.wake.clear()
    started = time.monotonic()
    with store.lock():
        observer.tick()
    if not observer.closed:
        monotonic = time.monotonic()
        delay = max(0.0, interval - (monotonic - started))
        # A scheduled collection can be due before the periodic PF tick. An
        # in-flight collection owns its slot until it publishes a result; do
        # not spin on an overdue schedule while waiting for that result.
        if observer.worker is None or not observer.worker.is_alive():
            due = observer.next_sample
            if type(due) in (int, float) and math.isfinite(due):
                delay = min(delay, max(0.0, due - monotonic))
        deadline = observer.published_deadline
        if type(deadline) in (int, float) and math.isfinite(deadline):
            delay = min(delay, max(0.0, deadline - time.time()))
        cycle = observer.cycle
        if isinstance(cycle, AcceptanceCycle) and cycle.ticket.generation == observer.generation:
            delay = min(delay, max(0.0, cycle.started + 45 - monotonic))
        request = observer.active_recovery
        if isinstance(request, dict):
            delay = min(delay, max(0.0, request['request_deadline'] - time.time()))
        observer.wake.wait(delay)


def request_stop(observer):
    # Python signal handlers can interrupt Event while it holds a non-reentrant
    # lock. Do not set the Event here; the bounded periodic wait handles shutdown.
    observer.closed = True


def submit_recheck(plan_id, request_id=None, expected_revision=None, expected_binding=None):
    """Validate the live installation under the same lock order as upgrades."""
    identity(plan_id)
    result = None
    retry = None
    try:
        with runtime_identity.control_lock():
            try:
                result = submit_recheck_locked(plan_id, request_id, expected_revision, expected_binding)
            except Exception as error:
                # A second cleanup error may replace this exception on exit.
                retry = getattr(error, 'request_identity', None)
                raise
    except Exception as error:
        if result is not None:
            receipt = result['recovery']
            retry = {'request_id': receipt['request_id'], 'expected_revision': receipt['revision'] - 1}
        if retry is not None:
            error.request_identity = retry
        raise
    return result


def submit_recheck_locked(plan_id, request_id=None, expected_revision=None, expected_binding=None):
    """Caller holds install.lock; acquire only the private journal lock here."""
    identity(plan_id)
    try:
        store, pf = Store(), PF()
        with startup_lock(store):
            plan = store.read(plan_id, 'plan')
            if plan.get('id') != plan_id:
                raise GuardError('plan_identity_mismatch')
            installation = runtime_identity.installed_for_plan(plan, __file__)
            binding = runtime_identity.verify_instance(store.read(plan_id, 'service'), installation, plan)
            check_plan(plan, pf)
            # Confirm launchd did not restart while checking private state/PF.
            if runtime_identity.installed_for_plan(plan, __file__) != installation:
                raise runtime_identity.IdentityError('service_instance_mismatch')
            current = recovery.load_locked(store, plan_id)
            if (request_id is None) != (expected_revision is None):
                raise recovery.ReceiptError('recovery_request_identity_required')
            if request_id is None:
                request_id = uuid.uuid4().hex
                expected_revision = current['revision'] if current is not None else 0
            receipt_binding = {'plan_id': plan_id, 'plan_sha256': fingerprint(plan),
                               'runtime_sha256': binding['runtime_sha256'],
                               'service_instance': binding['service_instance']}
            if expected_binding is not None:
                recovery.validate_binding(expected_binding)
                if expected_binding != receipt_binding:
                    raise runtime_identity.IdentityError('authorization_context_changed')
            # Revision checks belong to submit: an identical retry uses the preceding
            # revision even if the current receipt has already advanced to a result.
            value = recovery.submit(current, request_id=request_id, expected_revision=expected_revision,
                                    binding=receipt_binding, now=time.time())
            saved = recovery.commit_locked(store, plan_id, current, value)
            return {'reason': 'recheck_requested' if saved['status'] == 'received' else 'recheck_existing_result',
                    'recovery': saved, 'protection_verified': False, 'launch_authorized': False}
    except Exception as error:
        if (recovery.hex_id(request_id, 32) and recovery.revision(expected_revision)):
            error.request_identity = {'request_id': request_id, 'expected_revision': expected_revision}
        raise


def recheck_failure(error):
    """Control failures cannot publish daemon status or raw exception text."""
    reason = str(error) if isinstance(error, (runtime_identity.IdentityError, recovery.ReceiptError)) else 'recheck_outcome_unknown'
    if isinstance(error, GuardError) and str(error) == 'administrator_required_no_changes':
        reason = str(error)
    retry = getattr(error, 'request_identity', {})
    if (not isinstance(retry, dict) or set(retry) != {'request_id', 'expected_revision'} or
            not recovery.hex_id(retry.get('request_id'), 32) or not recovery.revision(retry.get('expected_revision'))):
        retry = {}
    return {'reason': reason, **retry, 'launch_authorized': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('run', 'recheck'))
    parser.add_argument('--id', required=True)
    parser.add_argument('--request-id')
    parser.add_argument('--expected-revision', type=int)
    args = parser.parse_args(argv)
    if args.mode == 'recheck':
        try:
            if os.geteuid() != 0:
                raise GuardError('administrator_required_no_changes')
            result = submit_recheck(args.id, args.request_id, args.expected_revision)
            print(json.dumps(result))
            return 0
        except Exception as error:
            # A rejected control command says nothing about daemon health.
            # Never overwrite the running service's public report here.
            print(json.dumps(recheck_failure(error)))
            return 78
    if args.request_id is not None or args.expected_revision is not None:
        return 78
    observer = None
    owns_instance = False
    try:
        if os.geteuid() != 0:
            raise GuardError('administrator_required_no_changes')
        identity(args.id)
        trusted_directory(ROOT)
        store, pf = Store(), PF()
        with startup_lock(store):
            plan = store.read(args.id, 'plan')
            if plan['id'] != args.id:
                raise GuardError('plan_identity_mismatch')
            installation = runtime_identity.installed_for_plan(plan, __file__, startup=True)
            if installation['service_pid'] != os.getpid():
                raise runtime_identity.IdentityError('service_instance_mismatch')
            owns_instance = True
            observer = Observer(plan, pf, store, installation=installation)
        def stop(*_):
            request_stop(observer)
        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while not observer.closed:
            run_iteration(observer, store)
        with store.lock():
            observer.interrupt_recovery('service_stopped')
            observer.latch('service_stopped')
            observer.state['running'] = False
            observer.save()
        publish({'version': 1, 'plan_id': args.id, 'checked_at': time.time(), 'status': 'stopped',
                 'service_running': False, 'rules_observed': False, 'evidence_fresh': False,
                 'manual_recheck_required': True, 'reason': 'service_stopped',
                 'recovery': observer.recovery, 'recovery_current': False,
                 'protection_verified': False, 'launch_authorized': False})
        return 0
    except Exception as error:
        # No raw PF output or private journal content reaches launchd logs.
        if not owns_instance:
            # Source/old-runtime invocations cannot speak for the real daemon.
            # Its last report retains its own deadline and expires normally.
            return 78
        if observer is not None:
            try:
                with store.lock():
                    # Unknown receipt writes/CAS need reread on restart, not a
                    # blind second write that could overwrite a committed result.
                    if not isinstance(error, recovery.ReceiptError):
                        observer.interrupt_recovery('service_stopped')
                    observer.latch('service_state_invalid')
                    observer.save()
            except Exception:
                pass  # Persisted running marker forces recheck on next startup.
        try:
            publish({'version': 1, 'plan_id': args.id, 'checked_at': time.time(), 'status': 'fault',
                     'service_running': False, 'rules_observed': False, 'evidence_fresh': False,
                     'manual_recheck_required': True, 'reason': 'service_state_invalid',
                     'protection_verified': False, 'launch_authorized': False})
        except Exception:
            pass
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
