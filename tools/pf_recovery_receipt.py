"""Request/result correlation used by the privileged PF observer.

These functions never inspect PF, clear an observer fault, or authorize traffic.
The privileged caller verifies the installation and actual checks.
Journal adapters require the caller to hold the existing Store.lock throughout
read, transition and commit; they do not acquire a second, nested lock.
"""
import copy
import re


JOURNAL_KIND = 'recovery'
MAX_REVISION = 2**53 - 1
ACTIVE = frozenset({'received', 'checking'})
CHECKS = frozenset({'installed', 'pf_enabled', 'root_matches', 'destinations_match', 'evidence_fresh'})
BINDING = frozenset({'plan_id', 'plan_sha256', 'runtime_sha256', 'service_instance'})
REASONS = {
    'received': frozenset({'request_received'}),
    'checking': frozenset({'checks_in_progress'}),
    'passed': frozenset({'checks_passed'}),
    'failed': frozenset({'dns_refresh_failed', 'network_check_timeout', 'proxy_probe_failed',
                         'proxy_exit_mismatch', 'address_or_proxy_policy_changed', 'pf_check_failed',
                         'rules_missing_or_changed', 'evidence_expired', 'request_expired', 'check_failed'}),
    'interrupted': frozenset({'service_restarted', 'service_stopped', 'runtime_changed',
                              'configuration_changed', 'manual_cancelled'}),
}
FIELDS = BINDING | frozenset({'version', 'revision', 'request_id', 'status', 'reason', 'generation',
    'received_at', 'updated_at', 'request_deadline', 'started_at', 'checked_at', 'finished_at',
    'checks', 'evidence_expires_at'})


class ReceiptError(Exception):
    """Fixed codes only; never includes input records or original exceptions."""


def require(condition, code='recovery_receipt_invalid'):
    if not condition:
        raise ReceiptError(code)


def hex_id(value, length):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{%d}' % length, value) is not None


def timestamp(value):
    # Bounds also reject NaN/Inf and huge integers without float conversion.
    return type(value) in (int, float) and 0 <= value <= 253402300799


def revision(value):
    return type(value) is int and 0 <= value <= MAX_REVISION


def validate_binding(value):
    require(isinstance(value, dict) and set(value) == BINDING)
    for key in BINDING:
        require(hex_id(value[key], 32 if key in ('plan_id', 'service_instance') else 64))


def validate(value):
    require(isinstance(value, dict) and set(value) == FIELDS)
    validate_binding({key: value[key] for key in BINDING})
    require(type(value['version']) is int and value['version'] == 1)
    require(revision(value['revision']) and value['revision'] > 0 and hex_id(value['request_id'], 32))
    status, reason = value['status'], value['reason']
    require(isinstance(status, str) and status in REASONS)
    require(isinstance(reason, str) and reason in REASONS[status])
    received, updated, deadline = (value[k] for k in ('received_at', 'updated_at', 'request_deadline'))
    require(all(timestamp(t) for t in (received, updated, deadline)))
    require(received <= updated and 0 < deadline - received <= 120)
    started, checked, finished = (value[k] for k in ('started_at', 'checked_at', 'finished_at'))
    generation = value['generation']
    require(generation is None or hex_id(generation, 32))
    require((started is None) == (generation is None))
    if started is not None:
        require(timestamp(started) and received <= started <= updated and started < deadline)
    if status == 'received':
        require(started is None and checked is None and finished is None and updated == received)
    elif status == 'checking':
        require(started is not None and updated == started and checked is None and finished is None)
    else:
        require(timestamp(finished) and finished == updated)
        if status == 'passed':
            require(started is not None and timestamp(checked) and started <= checked <= finished < deadline)
            checks, expires = value['checks'], value['evidence_expires_at']
            require(isinstance(checks, dict) and set(checks) == CHECKS and all(v is True for v in checks.values()))
            require(timestamp(expires) and finished < expires <= checked + 45)
        else:
            require(checked is None)
            if reason == 'request_expired':
                require(finished >= deadline)
    if status != 'passed':
        require(value['checks'] is None and value['evidence_expires_at'] is None)
    return value


def submit(current, *, request_id, expected_revision, binding, now, timeout=90):
    """Idempotent for the same (request_id, expected_revision, binding, timeout).

    A later user action must supply the current revision. Old messages retain
    their old expected_revision and cannot create another attempt.
    """
    validate_binding(binding)
    require(hex_id(request_id, 32) and revision(expected_revision) and timestamp(now))
    require(type(timeout) in (int, float) and 0 < timeout <= 120)
    if current is None:
        require(expected_revision == 0, 'recovery_revision_conflict')
    else:
        validate(current)
        require(current['plan_id'] == binding['plan_id'] and current['plan_sha256'] == binding['plan_sha256'],
                'recovery_plan_mismatch')
        if current['revision'] == expected_revision + 1 and current['request_id'] == request_id:
            require(all(current[k] == binding[k] for k in BINDING) and
                    current['request_deadline'] == current['received_at'] + timeout,
                    'recovery_binding_mismatch')
            return copy.deepcopy(current)
        require(expected_revision == current['revision'], 'recovery_revision_conflict')
        require(current['status'] not in ACTIVE, 'recovery_request_in_progress')
        require(now >= current['updated_at'], 'recovery_clock_reversed')
    require(expected_revision < MAX_REVISION, 'recovery_revision_exhausted')
    return validate(dict(binding, version=1, revision=expected_revision + 1, request_id=request_id,
        status='received', reason='request_received', generation=None, received_at=now, updated_at=now,
        request_deadline=now + timeout, started_at=None, checked_at=None, finished_at=None,
        checks=None, evidence_expires_at=None))


def matching(current, *, request_id, receipt_revision, binding, now):
    validate(current)
    validate_binding(binding)
    require(hex_id(request_id, 32) and revision(receipt_revision) and receipt_revision > 0)
    require(current['request_id'] == request_id and current['revision'] == receipt_revision,
            'recovery_revision_conflict')
    require(all(current[k] == binding[k] for k in BINDING), 'recovery_binding_mismatch')
    require(timestamp(now) and now >= current['updated_at'], 'recovery_clock_reversed')
    return copy.deepcopy(current)


def begin(current, *, generation, **identity):
    value = matching(current, **identity)
    require(value['status'] == 'received', 'recovery_transition_invalid')
    require(hex_id(generation, 32))
    require(identity['now'] < value['request_deadline'], 'recovery_request_expired')
    value.update(status='checking', reason='checks_in_progress', generation=generation,
                 started_at=identity['now'], updated_at=identity['now'])
    return validate(value)


def finish(current, *, generation, status, reason, checks=None, checked_at=None,
           evidence_expires_at=None, **identity):
    """Record only the caller's verified result; does not run or authorize checks."""
    value = matching(current, **identity)
    require(value['status'] in ACTIVE and generation == value['generation'], 'recovery_transition_invalid')
    require(isinstance(status, str) and status in ('passed', 'failed', 'interrupted'),
            'recovery_transition_invalid')
    if status == 'passed':
        require(value['status'] == 'checking' and identity['now'] < value['request_deadline'],
                'recovery_request_expired')
    value.update(status=status, reason=reason, updated_at=identity['now'], finished_at=identity['now'],
                 checks=copy.deepcopy(checks), checked_at=checked_at, evidence_expires_at=evidence_expires_at)
    return validate(value)


def interrupt_on_restart(current, *, new_service_instance, now):
    validate(current)
    require(hex_id(new_service_instance, 32) and timestamp(now))
    if current['status'] not in ACTIVE or current['service_instance'] == new_service_instance:
        return copy.deepcopy(current)
    require(now >= current['updated_at'], 'recovery_clock_reversed')
    value = copy.deepcopy(current)
    value.update(status='interrupted', reason='service_restarted', updated_at=now, finished_at=now,
                 checks=None, checked_at=None, evidence_expires_at=None)
    return validate(value)


def evidence_current(current, *, generation, **identity):
    """Correlation/freshness only. False after expiry; never a launch permit."""
    try:
        value = matching(current, **identity)
        return (value['status'] == 'passed' and value['generation'] == generation and
                identity['now'] < value['evidence_expires_at'])
    except ReceiptError:
        return False


def load_locked(store, plan_id):
    require(hex_id(plan_id, 32))
    try:
        value = store.read(plan_id, JOURNAL_KIND)
    except FileNotFoundError:
        return None
    except Exception:
        raise ReceiptError('recovery_journal_unreadable') from None
    validate(value)
    require(value['plan_id'] == plan_id, 'recovery_plan_mismatch')
    return value


def commit_locked(store, plan_id, expected, replacement):
    """Whole-record CAS under caller-held Store.lock, including same-revision changes.

    Replacement must be produced by a transition above. A write failure may be
    after replace/fsync: reread to resolve it, never blindly submit a new action.
    """
    if expected is not None:
        validate(expected)
    validate(replacement)
    require(replacement['plan_id'] == plan_id, 'recovery_plan_mismatch')
    current = load_locked(store, plan_id)
    require(current == expected, 'recovery_receipt_changed')
    if current != replacement:
        try:
            store.write(plan_id, JOURNAL_KIND, replacement)
        except Exception:
            raise ReceiptError('recovery_receipt_write_outcome_unknown') from None
    return copy.deepcopy(replacement)
