#!/usr/bin/env python3
"""Read installed observer evidence and run one independent root probe; no writes."""
import sys
sys.dont_write_bytecode = True

import argparse
from contextlib import contextmanager
import json
import math
import os
from pathlib import Path
import re
import stat
import time

import pf_guard as guard
import pf_policy as policy
import pf_service as service
import pf_service_install as installer
import pf_recovery_receipt as recovery

KINDS = ('plan', 'state', 'service', 'recheck', 'renewal', 'recovery')
JOURNAL_OWNER = 0
STAGES = frozenset({'entry', 'manifest_sources', 'snapshot_before', 'plan_binding',
                    'summary_before', 'current_probe', 'snapshot_after', 'summary_after'})
INPUT_CODES = frozenset({
    'administrator_required_no_changes', 'invalid_plan_id', 'diagnostic_installation_not_ready',
    'diagnostic_plan_binding_mismatch', 'diagnostic_runtime_files_mismatch',
    'diagnostic_source_runtime_mismatch',
    'diagnostic_recovery_invalid',
    'diagnostic_journal_directory_missing', 'diagnostic_journal_directory_unreadable',
    'diagnostic_journal_directory_unsafe', 'diagnostic_journal_file_unreadable',
    'diagnostic_journal_json_invalid', 'unsafe_or_oversized_file', 'unsafe_journal_file',
    'oversized_file', 'service_state_invalid', 'untrusted_service_directory',
    'untrusted_service_file', 'invalid_service_manifest', 'invalid_service_runtime',
    'modified_runtime_preserved', 'modified_launchd_plist_preserved', 'invalid_service_source',
})
PROBE_CODES = policy.DNS_DIAGNOSTICS | service.FAULTS | {
    'pfctl_unavailable_or_timeout', 'pfctl_rejected', 'pfctl_output_too_large',
    'journal_plan_mismatch', 'plan_content_mismatch', 'invalid_evidence_interval',
}


def finite(value):
    return value if type(value) in (int, float) and math.isfinite(value) else None


@contextmanager
def at_stage(stage):
    try:
        yield
    except Exception as error:
        error.diagnostic_stage = stage
        raise


def verified_manifest(plan_id):
    service.trusted_directory(installer.ROOT)
    manifest = installer.read_manifest()
    if manifest is None or manifest.get('phase') != 'installed':
        raise guard.GuardError('diagnostic_installation_not_ready')
    if manifest['plan_id'] != plan_id:
        raise guard.GuardError('diagnostic_plan_binding_mismatch')
    runtime = Path(manifest['runtime'])
    service.trusted_directory(runtime)
    if {p.name for p in runtime.iterdir()} != set(installer.FILES):
        raise guard.GuardError('diagnostic_runtime_files_mismatch')
    installer.verify_files(manifest)
    hashes = {name: installer.sha(data) for name, data in installer.package().items()}
    if manifest['files'] != hashes or runtime.name != 'runtime-' + policy.fingerprint(hashes):
        raise guard.GuardError('diagnostic_source_runtime_mismatch')
    return manifest


def snapshot(plan_id):
    """Read bounded file versions without creating a lock or holding up sampling."""
    plan_id = guard.identity(plan_id)
    # macOS /private/var/run is root:daemon 0775. Validate and pin our private
    # directory itself; do not apply the executable-runtime ancestor policy here.
    try:
        directory = os.open(guard.DIRECTORY, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise guard.GuardError('diagnostic_journal_directory_missing') from None
    except OSError:
        raise guard.GuardError('diagnostic_journal_directory_unreadable') from None
    records, times, hashes = {}, {}, {}
    try:
        info = os.fstat(directory)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != JOURNAL_OWNER or
                stat.S_IMODE(info.st_mode) != 0o700):
            raise guard.GuardError('diagnostic_journal_directory_unsafe')
        for kind in KINDS:
            try:
                fd = os.open(plan_id+'.'+kind, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            except FileNotFoundError:
                records[kind] = times[kind] = hashes[kind] = None
                continue
            except OSError:
                raise guard.GuardError('diagnostic_journal_file_unreadable') from None
            try:
                info = os.fstat(fd)
            except Exception:
                os.close(fd)
                raise
            raw = guard.read_fd(fd, True)  # Checks ownership/permissions/size and closes fd.
            try:
                records[kind] = json.loads(raw)
            except (ValueError, UnicodeError):
                raise guard.GuardError('diagnostic_journal_json_invalid') from None
            times[kind], hashes[kind] = finite(info.st_mtime), installer.sha(raw)
    except OSError:
        raise guard.GuardError('diagnostic_journal_file_unreadable') from None
    finally:
        os.close(directory)
    return records, times, hashes


def summarize(records, times, binding):
    receipt = records.get('recovery')
    state, request = records.get('service'), records.get('recheck')
    state = {} if state is None else state
    # A receipt replaces legacy request semantics, including its old JSON shape.
    request = {} if receipt is not None or request is None else request
    if not isinstance(state, dict) or not isinstance(request, dict):
        raise guard.GuardError('service_state_invalid')
    token = request.get('request')
    valid = isinstance(token, str) and re.fullmatch('[a-f0-9]{32}', token) is not None
    fault = state.get('fault')
    renewal = records.get('renewal')
    request_time, renewal_time = times.get('recheck'), times.get('renewal')
    summary = {
        'service_bound_to_plan': state.get('plan_sha256') == binding,
        'recheck_bound_to_plan': request.get('plan_sha256') == binding if request else None,
        'renewal_bound_to_plan': renewal.get('plan_sha256') == binding if isinstance(renewal, dict) else None,
        'request_present': bool(request), 'request_valid': valid,
        'request_seen_by_service': state.get('request') == token if valid else None,
        'request_modified_at': request_time, 'renewal_modified_at': renewal_time,
        'renewal_saved_after_request': renewal_time > request_time
            if request_time is not None and renewal_time is not None else None,
        'latched_fault': fault if isinstance(fault, str) and fault in service.FAULTS else None,
        'fault_at': finite(state.get('fault_at')),
        'fault_detail': service.safe_detail(state.get('fault_detail')),
        'fault_diagnostic': policy.safe_diagnostic(state.get('fault_diagnostic')),
        'running_journal_marker': state.get('running') is True,
        'last_manual_attempt_result_available': False,
    }
    if receipt is not None:
        try:
            recovery.validate(receipt)
            if receipt['plan_sha256'] != binding or receipt['plan_id'] != records['plan']['id']:
                raise recovery.ReceiptError('recovery_plan_mismatch')
        except (recovery.ReceiptError, KeyError, TypeError):
            raise guard.GuardError('diagnostic_recovery_invalid') from None
        same_instance = (receipt['service_instance'] == state.get('service_instance') and
                         receipt['runtime_sha256'] == state.get('runtime_sha256'))
        summary.update(
            request_source='recovery', request_present=True, request_valid=True, recheck_bound_to_plan=True,
            request_seen_by_service=(same_instance and state.get('request') == receipt['request_id'] and
                                     state.get('request_revision') == receipt['revision']),
            request_modified_at=times.get('recovery'), request_received_at=receipt['received_at'],
            # Receipt mtime reflects transitions, not the user's request time.
            renewal_saved_after_request=None,
            renewal_saved_after_request_received=(renewal_time > receipt['received_at']
                                                  if renewal_time is not None else None),
            last_manual_attempt_result_available=receipt['status'] not in recovery.ACTIVE,
            manual_attempt_same_service_instance=same_instance,
            manual_attempt={key: receipt[key] for key in (
                'status', 'reason', 'revision', 'received_at', 'started_at', 'checked_at', 'finished_at',
                'request_deadline', 'evidence_expires_at')})
    else:
        summary['request_source'] = 'legacy_recheck'
    return summary


def probe(plan):
    started, stage, result = time.monotonic(), 'collect', {}
    try:
        sample = service.collect(plan)
        result['sampling_diagnostic'] = service.sampling_diagnostic(sample)
        stage = 'pf_readonly_health'
        observed = guard.health(plan, guard.PF(), guard.Store(), evidence=sample['policy'])
        checks = observed.get('checks')
        if (not isinstance(checks, dict) or set(checks) != set(service.CHECKS) or
                any(type(value) is not bool for value in checks.values())):
            raise guard.GuardError('pf_check_failed')
        result['checks'] = checks
        stage = 'post_health_freshness'
        deadline = service.evidence_deadline(plan, sample, phase='pf_check')
        result.update(reason='current_sample_and_pf_checks_passed' if all(checks.values())
                      else 'current_pf_checks_not_all_passed', remaining_seconds=max(0, deadline-time.time()))
    except (guard.GuardError, guard.LabError, policy.PolicyError) as error:
        code = str(error)
        result.update(reason=code if code in PROBE_CODES else 'diagnostic_stage_failed',
                      fault_diagnostic=policy.safe_diagnostic(getattr(error, 'diagnostic', None)))
    except Exception:
        result['reason'] = 'diagnostic_stage_failed'
    result.update(stage=stage, duration_seconds=time.monotonic()-started)
    return result


def diagnose(plan_id):
    with at_stage('manifest_sources'):
        manifest = verified_manifest(plan_id)
    with at_stage('snapshot_before'):
        before, times_before, hashes_before = snapshot(plan_id)
    with at_stage('plan_binding'):
        plan = before['plan']
        if (not isinstance(plan, dict) or plan.get('id') != plan_id or
                policy.fingerprint(plan) != manifest.get('plan_sha256')):
            raise guard.GuardError('diagnostic_plan_binding_mismatch')
        binding = policy.fingerprint(plan)
    with at_stage('summary_before'):
        before_summary = summarize(before, times_before, binding)
    with at_stage('current_probe'):
        result = probe(plan)
    with at_stage('snapshot_after'):
        after, times_after, hashes_after = snapshot(plan_id)
    with at_stage('summary_after'):
        after_summary = summarize(after, times_after, binding)
    return {
        'version': 1, 'mode': 'readonly_service_diagnostic', 'reason': 'diagnostic_completed',
        'runtime_sources_match': True,
        'scope': 'non-atomic receipt history and independent current probe; probe is not the manual result',
        'before': before_summary, 'current_root_probe': result,
        'after': after_summary,
        'changed_during_probe': {kind: hashes_before[kind] != hashes_after[kind] for kind in KINDS},
        'pf_modified': False, 'state_modified': False,
        'protection_verified': False, 'launch_authorized': False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--id', required=True)
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise guard.GuardError('administrator_required_no_changes')
        report = diagnose(guard.identity(args.id))
    except Exception as error:
        code = str(error)
        stage = getattr(error, 'diagnostic_stage', 'entry')
        report = {'reason': code if code in INPUT_CODES else 'diagnostic_input_or_source_check_failed',
                  'stage': stage if isinstance(stage, str) and stage in STAGES else 'entry',
                  'pf_modified': False, 'state_modified': False,
                  'protection_verified': False, 'launch_authorized': False}
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0 if report['reason'] == 'diagnostic_completed' else 78


if __name__ == '__main__':
    raise SystemExit(main())
