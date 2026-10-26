#!/usr/bin/env python3
"""Terminal preparation only: authenticate, sample, then stage without changing PF."""
import json
import os
import re
import shlex
from pathlib import Path
import subprocess
import tempfile

from pf_policy import PolicyError, discover, validate

STAGE_REASONS = frozenset({
    'root_baseline_requires_manual_review', 'another_destination_guard_present',
    'pf_reference_table_unknown', 'pf_status_unknown', 'destination_evidence_expired',
    'pfctl_rejected', 'pfctl_unavailable_or_timeout', 'guard_operation_in_progress',
    'unsafe_journal_directory', 'local_operation_failed_review_journal',
})


def report_failure(reason):
    print(json.dumps({'reason': reason, 'pf_modified': False,
                      'protection_verified': False, 'launch_authorized': False}))
    return 78


def save_snapshot(policy):
    descriptor, filename = tempfile.mkstemp(prefix='claude-pf-policy-', suffix='.json')
    with os.fdopen(descriptor, 'w') as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(policy, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    return filename


def main():
    if os.geteuid() == 0:
        return report_failure('run_preparation_as_normal_user')
    try:
        # Interactive authentication happens before time-limited DNS sampling.
        # Neither stdin nor the password prompt is captured by this program.
        authenticated = subprocess.run(['/usr/bin/sudo', '-v'])
        if authenticated.returncode:
            return report_failure('authentication_not_completed')
        policy = discover()
        validate(policy)
        filename = save_snapshot(policy)
        manager = str(Path(__file__).resolve().with_name('pf_guard.py'))
        result = subprocess.run(
            ['/usr/bin/sudo', '-n', '--', '/usr/bin/python3', manager, 'stage', '--policy', filename],
            capture_output=True, timeout=60,
            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
        if len(result.stdout) > 1024 * 1024:
            return report_failure('stage_output_invalid')
        try:
            output = json.loads(result.stdout)
        except (ValueError, UnicodeError):
            return report_failure('stage_failed_or_authentication_expired')
        if not isinstance(output, dict):
            return report_failure('stage_output_invalid')
        if result.returncode:
            reason = output.get('reason')
            return report_failure(reason if isinstance(reason, str) and reason in STAGE_REASONS
                                  else 'stage_failed_review_required')
        if (output.get('reason') != 'staged_only_no_pf_changes' or
                not re.fullmatch('[a-f0-9]{32}', str(output.get('id', ''))) or
                output.get('protection_verified') is not False or output.get('launch_authorized') is not False):
            return report_failure('stage_output_invalid')
        output.update(policy_snapshot=filename, pf_modified=False)
        installer = Path(__file__).resolve().with_name('pf_service_install.py')
        output['observer_install_command'] = (
            f'sudo /usr/bin/python3 {shlex.quote(str(installer))} install --id {output["id"]}')
        print(json.dumps(output, ensure_ascii=False, indent=2))
        return 0
    except PolicyError as error:
        return report_failure(str(error))
    except subprocess.TimeoutExpired:
        return report_failure('stage_timeout_no_apply_attempted')
    except KeyboardInterrupt:
        return report_failure('preparation_interrupted_no_apply_attempted')
    except (OSError, ValueError, TypeError):
        return report_failure('preparation_failed_no_apply_attempted')


if __name__ == '__main__':
    raise SystemExit(main())
