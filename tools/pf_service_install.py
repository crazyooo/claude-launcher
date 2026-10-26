#!/usr/bin/env python3
"""Install an explicitly selected PF observer as a root launchd job; never apply PF."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import time
import uuid
import pf_runtime_identity as runtime_identity

from pf_guard import PF, Store, GuardError, health, identity
from pf_policy import dns_evidence, fingerprint
from pf_service import ROOT, atomic, safe_read, trusted_directory, publish

LABEL = 'local.crazymax.claude-pf-observer'
PLIST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
FILES = runtime_identity.FILES
MANIFEST = ROOT / 'installation.json'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class LaunchdError(GuardError):
    def __init__(self, operation, exit_code=None, timed_out=False):
        super().__init__('launchd_operation_failed_files_preserved')
        self.diagnostic = {'operation': operation, 'exit_code': exit_code, 'timed_out': timed_out}


def launchctl(*args, timeout=15, check=True):
    try:
        result = subprocess.run(['/bin/launchctl', *args], capture_output=True, timeout=timeout,
                                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    except subprocess.TimeoutExpired:
        raise LaunchdError(args[0], timed_out=True) from None
    if check and result.returncode:
        raise LaunchdError(args[0], exit_code=result.returncode)
    return result


def job_snapshot(timeout=5):
    result = launchctl('print', 'system/' + LABEL, timeout=timeout, check=False)
    absent = f'Could not find service "{LABEL}" in domain for system'
    if result.returncode == 113 and absent in result.stderr.decode('utf-8', errors='replace').splitlines():
        return None
    if result.returncode:
        raise LaunchdError('print', exit_code=result.returncode)
    # launchctl print is a diagnostic format, not a stable API. Unknown or
    # ambiguous identity must preserve the loaded job instead of stopping it.
    try:
        return runtime_identity.parse_job(result.stdout.decode('utf-8', errors='strict'))
    except runtime_identity.IdentityError as error:
        raise GuardError(str(error)) from None


def job_matches(snapshot, manifest):
    expected = definition(manifest['plan_id'], Path(manifest['runtime']))
    return (snapshot['path'] == str(PLIST) and snapshot['program'] == '/usr/bin/python3' and
            snapshot['cwd'] == expected['WorkingDirectory'] and
            snapshot['arguments'] == expected['ProgramArguments'])


def pid_gone(pid):
    try:
        os.kill(pid, 0)  # Existence probe only; never signals or kills a process.
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def stop_job(manifest, snapshot=None):
    current = job_snapshot() if snapshot is None else snapshot
    if current is not None and not job_matches(current, manifest):
        raise GuardError('loaded_service_identity_mismatch_preserved')
    pids = manifest.get('stop_pids', [])
    if (not isinstance(pids, list) or len(pids) > 16 or
            any(type(pid) is not int or pid <= 1 for pid in pids)):
        raise GuardError('invalid_pending_stop')
    pids = sorted(set(pids + ([current['pid']] if current and current['pid'] else [])))
    # Persist before bootout: a retry must still wait for a removed job's old
    # process. Keep phase so interrupted upgrades retain their plist ownership.
    manifest.update(stop_requested=True, stop_pids=pids)
    write_manifest(manifest)
    outcome = manifest.get('last_stop_attempt')
    if current is not None:
        try:
            result = launchctl('bootout', 'system/' + LABEL, check=False)
            outcome = {'operation': 'bootout', 'exit_code': result.returncode, 'timed_out': False}
        except LaunchdError as error:
            outcome = error.diagnostic
        manifest['last_stop_attempt'] = outcome
        write_manifest(manifest)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        observed = job_snapshot(timeout=min(2, max(0.01, deadline - time.monotonic())))
        if observed is None and all(pid_gone(pid) for pid in pids):
            manifest.update(stop_requested=False, stop_pids=[],
                            last_stop={'effect': 'job_absent_old_processes_exited', 'bootout': outcome})
            write_manifest(manifest)
            return manifest['last_stop']
        if observed is not None and not job_matches(observed, manifest):
            raise GuardError('loaded_service_identity_mismatch_preserved')
        if observed is not None and observed['pid'] is not None and observed['pid'] not in pids:
            if len(pids) >= 16:
                raise GuardError('too_many_service_processes_preserved')
            pids.append(observed['pid'])
            manifest['stop_pids'] = sorted(pids)
            write_manifest(manifest)
        time.sleep(min(0.2, max(0, deadline - time.monotonic())))
    error = LaunchdError('wait_for_removal', timed_out=True)
    error.diagnostic['bootout'] = outcome
    raise error


@contextmanager
def installation_lock():
    trusted_directory(ROOT.parent)
    try:
        ROOT.mkdir(mode=0o755)
        ROOT.chmod(0o755)
    except FileExistsError:
        pass
    trusted_directory(ROOT)
    fd = os.open(ROOT / 'install.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
            raise GuardError('unsafe_service_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise GuardError('service_installation_in_progress') from None
        yield
    finally:
        os.close(fd)


def package():
    source = Path(__file__).resolve().parent
    # Explicit administrator installation is the trust boundary. Copy only these
    # bounded regular files; launchd never executes the writable source checkout.
    result = {}
    for name in FILES:
        path = source / name
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
                raise GuardError('invalid_service_source')
            result[name] = stream.read(1024 * 1024 + 1)
            if len(result[name]) > 1024 * 1024:
                raise GuardError('invalid_service_source')
    return result


def definition(plan_id, runtime):
    return runtime_identity.definition(identity(plan_id), runtime)


def read_manifest():
    try:
        value = json.loads(safe_read(MANIFEST))
    except FileNotFoundError:
        return None
    try:
        runtime_identity.manifest_layout(value, ROOT)
    except runtime_identity.IdentityError as error:
        raise GuardError(str(error)) from None
    return value


def verify_files(manifest):
    try:
        layout = runtime_identity.manifest_layout(manifest, ROOT)
    except runtime_identity.IdentityError as error:
        raise GuardError(str(error)) from None
    verify_control_file(manifest)
    runtime = Path(manifest['runtime'])
    if runtime.exists():
        trusted_directory(runtime)
        if any(path.name not in layout for path in runtime.iterdir()):
            raise GuardError('unknown_runtime_file_preserved')
        for name, expected in manifest['files'].items():
            path = runtime / name
            if path.exists() or path.is_symlink():
                if sha(safe_read(path, limit=1024 * 1024)) != expected:
                    raise GuardError('modified_runtime_preserved')
    if PLIST.exists() or PLIST.is_symlink():
        permitted = {manifest['plist_sha256']}
        if manifest.get('phase') == 'install_pending':
            permitted.add(manifest.get('previous_plist_sha256'))
        if sha(safe_read(PLIST)) not in permitted:
            raise GuardError('modified_launchd_plist_preserved')


def verify_control_file(manifest):
    path = ROOT / 'pf_control.py'
    present = path.exists() or path.is_symlink()
    if 'pf_control.py' not in manifest['files']:
        if present:
            raise GuardError('unowned_control_entry_preserved')
        return
    if present:
        permitted = {manifest['control_sha256']}
        if manifest['phase'] == 'install_pending':
            permitted.add(manifest.get('previous_control_sha256'))
        if sha(safe_read(path, limit=1024 * 1024)) not in permitted:
            raise GuardError('modified_control_entry_preserved')


def install_control_file(manifest, content):
    verify_control_file(manifest)
    path = ROOT / 'pf_control.py'
    if path.exists() or path.is_symlink():
        if sha(safe_read(path, limit=1024 * 1024)) == manifest['control_sha256']:
            return
        # Prior owned bytes remain recoverable; interrupted replacement retries
        # are bound to the already persisted install_pending manifest.
        os.rename(path, ROOT / ('archived-control-' + uuid.uuid4().hex + '.py'))
    atomic(path, content, 0o644, staging_directory=ROOT)


def write_manifest(value):
    atomic(MANIFEST, json.dumps(value, sort_keys=True).encode())


def check_active_plan(plan, pf, store, expected_hash=None):
    if expected_hash is not None and fingerprint(plan) != expected_hash:
        raise GuardError('plan_changed_before_service_activation')
    result = health(plan, pf, store)
    if not all(result['checks'][k] for k in ('installed', 'pf_enabled', 'root_matches', 'destinations_match')):
        raise GuardError('active_applied_plan_required_no_pf_changes')


def installation_result(reason, plan_id, runtime):
    result = {'reason': reason, 'plan_id': plan_id,
            'recheck_command': f'sudo /usr/bin/python3 -E -s -B "{runtime / "pf_service.py"}" recheck --id {plan_id}',
            'restore_command': f'sudo /usr/bin/python3 -E -s -B "{runtime / "pf_guard.py"}" restore --id {plan_id}'}
    if 'pf_control.py' in FILES:
        result.update(control_entry=str(ROOT / 'pf_control.py'), control_version=1)
    return result


def install(plan_id):
    store, pf = Store(), PF()
    with store.lock():
        plan = store.read(identity(plan_id), 'plan')
        if plan['id'] != plan_id:
            raise GuardError('plan_identity_mismatch')
        dns_evidence(plan['policy'], fresh=False)
        check_active_plan(plan, pf, store)
    content = package()
    hashes = {name: sha(data) for name, data in content.items()}
    runtime = ROOT / ('runtime-' + fingerprint(hashes))
    plist = plistlib.dumps(definition(plan_id, runtime), sort_keys=True)
    previous = read_manifest()
    desired = {'plan_id': plan_id, 'plan_sha256': fingerprint(plan), 'runtime': str(runtime),
               'files': hashes, 'plist_sha256': sha(plist)}
    control = ROOT / 'pf_control.py'
    if 'pf_control.py' in content:
        desired.update(control_version=1, control_sha256=hashes['pf_control.py'])
    if previous:
        verify_files(previous)
        loaded = job_snapshot()
        if loaded is not None and not job_matches(loaded, previous):
            raise GuardError('loaded_service_identity_mismatch_preserved')
        identical = all(previous.get(key) == value for key, value in desired.items())
        complete = (PLIST.exists() and sha(safe_read(PLIST)) == sha(plist) and
                    all((runtime / name).is_file() for name in FILES))
        if 'pf_control.py' in content:
            complete = (complete and control.is_file() and
                        sha(safe_read(control, limit=1024 * 1024)) == hashes['pf_control.py'])
        if (identical and complete and loaded is not None and not previous.get('stop_requested') and
                previous.get('phase') in ('installed', 'bootstrap_pending')):
            with store.lock():
                check_active_plan(store.read(plan_id, 'plan'), pf, store, desired['plan_sha256'])
            if previous['phase'] == 'bootstrap_pending':
                previous['phase'] = 'installed'
                write_manifest(previous)
            return installation_result('observer_already_loaded_state_preserved', plan_id, runtime)
        stop_job(previous, loaded)
    elif control.exists() or control.is_symlink():
        raise GuardError('unowned_control_entry_preserved')
    elif PLIST.exists() or PLIST.is_symlink():
        raise GuardError('unowned_launchd_plist_preserved')
    elif job_snapshot() is not None:
        raise GuardError('unowned_loaded_service_preserved')
    manifest = {'version': 1, 'phase': 'install_pending', **desired,
                'previous_plist_sha256': sha(safe_read(PLIST)) if PLIST.exists() else None}
    if 'pf_control.py' in content:
        manifest['previous_control_sha256'] = sha(safe_read(control, limit=1024 * 1024)) if control.exists() else None
    if previous and 'last_stop' in previous:
        manifest['last_stop'] = previous['last_stop']
    # Durable expected bytes permit a safe retry after partial installation.
    write_manifest(manifest)
    try:
        runtime.mkdir(mode=0o755)
        runtime.chmod(0o755)
    except FileExistsError:
        pass
    trusted_directory(runtime)
    if any(path.name not in FILES for path in runtime.iterdir()):
        raise GuardError('unknown_runtime_file_preserved')
    for name, data in content.items():
        path = runtime / name
        if path.exists() or path.is_symlink():
            if sha(safe_read(path, limit=1024 * 1024)) != hashes[name]:
                raise GuardError('modified_runtime_preserved')
        else:
            # Keep incomplete writes outside the executable directory. A crash
            # leaves recoverable bytes in ROOT, not an unknown Python import.
            atomic(path, data, 0o644, staging_directory=ROOT)
    if 'pf_control.py' in content:
        install_control_file(manifest, content['pf_control.py'])
    trusted_directory(PLIST.parent)
    atomic(PLIST, plist, 0o644)
    manifest['phase'] = 'bootstrap_pending'
    write_manifest(manifest)
    # Recheck after copying/stopping; restore may have run during preparation.
    with store.lock():
        current = store.read(plan_id, 'plan')
        check_active_plan(current, pf, store, manifest['plan_sha256'])
        launchctl('bootstrap', 'system', str(PLIST))
    launchctl('print', 'system/' + LABEL)
    manifest['phase'] = 'installed'
    write_manifest(manifest)
    return installation_result('observer_installed_network_validation_pending', plan_id, runtime)


def uninstall():
    manifest = read_manifest()
    if manifest is None:
        return {'reason': 'no_owned_observer_installation'}
    verify_files(manifest)
    stop_job(manifest)
    if PLIST.exists():
        # Recoverable archive, not permanent deletion. Retain root-owned runtime
        # so the independent restore command keeps working after observer removal.
        os.rename(PLIST, ROOT / ('archived-' + uuid.uuid4().hex + '.plist'))
    control = ROOT / 'pf_control.py'
    if 'pf_control.py' in manifest['files'] and control.exists():
        os.rename(control, ROOT / ('archived-control-' + uuid.uuid4().hex + '.py'))
    manifest['phase'] = 'uninstalled'
    write_manifest(manifest)
    publish({'version': 1, 'plan_id': manifest['plan_id'], 'checked_at': time.time(),
             'status': 'stopped', 'service_running': False, 'rules_observed': False,
             'evidence_fresh': False, 'manual_recheck_required': True, 'reason': 'service_stopped',
             'protection_verified': False, 'launch_authorized': False})
    return {'reason': 'observer_uninstalled_pf_rules_preserved_runtime_retained_for_restore'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('install', 'uninstall'))
    parser.add_argument('--id')
    args = parser.parse_args(argv)
    try:
        if os.geteuid() != 0:
            raise GuardError('administrator_required_no_changes')
        if (args.mode == 'install') != (args.id is not None):
            raise GuardError('plan_id_required_only_for_install')
        with installation_lock():
            result = install(args.id) if args.mode == 'install' else uninstall()
        print(json.dumps({**result, 'pf_rules_applied': False, 'launch_authorized': False}, indent=2))
        return 0
    except Exception as error:
        # Fixed GuardError codes only; no system output or file contents.
        failure = {'reason': str(error) if isinstance(error, GuardError) else 'service_installation_failed_files_preserved',
                   'launch_authorized': False}
        if isinstance(error, LaunchdError):
            failure['launchd_error'] = error.diagnostic
        print(json.dumps(failure))
        return 78


if __name__ == '__main__':
    raise SystemExit(main())
