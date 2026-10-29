"""Installed PF runtime identity. No PF calls, installation, or network access.

The installer may repair incomplete owned files. Control commands must instead
use verify_complete while holding control_lock, then the private Store.lock.
Legacy four/six-file installations are recognized for upgrade and removal only.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess

ROOT = Path('/Library/Application Support/Claude Launcher PF')
LABEL = 'local.crazyooo.claude-pf-observer'
PLIST = Path('/Library/LaunchDaemons') / (LABEL + '.plist')
LEGACY_FILES = ('pf_service.py', 'pf_guard.py', 'pf_policy.py', 'pf_lab.py')
RECEIPT_FILES = LEGACY_FILES + ('pf_runtime_identity.py', 'pf_recovery_receipt.py')
FILES = RECEIPT_FILES + ('pf_control.py',)
LAYOUTS = (frozenset(LEGACY_FILES), frozenset(RECEIPT_FILES), frozenset(FILES))


class IdentityError(Exception):
    """Only fixed local error codes, never remote text or private records."""


def require(condition, reason):
    if not condition:
        raise IdentityError(reason)


def hex_value(value, length):
    return isinstance(value, str) and re.fullmatch('[a-f0-9]{%d}' % length, value) is not None


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def manifest_layout(value, root=ROOT):
    require(isinstance(value, dict) and type(value.get('version')) is int and value['version'] == 1,
            'invalid_service_manifest')
    files = value.get('files')
    require(isinstance(files, dict) and frozenset(files) in LAYOUTS and
            all(hex_value(item, 64) for item in files.values()), 'invalid_service_manifest')
    require(hex_value(value.get('plan_id'), 32) and hex_value(value.get('plan_sha256'), 64) and
            hex_value(value.get('plist_sha256'), 64), 'invalid_service_manifest')
    require(value.get('runtime') == str(root / ('runtime-' + fingerprint(files))), 'invalid_service_runtime')
    require(value.get('phase') in ('install_pending', 'bootstrap_pending', 'installed', 'uninstalled'),
            'invalid_service_manifest')
    if set(files) == set(FILES):
        require(type(value.get('control_version')) is int and value['control_version'] == 1 and
                value.get('control_sha256') == files['pf_control.py'], 'invalid_control_manifest')
        previous = value.get('previous_control_sha256')
        require(previous is None or hex_value(previous, 64), 'invalid_control_manifest')
    else:
        require(not any(key in value for key in ('control_version', 'control_sha256', 'previous_control_sha256')),
                'invalid_control_manifest')
    return tuple(name for name in FILES if name in files)


def definition(plan_id, runtime):
    require(hex_value(plan_id, 32), 'invalid_plan_id')
    return {
        'Label': LABEL,
        'ProgramArguments': ['/usr/bin/python3', '-E', '-s', '-B', str(runtime / 'pf_service.py'), 'run', '--id', plan_id],
        'WorkingDirectory': str(runtime),
        'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'},
        'RunAtLoad': True, 'KeepAlive': True, 'ThrottleInterval': 10,
        'ProcessType': 'Background', 'Umask': 0o077,
        'StandardOutPath': '/dev/null', 'StandardErrorPath': '/dev/null',
    }


def trusted_directory(path, owner=0):
    for component in [*reversed(path.parents), path]:
        info = component.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022,
                'untrusted_service_directory')


def safe_read(path, owner=0, limit=65536):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == owner and not info.st_mode & 0o022 and
                info.st_nlink == 1 and info.st_size <= limit, 'untrusted_service_file')
        value = stream.read(limit + 1)
        require(len(value) <= limit, 'service_file_too_large')
        return value


@contextmanager
def control_lock(root=ROOT):
    """Open the installed lock only; never create a directory or install a job."""
    trusted_directory(root)
    fd = os.open(root / 'install.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'unsafe_service_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise IdentityError('service_installation_in_progress') from None
        yield
    finally:
        os.close(fd)


def verify_complete(value, *, root=ROOT, plist=PLIST, service_file=None, startup=False):
    layout = manifest_layout(value, root)
    require(value['phase'] in (('installed', 'bootstrap_pending') if startup else ('installed',)),
            'current_installation_required')
    require(value.get('stop_requested', False) is False and value.get('stop_pids', []) == [],
            'service_stop_pending')
    runtime = Path(value['runtime'])
    trusted_directory(runtime)
    trusted_directory(plist.parent)
    require({item.name for item in runtime.iterdir()} == set(layout), 'runtime_files_incomplete')
    for name in layout:
        require(digest(safe_read(runtime / name, limit=1024 * 1024)) == value['files'][name],
                'runtime_digest_mismatch')
    if 'pf_control.py' in layout:
        require(digest(safe_read(root / 'pf_control.py', limit=1024 * 1024)) == value['control_sha256'],
                'control_digest_mismatch')
    raw = safe_read(plist)
    require(raw == plistlib.dumps(definition(value['plan_id'], runtime), sort_keys=True) and
            digest(raw) == value['plist_sha256'], 'launchd_definition_mismatch')
    if service_file is not None:
        require(Path(service_file).absolute() == runtime / 'pf_service.py', 'stale_runtime_command')
    return runtime


def parse_job(raw):
    """Parse only the identity fields of launchctl's bounded diagnostic format."""
    require(len(raw) <= 65536 and raw.startswith('system/' + LABEL + ' = {'), 'launchd_status_unknown')
    fields = {}
    for key in ('path', 'program', 'working directory', 'state', 'active count'):
        matches = re.findall(r'^\t' + re.escape(key) + r' = (.+)$', raw, re.M)
        require(len(matches) == 1, 'launchd_status_unknown')
        fields[key] = matches[0].strip()
    blocks = re.findall(r'^\targuments = \{\n((?:\t\t[^\n]*\n)*)\t\}', raw, re.M)
    pids = re.findall(r'^\tpid = ([1-9][0-9]*)$', raw, re.M)
    require(len(blocks) == 1 and len(pids) <= 1 and fields['active count'].isdigit(), 'launchd_status_unknown')
    pid = int(pids[0]) if pids else None
    require((pid is not None and pid > 1) or
            (pid is None and fields['state'] != 'running' and int(fields['active count']) == 0),
            'launchd_status_unknown')
    return {'pid': pid, 'path': fields['path'], 'program': fields['program'],
            'cwd': fields['working directory'],
            'arguments': [line.strip() for line in blocks[0].splitlines() if line.strip()]}


def running_job():
    result = subprocess.run(['/bin/launchctl', 'print', 'system/' + LABEL], capture_output=True, timeout=5,
                            env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
    require(result.returncode == 0, 'service_not_running')
    return parse_job(result.stdout.decode('utf-8', errors='strict'))


def verify_running(value, snapshot, plist=PLIST):
    expected = definition(value['plan_id'], Path(value['runtime']))
    require(isinstance(snapshot, dict) and type(snapshot.get('pid')) is int and snapshot['pid'] > 1 and
            snapshot.get('path') == str(plist) and snapshot.get('program') == '/usr/bin/python3' and
            snapshot.get('cwd') == expected['WorkingDirectory'] and
            snapshot.get('arguments') == expected['ProgramArguments'], 'loaded_service_identity_mismatch')
    return snapshot['pid']


def installed_for_plan(plan, service_file, *, startup=False, root=ROOT, plist=PLIST):
    trusted_directory(root)
    value = json.loads(safe_read(root / 'installation.json'))
    runtime = verify_complete(value, root=root, plist=plist, service_file=service_file, startup=startup)
    require(set(value['files']) == set(FILES), 'service_upgrade_required')
    require(value['plan_id'] == plan.get('id') and value['plan_sha256'] == fingerprint(plan),
            'service_plan_binding_mismatch')
    pid = verify_running(value, running_job(), plist)
    return {'runtime_sha256': fingerprint(value['files']), 'runtime': str(runtime), 'service_pid': pid}


def verify_instance(state, installation, plan):
    require(isinstance(state, dict) and type(state.get('version')) is int and state['version'] == 1 and
            state.get('plan_sha256') == fingerprint(plan) and state.get('running') is True and
            hex_value(state.get('service_instance'), 32) and
            type(state.get('service_pid')) is int and state['service_pid'] == installation['service_pid'] and
            state.get('runtime_sha256') == installation['runtime_sha256'], 'service_instance_mismatch')
    return {key: state[key] for key in ('service_instance', 'service_pid', 'runtime_sha256')}
