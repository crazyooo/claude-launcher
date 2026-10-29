#!/usr/bin/env python3
"""Own only the local connector LaunchAgent; leave proxy/VPN/PF untouched."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import tempfile
import time

ROOT = Path.home() / 'Library/Application Support/ClaudeLauncher'
LABEL = 'local.crazyooo.claude-connector'
PLIST = Path.home() / 'Library/LaunchAgents' / (LABEL + '.plist')
MANIFEST = ROOT / 'connector-installation.json'
TOOL = Path.home() / 'Applications/Claude Launcher.app/Contents/MacOS/launcher-tool'
DOMAIN = 'gui/' + str(os.getuid())

class ServiceError(Exception):
    pass

def run(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, timeout=timeout,
                          env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})

def private(path, directory=False):
    info = path.lstat()
    if (path.resolve() != path.absolute() or info.st_uid != os.getuid() or
        info.st_mode & 0o077 or (not directory and info.st_nlink != 1) or
        not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))):
        raise ServiceError('untrusted_connector_file')

def read(path):
    private(path)
    if path.stat().st_size > 16384:
        raise ServiceError('connector_file_too_large')
    return path.read_bytes()

def atomic(path, data):
    descriptor, name = tempfile.mkstemp(prefix='.connector-', dir=path.parent)
    with os.fdopen(descriptor, 'wb') as stream:
        os.fchmod(stream.fileno(), 0o600); stream.write(data); stream.flush(); os.fsync(stream.fileno())
    os.replace(name, path)
    directory = os.open(path.parent, os.O_RDONLY)
    try: os.fsync(directory)
    finally: os.close(directory)

def digest(data):
    return hashlib.sha256(data).hexdigest()

def job():
    result = run(['/bin/launchctl', 'print', DOMAIN + '/' + LABEL])
    absent = 'Could not find service "' + LABEL + '" in domain for user gui: ' + str(os.getuid())
    if result.returncode == 113 and absent in result.stderr.decode('utf-8', errors='replace').splitlines():
        return None
    if result.returncode: raise ServiceError('connector_job_query_failed')
    raw = result.stdout.decode('utf-8')
    if len(raw) > 65536 or not raw.startswith(DOMAIN + '/' + LABEL + ' = {'):
        raise ServiceError('connector_job_format_unknown')
    values = {}
    for key in ('path', 'program', 'state', 'active count'):
        matches = re.findall(r'^\t' + re.escape(key) + r' = (.+)$', raw, re.M)
        if len(matches) != 1: raise ServiceError('connector_job_format_unknown')
        values[key] = matches[0].strip()
    blocks = re.findall(r'^\targuments = \{\n((?:\t\t[^\n]*\n)*)\t\}', raw, re.M)
    pids = re.findall(r'^\tpid = ([1-9][0-9]*)$', raw, re.M)
    if len(blocks) != 1 or len(pids) > 1 or not values['active count'].isdigit():
        raise ServiceError('connector_job_format_unknown')
    arguments = [line.strip() for line in blocks[0].splitlines() if line.strip()]
    if values['path'] != str(PLIST) or values['program'] != str(TOOL) or arguments != [str(TOOL), 'connector-guard']:
        raise ServiceError('connector_loaded_identity_mismatch')
    pid = int(pids[0]) if pids else 0
    if pid <= 1 and (values['state'] == 'running' or int(values['active count']) > 0):
        raise ServiceError('connector_job_format_unknown')
    return pid

def descendants(root):
    result = run(['/bin/ps', '-axo', 'pid=,ppid='])
    if result.returncode:
        raise ServiceError('process_inventory_failed')
    rows = [tuple(map(int, line.split())) for line in result.stdout.splitlines() if len(line.split()) == 2]
    found = {root} if root else set()
    while True:
        expanded = found | {pid for pid, parent in rows if parent in found}
        if expanded == found: return found
        found = expanded

def alive(pid):
    try: os.kill(pid, 0); return True
    except ProcessLookupError: return False

def ownership():
    value = json.loads(read(MANIFEST)) if MANIFEST.exists() else {}
    if PLIST.exists() or PLIST.is_symlink():
        if digest(read(PLIST)) != value.get('plist_sha256'):
            raise ServiceError('connector_agent_not_owned')
    elif job() is not None:
        raise ServiceError('loaded_connector_without_owned_plist')
    return value

def await_stopped(value):
    pending = value.get('pending_stop_pids', [])
    if not isinstance(pending, list) or any(type(p) is not int or p <= 1 for p in pending):
        raise ServiceError('connector_stop_record_invalid')
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if job() is None and not any(alive(p) for p in pending):
            value.pop('pending_stop_pids', None)
            atomic(MANIFEST, json.dumps(value).encode())
            return
        time.sleep(.1)
    raise ServiceError('connector_stop_pending')


def stop(value):
    if value.get('pending_stop_pids'):
        if job() is not None:
            run(['/bin/launchctl', 'bootout', DOMAIN, str(PLIST)])
        await_stopped(value)
    pid = job()
    if pid is None: return
    if not value.get('plist_sha256'):
        raise ServiceError('connector_agent_not_owned')
    # Try graceful BLOCK first; a broken control pipe must not make an owned
    # failed job impossible to stop. Bootout + all-process exit is the fallback.
    try:
        run([str(TOOL), 'connector', 'block'], timeout=6)
    except (OSError, subprocess.TimeoutExpired):
        pass
    processes = descendants(pid)
    value['pending_stop_pids'] = sorted(processes)
    atomic(MANIFEST, json.dumps(value).encode())
    result = run(['/bin/launchctl', 'bootout', DOMAIN, str(PLIST)])
    if result.returncode and job() is not None:
        raise ServiceError('connector_bootout_failed')
    await_stopped(value)

def healthy(snapshot):
    if not isinstance(snapshot, dict): return False
    sampled = snapshot.get('sampledAt')
    age = snapshot.get('heartbeatAge')
    return (type(sampled) in (int, float) and 0 <= time.time() - (sampled + 978307200) < 4 and
            type(age) in (int, float) and 0 <= age < 3 and
            snapshot.get('state') in ('blocked', 'checking', 'allowed') and
            type(snapshot.get('port')) is int and 0 < snapshot['port'] <= 65535 and
            snapshot.get('launchAuthorized') is False and snapshot.get('protectionVerified') is False)


def operate(action):
    if ROOT.resolve() != ROOT.absolute(): raise ServiceError('untrusted_connector_directory')
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700); private(ROOT, directory=True)
    descriptor = os.open(ROOT / 'connector-install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ServiceError('untrusted_connector_lock')
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        value = ownership()
        if action in ('stop', 'uninstall'):
            stop(value)
            if action == 'uninstall' and PLIST.exists():
                script = 'tell application "Finder" to delete POSIX file ' + json.dumps(str(PLIST))
                if run(['/usr/bin/osascript', '-e', script]).returncode:
                    raise ServiceError('connector_trash_failed')
            return {'reason': 'connector_stopped', 'launch_authorized': False}
        if not TOOL.is_file(): raise ServiceError('installed_tool_missing')
        if run(['/usr/bin/codesign', '--verify', '--strict', str(TOOL)]).returncode:
            raise ServiceError('installed_tool_signature_invalid')
        config = ROOT / 'connector.json'
        if not config.exists():
            atomic(config, json.dumps(dict(version=1, upstreamProtocol='http', upstreamHost='127.0.0.1',
                   upstreamPort=1082, expectedIPv4='203.0.113.43', expectedIPv6='', listenPort=0)).encode())
        else: read(config)
        PLIST.parent.mkdir(parents=True, exist_ok=True)
        data = plistlib.dumps(dict(Label=LABEL, ProgramArguments=[str(TOOL), 'connector-guard'],
            RunAtLoad=True, KeepAlive=True, ThrottleInterval=10, ProcessType='Background',
            Umask=0o077, StandardOutPath='/dev/null', StandardErrorPath='/dev/null'))
        binding = {'version': 1, 'plist_sha256': digest(data),
                   'tool_sha256': digest(TOOL.read_bytes()), 'config_sha256': digest(read(config))}
        current_pid = job()
        if not value.get('pending_stop_pids') and current_pid and all(value.get(k) == v for k, v in binding.items()):
            try:
                response = run([str(TOOL), 'connector', 'status'], timeout=4)
                snapshot = json.loads(response.stdout) if response.returncode == 0 else {}
                if healthy(snapshot):
                    return {'reason': 'connector_already_running', 'launch_authorized': False}
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        stop(value)
        atomic(MANIFEST, json.dumps(binding).encode())
        atomic(PLIST, data)
        if run(['/bin/launchctl', 'bootstrap', DOMAIN, str(PLIST)]).returncode:
            raise ServiceError('connector_bootstrap_failed_files_preserved')
        # A loaded job alone is not proof the gateway and API are responsive.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            response = run([str(TOOL), 'connector', 'status'], timeout=4)
            if response.returncode == 0:
                state = json.loads(response.stdout)
                if state.get('port', 0) > 0 and state.get('state') == 'blocked':
                    return {'reason': 'connector_started_blocked', 'launch_authorized': False}
            time.sleep(.2)
        raise ServiceError('connector_start_pending_check_status')
    finally:
        os.close(descriptor)

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('start', 'stop', 'uninstall'))
    args = parser.parse_args()
    try:
        print(json.dumps(operate(args.action))); return 0
    except ServiceError as error:
        print(json.dumps({'reason': str(error), 'launch_authorized': False})); return 78
    except Exception:
        print(json.dumps({'reason': 'connector_service_operation_failed', 'launch_authorized': False})); return 78

if __name__ == '__main__': raise SystemExit(main())
