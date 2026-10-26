#!/usr/bin/env python3
"""Fixed root recheck entry; no installation, proxy, launch or PF apply actions."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path('/Library/Application Support/Claude Launcher PF')
FILES = ('pf_service.py', 'pf_guard.py', 'pf_policy.py', 'pf_lab.py',
         'pf_runtime_identity.py', 'pf_recovery_receipt.py', 'pf_control.py')


class ControlError(Exception):
    """Fixed codes only; never interpolate arguments or exception content."""


def require(condition, reason):
    if not condition:
        raise ControlError(reason)


def hex_value(value, length):
    return isinstance(value, str) and len(value) == length and all(c in '0123456789abcdef' for c in value)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fingerprint(value):
    return sha(json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode())


def trusted_directory(path):
    for component in [*reversed(path.parents), path]:
        info = component.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                'untrusted_control_directory')


def safe_read(path, limit=1024 * 1024):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                not info.st_mode & 0o022 and 0 <= info.st_size <= limit, 'untrusted_control_file')
        raw = stream.read(limit + 1)
        require(len(raw) <= limit, 'control_file_too_large')
        return raw


@contextmanager
def installation_lock():
    trusted_directory(ROOT)
    fd = os.open(ROOT / 'install.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1 and
                stat.S_IMODE(info.st_mode) == 0o600, 'unsafe_service_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ControlError('service_installation_in_progress') from None
        yield
    finally:
        os.close(fd)


class VerifiedModules(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Load only snapshotted, verified source; never add a directory to sys.path."""
    def __init__(self, runtime, sources):
        self.runtime, self.sources = runtime, sources

    def find_spec(self, fullname, path=None, target=None):
        if fullname in self.sources:
            return importlib.util.spec_from_loader(fullname, self, origin=str(self.runtime / (fullname + '.py')))
        return None

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        path = str(self.runtime / (module.__name__ + '.py'))
        module.__file__ = path
        exec(compile(self.sources[module.__name__], path, 'exec'), module.__dict__)


def verified_sources(manifest):
    require(isinstance(manifest, dict) and type(manifest.get('version')) is int and manifest['version'] == 1,
            'invalid_service_manifest')
    require(manifest.get('phase') == 'installed' and manifest.get('stop_requested', False) is False and
            manifest.get('stop_pids', []) == [], 'current_installation_required')
    require(type(manifest.get('control_version')) is int and manifest['control_version'] == 1,
            'control_upgrade_required')
    files = manifest.get('files')
    require(isinstance(files, dict) and set(files) == set(FILES) and
            all(hex_value(value, 64) for value in files.values()), 'control_upgrade_required')
    require(manifest.get('control_sha256') == files['pf_control.py'], 'invalid_control_manifest')
    require(hex_value(manifest.get('plan_id'), 32) and hex_value(manifest.get('plan_sha256'), 64) and
            hex_value(manifest.get('plist_sha256'), 64), 'invalid_service_manifest')
    require(Path(__file__).absolute() == ROOT / 'pf_control.py', 'fixed_control_entry_required')
    # This proves the installed on-disk entry, not the bytes Python loaded before
    # acquiring the lock. Dispatch supports only this explicit control protocol.
    require(sha(safe_read(ROOT / 'pf_control.py')) == manifest['control_sha256'], 'modified_control_preserved')
    runtime = ROOT / ('runtime-' + fingerprint(files))
    require(manifest.get('runtime') == str(runtime), 'invalid_service_runtime')
    trusted_directory(runtime)
    require({item.name for item in runtime.iterdir()} == set(FILES), 'runtime_files_incomplete')
    sources = {}
    for name in FILES:
        raw = safe_read(runtime / name)
        require(sha(raw) == files[name], 'runtime_digest_mismatch')
        if name != 'pf_control.py':
            sources[name[:-3]] = raw
    return runtime, sources


@contextmanager
def verified_modules(manifest):
    runtime, sources = verified_sources(manifest)
    require(not any(name in sys.modules for name in sources), 'runtime_module_already_loaded')
    loader = VerifiedModules(runtime, sources)
    sys.meta_path.insert(0, loader)
    try:
        import pf_runtime_identity as identity
        identity.verify_complete(manifest)
        import pf_service as service
        yield service
    finally:
        sys.meta_path.remove(loader)
        for name in sources:
            sys.modules.pop(name, None)


def execute(args):
    require(os.geteuid() == 0, 'administrator_required_no_changes')
    require(hex_value(args.id, 32) and hex_value(args.request_id, 32) and
            hex_value(args.plan_sha256, 64) and hex_value(args.runtime_sha256, 64) and
            hex_value(args.service_instance, 32) and type(args.expected_revision) is int and
            0 <= args.expected_revision <= 2**53 - 1, 'invalid_control_request')
    expected = dict(plan_id=args.id, plan_sha256=args.plan_sha256,
                    runtime_sha256=args.runtime_sha256, service_instance=args.service_instance)
    with installation_lock():
        manifest = json.loads(safe_read(ROOT / 'installation.json', 65536))
        with verified_modules(manifest) as service:
            try:
                # The enclosing dispatcher already owns the installation lock.
                return service.submit_recheck_locked(args.id, args.request_id, args.expected_revision, expected)
            except Exception as error:
                return service.recheck_failure(error)


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ControlError('invalid_control_arguments')


def main(argv=None):
    args = None
    try:
        parser = Parser(description=__doc__)
        parser.add_argument('mode', choices=('recheck',))
        for flag in ('id', 'request-id', 'plan-sha256', 'runtime-sha256', 'service-instance'):
            parser.add_argument('--' + flag, required=True)
        parser.add_argument('--expected-revision', type=int, required=True)
        args = parser.parse_args(argv)
        require(sys.flags.isolated and sys.flags.no_site and sys.flags.dont_write_bytecode,
                'isolated_control_interpreter_required')
        result = execute(args)
    except Exception as error:
        result = {'reason': str(error) if isinstance(error, ControlError) else 'control_outcome_unknown',
                  'protection_verified': False, 'launch_authorized': False}
        if (args is not None and hex_value(args.request_id, 32) and type(args.expected_revision) is int and
                0 <= args.expected_revision <= 2**53 - 1):
            result.update(request_id=args.request_id, expected_revision=args.expected_revision)
    print(json.dumps(result, allow_nan=False))
    return 0 if result.get('reason') in ('recheck_requested', 'recheck_existing_result') else 78


if __name__ == '__main__':
    raise SystemExit(main())
