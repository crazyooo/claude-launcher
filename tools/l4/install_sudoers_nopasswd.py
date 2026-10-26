#!/usr/bin/env python3
"""Migrate legacy grants to a root-owned snapshot with read-only NOPASSWD.

Administrator authorization is required for installation and all PF mutations.
No PF, launchd, proxy or Claude process changes are performed here.
"""
from __future__ import annotations
import argparse
import fcntl
import getpass
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import subprocess
import sys
import tempfile
import uuid

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
import claude_protect_privileged as secure

SUDOERS = Path('/private/etc/sudoers.d/claude-protect')
LEGACY = tuple(Path('/usr/local/sbin') / name for name in
               ('claude-protect-pf', 'claude-protect-hook', 'claude-protect-guard-daemon'))
HEADER = '# Claude protect secure status-only v2\n'
DISABLED = '# Claude protect disabled: administrator migration incomplete; no grants.\n'
RETIRED = '#!/bin/sh\n# Claude protect legacy entry retired v2\necho "Legacy entry retired; use the updated App." >&2\nexit 78\n'


def output(status, **extra):
    print(json.dumps(dict(product='claude_protect_sudoers', version=2, status=status,
                         accepted=False, protection_verified=False, routing_verified=False, **extra)))
    return 78 if status == 'blocked' else 0


def validate_user(user):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,63}', user):
        raise ValueError('invalid_user')
    record = pwd.getpwnam(user)
    if record.pw_uid == 0:
        raise ValueError('non_root_user_required')
    return user


def sudoers_body(user):
    validate_user(user)
    # Exact argument strings; no wildcards, no shell or interpreter grants.
    return HEADER + f'{user} ALL=(root) NOPASSWD: {secure.ENTRY} status\n'


def atomic(path, data, mode=0o644):
    secure.trusted_path(path.parent)
    if path.exists() or path.is_symlink():
        secure.trusted_path(path)
    fd, name = tempfile.mkstemp(prefix='.protect-', dir=path.parent)
    # Temporary files remain recoverable on errors; never follow a target symlink.
    with os.fdopen(fd, 'wb') as stream:
        os.fchmod(stream.fileno(), mode)
        os.fchown(stream.fileno(), 0, 0)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(name, path)


def check_sudoers(path):
    subprocess.run(['/usr/sbin/visudo', '-cf', str(path)], capture_output=True,
                   text=True, timeout=10, check=True)


def owned_sudoers():
    if not SUDOERS.exists() and not SUDOERS.is_symlink():
        return b''
    secure.trusted_path(SUDOERS)
    data = SUDOERS.read_bytes()
    if not data.startswith((b'# Claude protect ',)):
        raise ValueError('sudoers_not_owned')
    return data


def source_snapshot():
    snapshot = {}
    for name in (*secure.FILES, 'claude_protect_launcher.c', 'l4/install_sudoers_nopasswd.py'):
        path = TOOLS / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('invalid_source')
        snapshot[name] = path.read_bytes()
    return snapshot


def source_hashes(snapshot):
    return {name: hashlib.sha256(data).hexdigest() for name, data in snapshot.items()}


def source_manifest_hash(snapshot):
    return hashlib.sha256(json.dumps(source_hashes(snapshot), sort_keys=True).encode()).hexdigest()


def migrate(user, uninstall=False, expected_source_sha256=None):
    snapshot = {} if uninstall else source_snapshot()
    if not uninstall and source_manifest_hash(snapshot) != expected_source_sha256:
        raise ValueError('source_changed_since_review_or_digest_missing')
    secure.trusted_path(secure.ROOT.parent)
    secure.trusted_path(SUDOERS.parent)
    secure.ROOT.mkdir(mode=0o755, exist_ok=True)
    secure.trusted_path(secure.ROOT)
    lock_path = secure.ROOT / 'install.lock'
    if lock_path.exists() or lock_path.is_symlink():
        secure.trusted_path(lock_path)
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'r+') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        previous = owned_sudoers()
        archive = secure.ROOT / ('archive-' + uuid.uuid4().hex)
        archive.mkdir(mode=0o700)
        atomic(archive / 'previous-sudoers.txt', previous, 0o600)
        # Revoke FIRST. On any subsequent failure never restore the unsafe grant.
        disabled = archive / 'disabled-sudoers.txt'
        atomic(disabled, DISABLED.encode(), 0o440)
        check_sudoers(disabled)
        atomic(SUDOERS, disabled.read_bytes(), 0o440)
        retired = []
        warnings = []
        for path in LEGACY:
            if not path.exists() and not path.is_symlink():
                continue
            try:
                secure.trusted_path(path)
            except (OSError, ValueError):
                # The grant is already revoked. Never read/write an untrusted legacy path.
                warnings.append('legacy_wrapper_unretired_untrusted_ancestry:' + str(path))
                continue
            data = path.read_bytes()
            if b'# Managed by claude-protect sudoers installer.' not in data and data != RETIRED.encode():
                raise ValueError('legacy_wrapper_not_owned')
            atomic(archive / path.name, data, 0o600)
            atomic(path, RETIRED.encode(), 0o755)
            retired.append(str(path))
        if uninstall:
            return output('authorization_revoked', archive=str(archive), pf_modified=False)
        for name, data in snapshot.items():
            atomic(archive / Path(name).name, data, 0o600)
        atomic(archive / 'source-sha256.json', json.dumps(source_hashes(snapshot), sort_keys=True).encode(), 0o600)
        release = secure.ROOT / ('release-' + uuid.uuid4().hex)
        release.mkdir(mode=0o755)
        manifest = {}
        for name in secure.FILES:
            data = snapshot[name]
            atomic(release / name, data)
            manifest[name] = hashlib.sha256(data).hexdigest()
        atomic(release / 'manifest.json', json.dumps(manifest, sort_keys=True).encode())
        body = sudoers_body(user)
        candidate = archive / 'new-sudoers.txt'
        atomic(candidate, body.encode(), 0o440)
        check_sudoers(candidate)
        # Compile the small gate once, during explicit administrator installation.
        # The selected Xcode shim is never used by the passwordless entry.
        compiler = Path('/Library/Developer/CommandLineTools/usr/bin/clang').resolve()
        secure.trusted_path(compiler)
        sdk = Path('/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk').resolve()
        secure.trusted_path(sdk)
        native = archive / 'claude-protect-native'
        subprocess.run([str(compiler), '-isysroot', str(sdk), '-mmacosx-version-min=13.0',
                        '-O2', '-Wall', '-Wextra', '-Werror',
                        str(archive / 'claude_protect_launcher.c'), '-o', str(native)],
                       capture_output=True, text=True, timeout=60, check=True,
                       env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'LC_ALL': 'C'})
        secure.trusted_path(native)
        subprocess.run([str(native), '--check-runtime'], check=True, timeout=30,
                       capture_output=True, text=True)
        atomic(secure.ENTRY, native.read_bytes(), 0o755)
        atomic(secure.ROOT / 'entry-sha256', hashlib.sha256(native.read_bytes()).hexdigest().encode())
        atomic(secure.ROOT / 'current-release', release.name.encode())
        secure.verify_installation()
        atomic(SUDOERS, body.encode(), 0o440)
        check_sudoers(SUDOERS)
        return output('installed', security_version=2, archive=str(archive),
                      entry=str(secure.ENTRY), retired=retired, warnings=warnings, pf_modified=False,
                      source_manifest_sha256=source_manifest_hash(snapshot),
                      note='Only exact status commands are passwordless; mutations require system administrator authorization.')


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--user', default=None)
    sub = p.add_subparsers(dest='command', required=True)
    for name in ('plan', 'install', 'uninstall', 'verify'):
        sp = sub.add_parser(name)
        sp.add_argument('--user', default=argparse.SUPPRESS)
        if name in ('install', 'uninstall'):
            sp.add_argument('--i-confirm-' + name, action='store_true')
        if name == 'install':
            sp.add_argument('--expected-source-sha256', required=True)
    args = p.parse_args(argv)
    try:
        user = validate_user(args.user or os.environ.get('SUDO_USER') or getpass.getuser())
        if args.command == 'plan':
            snapshot = source_snapshot()
            return output('plan', entry=str(secure.ENTRY), sudoers_preview=sudoers_body(user),
                          source_sha256=source_hashes(snapshot),
                          source_manifest_sha256=source_manifest_hash(snapshot),
                          pf_modified=False, root_required=True)
        if args.command == 'verify':
            secure.verify_installation()
            # Reading sudoers needs root; verify cannot claim success without it.
            if owned_sudoers().decode() != sudoers_body(user):
                raise ValueError('sudoers_not_status_only')
            return output('verified', security_version=2, pf_modified=False)
        if not getattr(args, 'i_confirm_' + args.command):
            return output('blocked', reason='explicit_confirmation_required')
        if os.geteuid() != 0:
            return output('blocked', reason='system_admin_authorization_required')
        return migrate(user, uninstall=args.command == 'uninstall',
                       expected_source_sha256=getattr(args, 'expected_source_sha256', None))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        return output('blocked', reason=str(exc), pf_modified=False,
                      note='If migration started, legacy grants stay revoked. Inspect and rerun; do not restore unsafe sudoers.')


if __name__ == '__main__':
    sys.exit(main())
