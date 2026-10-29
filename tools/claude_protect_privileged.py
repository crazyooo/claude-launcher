#!/usr/bin/env python3
"""Fixed privileged boundary. Only status is eligible for NOPASSWD.

Mutations require OS administrator authorization, not an App-local LAContext.
Installed code and imports are a root-owned snapshot, never repository paths.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ROOT = Path('/Library/PrivilegedHelperTools/local.crazyooo.claude-protect')
ENTRY = ROOT / 'claude-protect'
FILES = ('claude_protect_privileged.py', 'claude_protect_pf.py',
         'claude_protect_root_hook.py', 'router_pf_root_hook.py')
WINDOW = 'claude-protect-pf-user-confirm-v1'


def trusted_path(path: Path) -> None:
    """Reject symlinks, writable ancestors, non-root ownership, and ACLs."""
    if not path.is_absolute():
        raise ValueError('path_not_absolute')
    for item in list(reversed(path.parents)) + [path]:
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError('untrusted_path_permissions')
        if item != path and not stat.S_ISDIR(info.st_mode):
            raise ValueError('ancestor_not_directory')
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError('unsupported_file_type')
        acl = subprocess.run(['/bin/ls', '-lde', str(item)], capture_output=True,
                             text=True, timeout=5, check=True)
        if re.search(r'^\s*\d+:', acl.stdout, re.M):
            raise ValueError('acl_not_supported')


def verify_installation() -> Path:
    trusted_path(ENTRY)
    trusted_path(ROOT / 'current-release')
    name = (ROOT / 'current-release').read_text()
    if not re.fullmatch(r'release-[0-9a-f]{32}', name):
        raise ValueError('invalid_release_path')
    release = ROOT / name
    trusted_path(ROOT / 'entry-sha256')
    if hashlib.sha256(ENTRY.read_bytes()).hexdigest() != (ROOT / 'entry-sha256').read_text():
        raise ValueError('entry_changed')
    trusted_path(release / 'manifest.json')
    manifest = json.loads((release / 'manifest.json').read_text())
    if set(manifest) != set(FILES):
        raise ValueError('manifest_files_invalid')
    for name in FILES:
        file = release / name
        trusted_path(file)
        if hashlib.sha256(file.read_bytes()).hexdigest() != manifest[name]:
            raise ValueError('installed_digest_mismatch')
    return release


def allowed_arguments(args: list[str]) -> bool:
    if args in (['status'], ['hook-status'], ['unload', '--i-confirm-unload']):
        return True
    return (len(args) == 9 and args[0:2] == ['enable', '--conf']
            and args[2].startswith('/') and len(args[2]) <= 4096 and '\x00' not in args[2]
            and args[3] == '--conf-sha256' and re.fullmatch('[0-9a-f]{64}', args[4]) is not None
            and args[5:] == ['--i-confirm-apply', '--i-confirm-window', WINDOW,
                            '--i-acknowledge-network-mutation'])


def reply(status: str, reason: str = '') -> int:
    print(json.dumps(dict(product='claude_protect_privileged', security_version=2,
                          status=status, reason=reason, accepted=False,
                          protection_verified=False, routing_verified=False)))
    return 0 if status == 'verified' else 78


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ['verify-installation'] and not allowed_arguments(args):
        return reply('blocked', 'operation_not_allowed')
    if args != ['verify-installation'] and os.geteuid() != 0:
        return reply('blocked', 'system_admin_authorization_required')
    try:
        release = verify_installation()
        if args == ['verify-installation']:
            return reply('verified')
        # Do not run a different release's dependencies during an upgrade.
        if Path(__file__).parent != release:
            return reply('blocked', 'release_changed_retry')
        os.environ.clear()
        os.environ.update(PATH='/usr/bin:/bin:/usr/sbin:/sbin', LC_ALL='C', HOME='/var/root')
        sys.path.insert(0, str(release))
        import claude_protect_pf as pf
        if args == ['hook-status']:
            return pf.protect_hook_module().main(['status'])
        return pf.main(args)
    except (OSError, ValueError, subprocess.SubprocessError):
        return reply('blocked', 'secure_installation_unavailable')


if __name__ == '__main__':
    sys.exit(main())
