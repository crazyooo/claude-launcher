#!/usr/bin/env python3
"""Pinned upstream engine acquisition. Never executes A, B or Chromium."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import stat
import signal
import subprocess
import time
import uuid

VERSION = '0.2.48'
ENGINE = '148.0.7778.215'
BUNDLE = 'ai.local.requirement-french.browser'
ASSET = 'CCBaga-0.2.48-macos-arm64.dmg'
URL = 'https://github.com/liseami/CCBaga/releases/download/v0.2.48/' + ASSET
SIZE = 333276239
SHA = 'e4ce1e86514fec0641ec573c1d6c7f231ef7e233d2081d54d58adb322664c395'
ROOT = Path.home() / 'Library/Application Support/ClaudeLauncher/browser'
RUNTIME = ROOT / ('runtime-' + VERSION + '-' + SHA[:16])

class Failure(Exception): pass

def command(arguments, timeout=120):
    result = subprocess.run(arguments, stdin=subprocess.DEVNULL, capture_output=True, timeout=timeout)
    if result.returncode: raise Failure('verification_failed_' + Path(arguments[0]).name)
    if len(result.stdout) > 1024 * 1024: raise Failure('verification_output_exceeded')
    return result.stdout

def directory(path, create=False):
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor = cursor / part
        if create and not cursor.exists(): cursor.mkdir(mode=0o700)
        info = cursor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o022: raise Failure('unsafe_parent')
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077: raise Failure('private_directory_required')

def regular(path):
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1: raise Failure('unsafe_file')
    return value

def checksum(path):
    regular(path); value = hashlib.sha256()
    with path.open('rb') as stream:
        for data in iter(lambda: stream.read(1024 * 1024), b''): value.update(data)
    return value.hexdigest()

def quarantine(path):
    command(['/usr/bin/xattr', '-w', 'com.apple.quarantine', '0081;%x;Claude Launcher;' % int(time.time()), str(path)])

def download(path):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
    # curl enforces an overall deadline even when a peer trickles bytes.
    command(['/usr/bin/curl', '-q', '--location', '--proto', '=https', '--proto-redir', '=https',
             '--connect-timeout', '20', '--max-time', '900', '--max-filesize', str(SIZE),
             '--fail', '--silent', '--show-error', '--output', str(path), URL], timeout=905)
    if regular(path).st_size != SIZE or checksum(path) != SHA: raise Failure('download_digest_mismatch')
    quarantine(path)

def verify(app):
    if not stat.S_ISDIR(app.lstat().st_mode): raise Failure('invalid_bundle')
    info_path = app / 'Contents/Info.plist'; executable = app / 'Contents/MacOS/Chromium'
    regular(info_path); regular(executable)
    metadata = plistlib.loads(info_path.read_bytes())
    if metadata.get('CFBundleIdentifier') != BUNDLE or metadata.get('CFBundleShortVersionString') != ENGINE:
        raise Failure('unexpected_bundle')
    command(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(app)])
    command(['/usr/sbin/spctl', '--assess', '--type', 'execute', str(app)])
    return dict(release=VERSION, engineVersion=ENGINE, assetSHA256=SHA, bundleIdentifier=BUNDLE,
                executableSHA256=checksum(executable))

def inspect():
    if not ROOT.exists(): return {'reason': 'browser_not_installed'}
    directory(ROOT)
    if not RUNTIME.exists(): return {'reason': 'browser_not_installed'}
    directory(RUNTIME); receipt_path = RUNTIME / 'receipt.json'
    if regular(receipt_path).st_size > 16384: raise Failure('invalid_receipt')
    receipt = json.loads(receipt_path.read_bytes()); actual = verify(RUNTIME / 'CCBaga-B.app')
    if any(receipt.get(key) != value for key, value in actual.items()): raise Failure('receipt_mismatch')
    return {'reason': 'browser_verified_not_started', **actual}

def install():
    if platform.system() != 'Darwin' or platform.machine() != 'arm64': raise Failure('macos_arm64_required')
    directory(ROOT, create=True)
    lock = os.open(ROOT / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    mounted = []; published = False
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise Failure('unsafe_lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if RUNTIME.exists() or RUNTIME.is_symlink(): return inspect()
        operation = ROOT / ('install-' + uuid.uuid4().hex); operation.mkdir(mode=0o700)
        image = operation / ASSET
        candidates = list(ROOT.glob('install-*/' + ASSET))
        reused = False
        for candidate in candidates:
            directory(candidate.parent)
            if regular(candidate).st_size == SIZE and checksum(candidate) == SHA:
                image = candidate; quarantine(image); reused = True; break
        if not reused: download(image)
        mount = plistlib.loads(command(['/usr/bin/hdiutil', 'attach', '-readonly', '-nobrowse', '-noautoopen', '-plist', str(image)]))
        mounted = [Path(item['mount-point']) for item in mount.get('system-entities', []) if 'mount-point' in item]
        if len(mounted) != 1: raise Failure('disk_layout_unsupported')
        source = mounted[0] / 'CCBaga-B.app'; verify(source)
        staged = operation / 'runtime'; staged.mkdir(mode=0o700)
        destination = staged / 'CCBaga-B.app'
        command(['/usr/bin/ditto', '--rsrc', '--extattr', str(source), str(destination)])
        quarantine(destination); receipt = verify(destination); receipt['installedAt'] = time.time()
        descriptor = os.open(staged / 'receipt.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump(receipt, stream, sort_keys=True); stream.flush(); os.fsync(stream.fileno())
        if RUNTIME.exists() or RUNTIME.is_symlink(): raise Failure('destination_changed')
        os.rename(staged, RUNTIME); published = True
        descriptor = os.open(ROOT, os.O_RDONLY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
        return {'reason': 'browser_installed_not_started', 'runtime': str(RUNTIME)}
    finally:
        detach_failed = False
        for volume in mounted:
            try: command(['/usr/bin/hdiutil', 'detach', str(volume)], timeout=30)
            except (Failure, subprocess.SubprocessError): detach_failed = True
        os.close(lock)
        if detach_failed: raise Failure('browser_installed_detach_pending' if published else 'browser_install_failed_detach_pending')

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('action', choices=('install', 'inspect')); args = parser.parse_args()
    def interrupted(*_):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        raise Failure('browser_operation_interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        result = install() if args.action == 'install' else inspect()
        print(json.dumps({**result, 'browser_started': False})); return 0
    except Failure as error:
        print(json.dumps({'reason': str(error), 'browser_started': False})); return 78
    except Exception:
        print(json.dumps({'reason': 'browser_operation_failed_files_preserved', 'browser_started': False})); return 78

if __name__ == '__main__': raise SystemExit(main())
