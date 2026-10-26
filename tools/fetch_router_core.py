#!/usr/bin/env python3
"""Fetch the reviewed release without executing it or changing network settings."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import urllib.request

VERSION = "1.19.32"
ARCHIVE_HASH = "3312a6780652c622890fd4357c6a853bbf865464fd047ac7b7f52dab8de18652"
BINARY_HASH = "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66"
URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.32/mihomo-darwin-arm64-v1.19.32.gz"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_BINARY = 128 * 1024 * 1024


def verified_archive(data):
    if len(data) > MAX_ARCHIVE or hashlib.sha256(data).hexdigest() != ARCHIVE_HASH:
        raise ValueError("archive_digest_mismatch")
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
        binary = stream.read(MAX_BINARY + 1)
    if len(binary) > MAX_BINARY or hashlib.sha256(binary).hexdigest() != BINARY_HASH:
        raise ValueError("binary_digest_mismatch")
    return binary


def verify_core(path):
    path = path.absolute()
    if path != path.resolve():
        raise ValueError("symlink_core")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or before.st_nlink != 1 or before.st_mode & 0o022
                or not before.st_mode & 0o100 or not 0 < before.st_size <= MAX_BINARY):
            raise ValueError("unsafe_cached_core")
        data = stream.read(MAX_BINARY + 1)
        after = os.fstat(stream.fileno())
    linked = path.lstat()
    if ((before.st_dev, before.st_ino) != (linked.st_dev, linked.st_ino)
            or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
               (after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or len(data) != before.st_size or hashlib.sha256(data).hexdigest() != BINARY_HASH):
        raise ValueError("cached_core_changed_preserved")


def download_worker():
    try:
        request = urllib.request.Request(URL, headers={"User-Agent": "Claude-Router-Core-Fetch/1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = response.read(MAX_ARCHIVE + 1)
        if len(data) > MAX_ARCHIVE:
            return 1
        sys.stdout.buffer.write(data)
        return 0
    except Exception:
        return 1


def download_archive(timeout=90, popen=subprocess.Popen):
    # The worker owns DNS/TLS/body reads; the parent bounds total elapsed network work.
    child = popen([sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--download-worker"],
                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
    try:
        data, _ = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        child.kill()
        try:
            child.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            raise ValueError("download_timeout_cleanup_unconfirmed")
        raise ValueError("download_total_timeout")
    if child.returncode != 0 or len(data) > MAX_ARCHIVE:
        raise ValueError("download_failed")
    return data


def fetch(destination):
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("unsupported_architecture")
    destination = destination.absolute()
    if destination != destination.resolve():
        raise ValueError("symlink_destination")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = destination.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("unsafe_destination")
    executable = destination / "mihomo"
    if executable.exists() or executable.is_symlink():
        verify_core(executable)
        return "verified_cached_core"
    archive = download_archive()
    binary = verified_archive(archive)
    # No overwrite: an interrupted or externally changed file is preserved and reported.
    fd = os.open(executable, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700)
    with os.fdopen(fd, "wb") as stream:
        stream.write(binary); stream.flush(); os.fsync(stream.fileno())
    return "pinned_core_downloaded"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=Path(__file__).resolve().parents[1] / ".build/router-core")
    parser.add_argument("--verify-file", type=Path)
    args = parser.parse_args()
    try:
        if args.verify_file is not None:
            verify_core(args.verify_file)
            reason = "verified_pinned_core_file"
        else:
            reason = fetch(args.destination)
        print(json.dumps({"reason": reason, "version": VERSION, "sha256": BINARY_HASH, "executed": False}))
    except Exception as error:
        reason = str(error) if isinstance(error, ValueError) else "download_or_filesystem_failed"
        print(json.dumps({"reason": reason, "executed": False})); return 1
    return 0


if __name__ == "__main__":
    if sys.argv[1:] == ["--download-worker"]:
        raise SystemExit(download_worker())
    raise SystemExit(main())
