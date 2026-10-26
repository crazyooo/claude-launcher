#!/usr/bin/env python3
"""Build an offline native system installer. Never installs or starts a service."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import subprocess
import uuid

CORE_VERSION = "1.19.32"
CORE_SHA256 = "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66"
MAX_BINARY = 128 * 1024 * 1024
PACKAGE = '''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "ClaudeRouterSystemPackage", platforms: [.macOS(.v13)], products: [
    .executable(name: "router-system-helper", targets: ["RouterSystemHelper"]),
    .executable(name: "router-system-installer", targets: ["RouterSystemInstaller"])
], targets: [
    .target(name: "RoutingCore"),
    .executableTarget(name: "RouterSystemHelper", dependencies: ["RoutingCore"]),
    .executableTarget(name: "RouterSystemInstaller", dependencies: ["RoutingCore"])
])
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def physical(path):
    path = Path(os.path.abspath(path))
    if path != path.resolve(strict=True):
        raise ValueError("symlink_path_rejected")
    return path


def read_file(path, maximum=MAX_BINARY):
    path = physical(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in (0, os.getuid()) or before.st_mode & 0o022
                or not 0 <= before.st_size <= maximum):
            raise ValueError("unsafe_source_file")
        chunks, size = [], 0
        while size <= maximum:
            chunk = os.read(fd, min(65536, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        def identity(value):
            return (value.st_dev, value.st_ino, value.st_size, value.st_mode,
                    value.st_uid, value.st_gid, value.st_nlink, value.st_mtime_ns, value.st_ctime_ns)
        if identity(before) != identity(os.fstat(fd)) or identity(before) != identity(path.lstat()) or size != before.st_size:
            raise ValueError("source_changed_during_read")
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_new(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    try:
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            size = os.write(fd, view)
            if size <= 0:
                raise OSError("short_write")
            view = view[size:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if read_file(path, max(len(data), 1)) != data:
        raise ValueError("artifact_readback_failed")


def replace_generated(path, expected, data):
    if read_file(path, 65536) != expected:
        raise ValueError("generated_source_changed")
    before = path.lstat()
    fd = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        current = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (current.st_dev, current.st_ino, current.st_mtime_ns, current.st_ctime_ns):
            raise ValueError("generated_source_replaced")
        os.ftruncate(fd, 0)
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short_write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    if read_file(path, 65536) != data:
        raise ValueError("generated_source_readback_failed")


def source_snapshot(repo):
    result = {}
    for target in ("RoutingCore", "RouterSystemHelper"):
        root = physical(repo / "Sources" / target)
        count = 0
        for parent, directories, files in os.walk(root, followlinks=False):
            for name in directories:
                physical(Path(parent) / name)
            for name in sorted(files):
                if not name.endswith(".swift"):
                    continue
                path = Path(parent) / name
                result[str(path.relative_to(repo))] = read_file(path, 2 * 1024 * 1024)
                count += 1
                if len(result) > 2048 or sum(map(len, result.values())) > 32 * 1024 * 1024:
                    raise ValueError("source_budget_exceeded")
        if count == 0:
            raise ValueError("missing_source_target")
    return result


def entry(package_id, helper_pin):
    # Only generated UUID/hex values enter Swift source, never a path or arbitrary user text.
    package_id = str(uuid.UUID(str(package_id)))
    if not re.fullmatch(r"[a-f0-9]{64}", helper_pin):
        raise ValueError("invalid_helper_pin")
    return ('''import Foundation
import Darwin
import RoutingCore
do {
    let packageID = UUID(uuidString: "%s")!
    try RouterSystemInstaller.run(arguments: Array(CommandLine.arguments.dropFirst()),
        packageID: packageID, helperSHA256: "%s")
} catch {
    let response: [String: Any] = ["version": 1, "status": "blocked",
        "reason": (error as? RouterSystemError)?.rawValue ?? "operationUnsettled",
        "routing_verified": false, "protection_verified": false, "launch_authorized": false]
    if let bytes = try? JSONSerialization.data(withJSONObject: response, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(bytes)
        FileHandle.standardOutput.write(Data([10]))
    }
    Darwin._exit(78)
}
''' % (package_id, helper_pin)).encode()


def prepare_output(path):
    path = Path(os.path.abspath(path))
    physical(path.parent)
    if path.exists() or path.is_symlink():
        raise ValueError("output_must_be_new")
    for parent in (path.parent, *path.parent.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
            raise ValueError("unsafe_output_ancestor")
    path.mkdir(mode=0o700)
    return path


def build_package(repo, core, output, developer_dir):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("packager_requires_nonroot")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("macos_arm64_required")
    repo = physical(repo)
    sources = source_snapshot(repo)
    release = sources["Sources/RoutingCore/RouterCoreRelease.swift"].decode()
    if (re.findall(r'public static let version = "([^"]+)"', release) != [CORE_VERSION]
            or re.findall(r'public static let executableSHA256 = "([^"]+)"', release) != [CORE_SHA256]):
        raise ValueError("source_core_pin_mismatch")
    core_bytes = read_file(core)
    if sha(core_bytes) != CORE_SHA256:
        raise ValueError("core_pin_mismatch")
    out_path = Path(os.path.abspath(output))
    if repo / "Sources" in out_path.parents:
        raise ValueError("output_inside_sources")
    output = prepare_output(out_path)
    build = output / "build-source"
    build.mkdir(mode=0o700)
    for relative, data in sources.items():
        path = build / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(path, data)
    write_new(build / "Package.swift", PACKAGE.encode())
    main = build / "Sources/RouterSystemInstaller/main.swift"
    main.parent.mkdir(mode=0o700)
    placeholder = b"import Foundation\n"
    write_new(main, placeholder)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "HOME": os.path.expanduser("~")}
    if developer_dir:
        environment["DEVELOPER_DIR"] = str(physical(developer_dir))
    number = 0
    def run(command, capture=False, timeout=600):
        nonlocal number
        number += 1
        log_path = output / ("command-%02d.log" % number)
        # A log is created first so failures and timeouts leave a usable diagnostic record.
        with log_path.open("xb") as log:
            if capture:
                result = subprocess.run(command, cwd=build, env=environment, timeout=timeout,
                    stdout=subprocess.PIPE, stderr=log, check=False)
                log.write(result.stdout)
                result.check_returncode()
            else:
                result = subprocess.run(command, cwd=build, env=environment, timeout=timeout,
                    stdout=log, stderr=subprocess.STDOUT, check=True)
            log.flush(); os.fsync(log.fileno())
        return result.stdout.decode().strip() if capture else None
    # The packaging host environment rejects SwiftPM's nested sandbox-exec, so every
    # build invocation must run with the SwiftPM sandbox disabled.
    run(["/usr/bin/swift", "build", "-c", "release", "--disable-sandbox", "--product", "router-system-helper"])
    bin_path = physical(run(["/usr/bin/swift", "build", "-c", "release", "--disable-sandbox", "--show-bin-path"], capture=True))
    if build not in bin_path.parents:
        raise ValueError("compiler_output_outside_build")
    bundle = output / "ClaudeRouterSystem"
    bundle.mkdir(mode=0o755)
    payload = bundle / "payload"
    payload.mkdir(mode=0o755)
    helper = payload / "router-system-helper"
    write_new(helper, read_file(bin_path / helper.name), mode=0o755)
    run(["/usr/bin/codesign", "--force", "--sign", "-", str(helper)], timeout=30)
    run(["/usr/bin/codesign", "--verify", "--strict", str(helper)], timeout=30)
    helper_pin = sha(read_file(helper))
    write_new(payload / "mihomo", core_bytes, mode=0o755)
    package_id, transaction_id = uuid.uuid4(), uuid.uuid4()
    replace_generated(main, placeholder, entry(package_id, helper_pin))
    run(["/usr/bin/swift", "build", "-c", "release", "--disable-sandbox", "--product", "router-system-installer"])
    installer = bundle / "router-system-installer"
    write_new(installer, read_file(bin_path / installer.name), mode=0o755)
    run(["/usr/bin/codesign", "--force", "--sign", "-", str(installer)], timeout=30)
    run(["/usr/bin/codesign", "--verify", "--strict", str(installer)], timeout=30)
    if sha(read_file(helper)) != helper_pin or sha(read_file(payload / "mihomo")) != CORE_SHA256:
        raise ValueError("payload_changed_after_pinning")
    if source_snapshot(repo) != sources:
        raise ValueError("reviewed_sources_changed_during_build")
    write_new(bundle / "mihomo-GPL-3.0.txt", read_file(repo / "docs/licenses/mihomo-GPL-3.0.txt", 128 * 1024), mode=0o644)
    inventory = {"version": 1, "package_id": str(package_id), "core_version": CORE_VERSION,
        "core_source": "https://github.com/MetaCubeX/mihomo/tree/v" + CORE_VERSION,
        "files": {str(path.relative_to(bundle)): sha(read_file(path)) for path in (installer, helper, payload / "mihomo")},
        "sources": {name: sha(data) for name, data in sorted(sources.items())}, "installed": False, "network_modified": False}
    write_new(bundle / "PACKAGE-SHA256.json", (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode(), mode=0o644)
    arguments = ["preview", "--action", "install", "--uid", str(os.getuid()), "--id", str(transaction_id)]
    preview = {"version": 1, "status": "offline_package_only", "preview_arguments": arguments,
        "read_only_preview_command": shlex.join(["sudo", str(installer)] + arguments),
        "installed": False, "network_modified": False, "routing_verified": False}
    write_new(bundle / "INSTALLATION-PREVIEW.json", (json.dumps(preview, indent=2, sort_keys=True) + "\n").encode(), mode=0o644)
    return {"package": str(bundle), "status": "offline_package_only", "installed": False, "network_modified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--core", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--developer-dir", default=os.environ.get("DEVELOPER_DIR"))
    args = parser.parse_args()
    print(json.dumps(build_package(args.repo, args.core, args.output, args.developer_dir)))


if __name__ == "__main__":
    main()
