#!/usr/bin/env python3
"""Build a recovery executable for the interrupted 2026-10-19 install. Never install or run it."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shlex
import subprocess
import package_router_system as packaging

PACKAGE_ID = "270826d7-a1fe-49b3-9c62-c7fc3f65a403"
TRANSACTION = "22601bea-5da1-4895-a692-27876226ef68"
HELPER = "bc37a9f6efd3f4084610fe36b46d0ae278ea0af9289fc19afe3aeb716cfe9363"
PINS = {
    "payload/router-system-helper": HELPER,
    "payload/mihomo": "94a386ec0149080deadd86b1f667363bde3c70f7489dba3258e52c56fc9a6d66",
    "router-system-installer": "c34e890c8bce40f5f186e905a08680a0985cd62ac61ff824f4ee300357efba12",
}
FIELDS = ["--action", "install", "--uid", "501", "--id", TRANSACTION]
SWIFT_PACKAGE = '''// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "RouterRecovery", platforms: [.macOS(.v13)], products: [
    .executable(name: "router-system-resume", targets: ["RecoveryEntry"])
], targets: [.target(name: "RoutingCore"), .executableTarget(name: "RecoveryEntry", dependencies: ["RoutingCore"])])
'''


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate_key")
            result[key] = value
        return result
    def invalid(_):
        raise ValueError("nonfinite_json")
    value = json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)
    if not isinstance(value, dict):
        raise ValueError("object_required")
    return value


def original_package(path):
    path = packaging.physical(path)
    records = {name: packaging.read_file(path / name, 256 * 1024)
               for name in ["PACKAGE-SHA256.json", "INSTALLATION-PREVIEW.json"]}
    inventory, preview = (strict_json(records[name]) for name in records)
    if (inventory.get("version") != 1 or inventory.get("package_id") != PACKAGE_ID
            or inventory.get("files") != PINS or inventory.get("core_version") != "1.19.32"
            or preview.get("preview_arguments") != ["preview"] + FIELDS
            or preview.get("status") != "offline_package_only"):
        raise ValueError("original_package_mismatch")
    for record in [inventory, preview]:
        if record.get("installed") is not False or record.get("network_modified") is not False:
            raise ValueError("not_original_offline_inventory")
    for name, digest in PINS.items():
        records[name] = packaging.read_file(path / name)
        if packaging.sha(records[name]) != digest:
            raise ValueError("original_binary_changed")
    return records


def entry_source():
    # Only fixed UUID/hex literals are interpolated. No input path becomes executable Swift.
    return ('''import Foundation
import Darwin
import RoutingCore
do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let verb = args.first, ["resume-preview", "resume-apply", "apply"].contains(verb),
          args.count == (verb == "resume-preview" ? 7 : 9),
          Array(args[1..<7]) == ["--action", "install", "--uid", "501", "--id", "%s"],
          verb == "resume-preview" || args[7] == "--confirm" else { throw RouterSystemError.invalidRequest }
    try RouterSystemInstaller.run(arguments: args, packageID: UUID(uuidString: "%s")!,
        helperSHA256: "%s", requireExisting: true)
} catch {
    let result: [String: Any] = ["version": 1, "status": "blocked",
        "reason": (error as? RouterSystemError)?.rawValue ?? "operationUnsettled",
        "routing_verified": false, "protection_verified": false, "launch_authorized": false]
    if let bytes = try? JSONSerialization.data(withJSONObject: result, options: [.sortedKeys]) {
        FileHandle.standardOutput.write(bytes); FileHandle.standardOutput.write(Data([10]))
    }
    Darwin._exit(78)
}
''' % (TRANSACTION, PACKAGE_ID, HELPER)).encode()


def routing_sources(repo):
    return {name: data for name, data in packaging.source_snapshot(repo).items()
            if name.startswith("Sources/RoutingCore/")}


def build(repo, old_package, output, developer_dir):
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("nonroot_packaging_required")
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise ValueError("macos_arm64_required")
    repo, old_package = packaging.physical(repo), packaging.physical(old_package)
    original = original_package(old_package)
    sources = routing_sources(repo)
    release = sources["Sources/RoutingCore/RouterCoreRelease.swift"].decode()
    if (re.findall(r'public static let version = "([^"]+)"', release) != ["1.19.32"]
            or re.findall(r'public static let executableSHA256 = "([^"]+)"', release) != [PINS["payload/mihomo"]]):
        raise ValueError("source_core_pin_changed")
    out = Path(os.path.abspath(output))
    if old_package == out or old_package in out.parents or repo / "Sources" in out.parents:
        raise ValueError("output_overlaps_input")
    out = packaging.prepare_output(out)
    build_dir = out / "build-source"
    build_dir.mkdir(mode=0o700)
    snapshot = dict(sources, **{"Package.swift": SWIFT_PACKAGE.encode(), "Sources/RecoveryEntry/main.swift": entry_source()})
    for name, data in snapshot.items():
        file = build_dir / name
        file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        packaging.write_new(file, data)
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C", "HOME": os.path.expanduser("~")}
    environment["DEVELOPER_DIR"] = str(packaging.physical(developer_dir))
    counter = 0
    def run(args, capture=False):
        nonlocal counter
        counter += 1
        with (out / ("command-%02d.log" % counter)).open("xb") as log:
            completed = subprocess.run(args, cwd=build_dir, env=environment, timeout=600,
                stdout=subprocess.PIPE if capture else log, stderr=log if capture else subprocess.STDOUT)
            if capture:
                log.write(completed.stdout)
            log.flush(); os.fsync(log.fileno())
            completed.check_returncode()
        return completed.stdout.decode().strip() if capture else None
    run(["/usr/bin/swift", "build", "-c", "release", "--product", "router-system-resume"])
    binaries = packaging.physical(run(["/usr/bin/swift", "build", "-c", "release", "--show-bin-path"], True))
    if build_dir not in binaries.parents:
        raise ValueError("unexpected_build_output")
    bundle = out / "ClaudeRouterRecovery"
    bundle.mkdir(mode=0o755)
    executable = bundle / "router-system-resume"
    packaging.write_new(executable, packaging.read_file(binaries / executable.name), mode=0o755)
    run(["/usr/bin/codesign", "--force", "--sign", "-", str(executable)])
    run(["/usr/bin/codesign", "--verify", "--strict", str(executable)])
    if original_package(old_package) != original or routing_sources(repo) != sources:
        raise ValueError("source_changed")
    if any(packaging.read_file(build_dir / name, 2 * 1024 * 1024) != data for name, data in snapshot.items()):
        raise ValueError("build_snapshot_changed")
    record = {"version": 1, "package_id": PACKAGE_ID, "transaction": TRANSACTION, "helper_sha256": HELPER,
        "files": {executable.name: packaging.sha(packaging.read_file(executable))},
        "sources": {name: packaging.sha(data) for name, data in snapshot.items()},
        "original_artifacts": {name: packaging.sha(data) for name, data in original.items()},
        "artifact_executed": False, "installed": False, "network_modified": False}
    preview = {"version": 1, "status": "offline_recovery_package_only",
        "read_only_preview_command": shlex.join(["sudo", str(executable), "resume-preview"] + FIELDS)}
    for name, data in [("RECOVERY-SHA256.json", record), ("RECOVERY-PREVIEW.json", preview)]:
        packaging.write_new(bundle / name, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(), mode=0o644)
    return {"package": str(bundle), "installed": False, "network_modified": False}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["repo", "old-package", "output", "developer-dir"]:
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.repo, args.old_package, args.output, args.developer_dir)))
