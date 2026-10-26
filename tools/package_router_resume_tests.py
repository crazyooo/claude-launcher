import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import package_router_resume as target


class RecoveryPackageTests(unittest.TestCase):
    def fixture(self):
        root = Path(tempfile.mkdtemp(prefix="router-resume-package-")).resolve()
        records = {
            "PACKAGE-SHA256.json": json.dumps({"version": 1, "package_id": target.PACKAGE_ID,
                "core_version": "1.19.32", "files": target.PINS, "installed": False, "network_modified": False}).encode(),
            "INSTALLATION-PREVIEW.json": json.dumps({"preview_arguments": ["preview"] + target.FIELDS,
                "status": "offline_package_only", "installed": False, "network_modified": False}).encode(),
        }
        records.update({name: name.encode() for name in target.PINS})
        return root, records

    def check(self, root, records):
        def digest(data):
            return target.PINS.get(data.decode(), "unrecognized")
        with patch.object(target.packaging, "read_file", side_effect=lambda path, *args: records[path.relative_to(root).as_posix()]), \
                patch.object(target.packaging, "sha", side_effect=digest):
            return target.original_package(root)

    def test_original_artifacts_and_transaction_are_verified(self):
        root, records = self.fixture()
        self.assertEqual(self.check(root, records), records)
        for file in target.PINS:
            changed = dict(records, **{file: b"changed"})
            with self.assertRaisesRegex(ValueError, "original_binary_changed"):
                self.check(root, changed)
        for field, value in [("package_id", "foreign"), ("files", {}), ("installed", True)]:
            changed = dict(records)
            metadata = json.loads(changed["PACKAGE-SHA256.json"]); metadata[field] = value
            changed["PACKAGE-SHA256.json"] = json.dumps(metadata).encode()
            with self.assertRaises(ValueError):
                self.check(root, changed)
        changed = dict(records)
        metadata = json.loads(changed["INSTALLATION-PREVIEW.json"])
        metadata["preview_arguments"][-1] = "foreign"
        changed["INSTALLATION-PREVIEW.json"] = json.dumps(metadata).encode()
        with self.assertRaisesRegex(ValueError, "original_package_mismatch"):
            self.check(root, changed)

    def test_json_rejects_duplicates_and_nonfinite_values(self):
        for value in [b'{"version":1,"version":2}', b'{"x":NaN}', b'[]']:
            with self.assertRaises(ValueError):
                target.strict_json(value)

    def test_root_cannot_build_or_read_package(self):
        with patch.object(target.os, "getuid", return_value=0), patch.object(target, "original_package") as read:
            with self.assertRaisesRegex(ValueError, "nonroot"):
                target.build("unused", "unused", "unused", "unused")
            read.assert_not_called()

    def test_build_is_isolated_and_never_runs_generated_executable(self):
        root = Path(tempfile.mkdtemp(prefix="router-recovery-build-")).resolve()
        repo, original, developer = (root / name for name in ["repo", "original", "developer"])
        for path in [repo, original, developer]:
            path.mkdir()
        output = root / "output"
        source = ('public static let version = "1.19.32"\npublic static let executableSHA256 = "' + target.PINS["payload/mihomo"] + '"').encode()
        commands = []
        def run(command, **kwargs):
            commands.append(command)
            build = kwargs["cwd"]
            binaries = build / ".build/release"
            if command[0] == "/usr/bin/swift":
                binaries.mkdir(parents=True, exist_ok=True)
                executable = binaries / "router-system-resume"
                if not executable.exists():
                    executable.write_bytes(b"signed by mock only")
            data = (str(binaries) + "\n").encode() if "--show-bin-path" in command else b""
            return target.subprocess.CompletedProcess(command, 0, data)
        with patch.object(target, "original_package", return_value={"metadata": b"fixed"}), \
                patch.object(target, "routing_sources", return_value={"Sources/RoutingCore/RouterCoreRelease.swift": source}), \
                patch.object(target.subprocess, "run", side_effect=run):
            result = target.build(repo, original, output, developer)
        self.assertFalse(result["installed"])
        self.assertEqual([c[0] for c in commands], ["/usr/bin/swift", "/usr/bin/swift", "/usr/bin/codesign", "/usr/bin/codesign"])
        main = (output / "build-source/Sources/RecoveryEntry/main.swift").read_text()
        self.assertIn("requireExisting: true", main)
        self.assertIn(target.TRANSACTION, main); self.assertIn(target.HELPER, main)
        self.assertEqual(list(original.iterdir()), [])
        with self.assertRaises(ValueError):
            target.packaging.prepare_output(output)


if __name__ == "__main__":
    unittest.main()
