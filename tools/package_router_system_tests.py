import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid

SPEC = importlib.util.spec_from_file_location("packager", Path(__file__).with_name("package_router_system.py"))
packager = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packager)


class PackageTests(unittest.TestCase):
    def folder(self):
        # Keep fixture evidence; no automatic permanent deletion.
        return Path(tempfile.mkdtemp(prefix="router-package-test-")).resolve()

    def test_root_is_rejected_before_any_read_or_build(self):
        with patch.object(packager.os, "getuid", return_value=0), patch.object(packager.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "requires_nonroot"):
                packager.build_package("missing", "missing", "missing", None)
            run.assert_not_called()

    def test_new_artifacts_cannot_replace_existing_output(self):
        folder = self.folder()
        packager.write_new(folder / "keep", b"original")
        with self.assertRaises(FileExistsError):
            packager.write_new(folder / "keep", b"replacement")
        with self.assertRaisesRegex(ValueError, "output_must_be_new"):
            packager.prepare_output(folder)
        self.assertEqual((folder / "keep").read_bytes(), b"original")

    def test_read_rejects_symlinks_hardlinks_and_writable_files(self):
        folder = self.folder()
        source = folder / "source"
        packager.write_new(source, b"fixed")
        self.assertEqual(packager.read_file(source), b"fixed")
        link = folder / "link"
        link.symlink_to(source)
        with self.assertRaisesRegex(ValueError, "symlink"):
            packager.read_file(link)
        os.link(source, folder / "hardlink")
        with self.assertRaisesRegex(ValueError, "unsafe_source"):
            packager.read_file(source)
        writable = folder / "writable"
        writable.write_bytes(b"fixed"); writable.chmod(0o666)
        with self.assertRaisesRegex(ValueError, "unsafe_source"):
            packager.read_file(writable)

    def test_generated_entry_contains_only_frozen_identity_and_safe_failure(self):
        identifier, digest = uuid.uuid4(), "a" * 64
        entry = packager.entry(identifier, digest).decode()
        self.assertIn(str(identifier), entry)
        self.assertIn(digest, entry)
        self.assertIn("RouterSystemInstaller.run", entry)
        self.assertIn('"routing_verified": false', entry)
        self.assertNotIn("\\n", entry)
        with self.assertRaises(ValueError):
            packager.entry(identifier, '"; arbitrary source')

    def test_only_selected_swift_targets_enter_snapshot(self):
        repo = self.folder()
        for name in ("RoutingCore", "RouterSystemHelper", "LauncherApp"):
            target = repo / "Sources" / name
            target.mkdir(parents=True)
            packager.write_new(target / "main.swift", ("// " + name).encode())
            packager.write_new(target / "secret.txt", b"not copied")
        snapshot = packager.source_snapshot(repo)
        self.assertEqual(set(snapshot), {"Sources/RoutingCore/main.swift", "Sources/RouterSystemHelper/main.swift"})
        (repo / "Sources/RoutingCore/linked.swift").symlink_to(repo / "Sources/LauncherApp/main.swift")
        with self.assertRaisesRegex(ValueError, "symlink"):
            packager.source_snapshot(repo)

    def test_generated_rewrite_requires_exact_owned_preimage(self):
        folder = self.folder()
        path = folder / "main.swift"
        packager.write_new(path, b"placeholder")
        with self.assertRaisesRegex(ValueError, "generated_source_changed"):
            packager.replace_generated(path, b"unexpected", b"bad")
        self.assertEqual(path.read_bytes(), b"placeholder")
        packager.replace_generated(path, b"placeholder", b"final")
        self.assertEqual(path.read_bytes(), b"final")


if __name__ == "__main__":
    unittest.main()
