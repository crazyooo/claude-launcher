#!/usr/bin/env python3
"""Operator-executed journal recovery (evidence-preserving archival unlock, direction B).

Archives the complete system-host state directory, then resets journal.json to the
validated idle state so an exactJournal upgrade can proceed while stop cleanup cannot
prove against persistent environmental drift. Never touches stage directories, locks,
launchd or the running helper; the helper reads the journal from disk per request.
"""
import argparse
import json
import os
import shutil
import stat
import sys
import uuid

STATE = "/Library/Application Support/Claude Router/state"


def fail(message):
    print(json.dumps({"recovered": False, "error": message}, sort_keys=True))
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, help="new directory for the evidence copy")
    parser.add_argument("--state", default=STATE)
    arguments = parser.parse_args()

    if os.geteuid() != 0 or os.getuid() != 0:
        fail("requires_root")
    state = os.path.realpath(arguments.state)
    if not os.path.isdir(state) or state == "/":
        fail("state_directory_missing")
    info = os.stat(state)
    if info.st_uid != 0 or info.st_mode & 0o077:
        fail("unsafe_state_directory")
    archive = os.path.realpath(arguments.archive)
    if os.path.exists(archive) or os.path.lexists(archive):
        fail("archive_must_be_new")
    if not archive.startswith(os.path.realpath(os.path.expanduser("~/projects/claude-launcher-preserved/"))):
        fail("archive_outside_preserved")

    journal_path = os.path.join(state, "journal.json")
    try:
        with open(journal_path, "rb") as handle:
            current = json.loads(handle.read().decode())
        before = os.stat(journal_path)
    except (OSError, ValueError) as error:
        fail("unreadable_journal:%s" % type(error).__name__)
    if current.get("version") != 1 or current.get("phase") not in ("stopping", "stopped", "fault"):
        fail("unexpected_phase:%s" % current.get("phase"))
    installation = current.get("installation")
    if not isinstance(installation, dict) or not installation.get("id") or installation.get("ownerUID") != 501:
        fail("installation_identity_missing")

    os.makedirs(archive, mode=0o700)
    for name in sorted(os.listdir(state)):
        source = os.path.join(state, name)
        if os.path.isdir(source) and not os.path.islink(source):
            shutil.copytree(source, os.path.join(archive, name), symlinks=False)
        else:
            shutil.copy2(source, os.path.join(archive, name))
    for root, directories, files in os.walk(archive):
        os.chown(root, 501, 20)
        os.chmod(root, 0o700)
        for entry in files:
            path = os.path.join(root, entry)
            os.chown(path, 501, 20)
            os.chmod(path, 0o600)
    with open(os.path.join(archive, "RECOVERY-MANIFEST.json"), "w") as handle:
        json.dump({"recovered_at": "operator-executed", "previous_phase": current.get("phase"),
                   "previous_reason": current.get("reason"), "previous_revision": current.get("revision"),
                   "instance": (current.get("intent") or {}).get("id")}, handle, indent=1, sort_keys=True)
    os.chown(os.path.join(archive, "RECOVERY-MANIFEST.json"), 501, 20)

    reset = {"installation": installation, "phase": "idle", "reason": "no_system_instance",
             "revision": str(uuid.uuid4()), "version": 1}
    temporary = os.path.join(state, "journal.json.recovery-" + uuid.uuid4().hex)
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, (json.dumps(reset, sort_keys=True, separators=(",", ":")) + "\n").encode())
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, journal_path)
    directory_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    after = os.stat(journal_path)
    print(json.dumps({"recovered": True, "archive": archive,
                      "journal_mode": oct(stat.S_IMODE(after.st_mode)), "phase": "idle",
                      "previous_phase": current.get("phase"), "previous_reason": current.get("reason")},
                     sort_keys=True))


if __name__ == "__main__":
    main()
