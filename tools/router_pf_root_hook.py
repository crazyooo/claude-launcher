#!/usr/bin/env python3
"""Journaled root-hook + optional pfctl -E for `claude_router_failclosed`.

Mirrors the ownership discipline of `pf_guard.py`, but:
  - fixed anchor name (not `clguard_<id>`)
  - allows coexisting `clguard_*` / Apple anchors
  - refuses if this fail-closed anchor is already hooked
  - never claims routing_verified / accepted / fail-closed proven

Lifecycle (default = stage only, no mutation):
  1. stage   — snapshot root, compute root_after, syntax-check, write journal
  2. apply   — dual confirm + root: load root_after; if PF was disabled, -E with receipt
  3. restore — dual confirm + root: restore root_before; release our token if we enabled

Journal directory (mode 0700, files 0600):
  default `/private/var/run/claude-launcher-pf-failclosed`
  override with --journal-dir or ROUTER_PF_FAILCLOSED_JOURNAL
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ANCHOR = "claude_router_failclosed"
WINDOW = "pf-arming-user-confirm-v1"
PLAN_KIND = "router_pf_failclosed_root_hook"
POLICY_VERSION = 1
DEFAULT_JOURNAL = Path("/private/var/run/claude-launcher-pf-failclosed")
JOURNAL_ENV = "ROUTER_PF_FAILCLOSED_JOURNAL"
LIMIT = 1024 * 1024
APPLE_SCRUB = 'scrub-anchor "com.apple/*" all fragment reassemble'


class HookError(Exception):
    """Fixed diagnostic codes only — never raw pfctl blobs."""


def normalize(text: str) -> str:
    return "\n".join(line.strip() for line in text.splitlines() if line.strip())


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def fingerprint(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def die(reason: str, **extra) -> int:
    payload = {
        "version": 1,
        "status": "blocked",
        "reason": reason,
        "pf_modified": False,
        "armed": False,
        "hook_installed": False,
        "routing_verified": False,
        "protection_verified": False,
        "launch_authorized": False,
        "accepted": False,
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 78


def ok(status: str, **extra) -> int:
    payload = {
        "version": 1,
        "status": status,
        "routing_verified": False,
        "protection_verified": False,
        "launch_authorized": False,
        "accepted": False,
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def reference_tokens(output: str) -> set[str]:
    """macOS -s References is a table, unlike the -E receipt's Token line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines and lines[0] == "TOKENS:":
        lines.pop(0)
    if lines == ["No pf starter references held"]:
        return set()
    if not lines or not re.fullmatch(r"PID\s+Process Name\s+TOKEN\s+TIMESTAMP", lines[0]):
        raise HookError("pf_reference_table_unknown")
    tokens: set[str] = set()
    for line in lines[1:]:
        match = re.fullmatch(
            r"[0-9]+\s+.{1,28}?\s+([0-9]{1,20})\s+[0-9]+ days [0-9]{2}:[0-9]{2}:[0-9]{2}",
            line,
        )
        if not match or int(match[1]) >= 2**64 or match[1] in tokens:
            raise HookError("pf_reference_table_unknown")
        tokens.add(match[1])
    return tokens


def build_root_after(before: str, name: str = ANCHOR) -> str:
    """Insert `anchor "name" quick all` after Apple scrub (if present).

    Baseline must be scrub (optional) followed only by top-level anchor lines.
    Coexistence with `clguard_*` / `com.apple/*` is allowed; duplicate of *our*
    anchor is refused.
    """
    lines = before.splitlines()
    insertion = 1 if lines and lines[0] == APPLE_SCRUB else 0
    for line in lines[insertion:]:
        if not re.fullmatch(r'anchor "[A-Za-z0-9_./*-]+"(?: quick)? all', line):
            raise HookError("root_baseline_requires_manual_review")
        if f'anchor "{name}"' in line:
            raise HookError("failclosed_anchor_already_hooked")
    lines.insert(insertion, f'anchor "{name}" quick all')
    return normalize("\n".join(lines))


def parse_enable_token(text: str) -> str:
    tokens = re.findall(r"^Token\s*:\s*([0-9]{1,20})\s*$", text, re.M)
    if len(tokens) != 1 or int(tokens[0]) >= 2**64:
        raise HookError("enable_reference_ownership_unknown")
    return tokens[0]


class PF:
    """Thin pfctl adapter. Tests inject a FakePF with the same surface."""

    def call(self, *args: str, source: str | None = None) -> str:
        try:
            result = subprocess.run(
                ["/sbin/pfctl", *args],
                input=source,
                text=True,
                capture_output=True,
                timeout=8,
                env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HookError("pfctl_unavailable_or_timeout") from exc
        if result.returncode:
            raise HookError("pfctl_rejected")
        if len(result.stdout) > 2 * 1024 * 1024:
            raise HookError("pfctl_output_too_large")
        return result.stdout

    def enabled(self) -> bool:
        match = re.search(r"^Status: (Enabled|Disabled)\b", self.call("-s", "info"), re.M)
        if not match:
            raise HookError("pf_status_unknown")
        return match[1] == "Enabled"

    def root(self) -> str:
        return normalize(self.call("-s", "rules"))

    def references(self) -> str:
        return self.call("-s", "References")

    def syntax(self, source: str) -> str:
        return normalize(self.call("-n", "-v", "-o", "none", "-R", "-f", "-", source=source + "\n"))

    def load_root(self, source: str) -> None:
        self.call("-o", "none", "-R", "-f", "-", source=source + "\n")

    def enable_with_receipt(self, store: "Store") -> str:
        fd = store.create_receipt()
        try:
            with os.fdopen(fd, "wb") as receipt:
                result = subprocess.run(
                    ["/sbin/pfctl", "-E"],
                    stdout=receipt,
                    stderr=receipt,
                    timeout=5,
                    env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
                )
                receipt.flush()
                os.fsync(receipt.fileno())
                if result.returncode:
                    raise HookError("pf_enable_failed_check_receipt")
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise HookError("pf_enable_outcome_unknown") from exc
        return store.receipt_token()

    def release(self, token: str) -> None:
        self.call("-X", token)


class Store:
    def __init__(self, directory: Path):
        self.directory = directory

    def sync_directory(self) -> None:
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    @contextmanager
    def lock(self):
        self.directory.mkdir(mode=0o700, exist_ok=True)
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise HookError("unsafe_journal_directory")
        fd = os.open(
            self.directory / "operation.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
        )
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise HookError("unsafe_lock_file")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise HookError("hook_operation_in_progress") from exc
            yield
        finally:
            os.close(fd)

    def _path(self, kind: str) -> Path:
        return self.directory / f"hook.{kind}"

    def _read_fd(self, fd: int, owned: bool) -> bytes:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > LIMIT:
                raise HookError("unsafe_or_oversized_file")
            if owned and (
                info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise HookError("unsafe_journal_file")
            data = stream.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise HookError("oversized_file")
            return data

    def read(self, kind: str) -> dict:
        fd = os.open(self._path(kind), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        return json.loads(self._read_fd(fd, True))

    def write(self, kind: str, value: dict, exclusive: bool = False) -> None:
        target = self._path(kind)
        temp = target if exclusive else self.directory / (uuid.uuid4().hex + ".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(value, stream, sort_keys=True)
            stream.flush()
            os.fsync(stream.fileno())
        if not exclusive:
            os.replace(temp, target)
        self.sync_directory()

    def create_receipt(self) -> int:
        fd = os.open(
            self._path("receipt"),
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(fd, 0o600)
        self.sync_directory()
        return fd

    def receipt_token(self) -> str:
        try:
            fd = os.open(self._path("receipt"), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            text = self._read_fd(fd, True).decode("ascii")
        except (OSError, UnicodeError) as exc:
            raise HookError("enable_reference_ownership_unknown") from exc
        return parse_enable_token(text)

    def has(self, kind: str) -> bool:
        return self._path(kind).exists()


def journal_dir_from_env(explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    env = os.environ.get(JOURNAL_ENV)
    if env:
        return Path(env)
    return DEFAULT_JOURNAL


def stage(pf: PF, store: Store) -> dict:
    """Read-only w.r.t. live PF mutation: snapshot + syntax + journal write."""
    plan = {
        "version": 1,
        "policy_version": POLICY_VERSION,
        "kind": PLAN_KIND,
        "anchor": ANCHOR,
        "window_id": WINDOW,
        "created_at": time.time(),
        "pf_was_enabled": pf.enabled(),
        "root_before": pf.root(),
        "references_before_sha256": fingerprint(sorted(reference_tokens(pf.references()))),
    }
    plan["root_after"] = build_root_after(plan["root_before"], ANCHOR)
    # Do not trust dry-run rewritten paths; still require syntax acceptance.
    rendered = pf.syntax(plan["root_after"])
    if f'anchor "{ANCHOR}"' not in rendered and f'anchor "{ANCHOR}"' not in plan["root_after"]:
        raise HookError("hook_line_missing_after_syntax")
    plan["root_before_sha256"] = sha256_text(plan["root_before"])
    plan["root_after_sha256"] = sha256_text(plan["root_after"])
    # plan_sha256 covers the staged fields excluding itself.
    body = {k: v for k, v in plan.items() if k != "plan_sha256"}
    plan["plan_sha256"] = fingerprint(body)
    if store.has("state"):
        phase = store.read("state").get("phase")
        if phase == "installed_unverified":
            raise HookError("hook_already_installed_restore_first")
        if phase in ("root_pending", "enable_pending", "release_pending"):
            raise HookError("hook_operation_incomplete_restore_or_inspect")
    store.write("plan", plan, exclusive=not store.has("plan"))
    return plan


def check_plan(plan: dict, pf: PF) -> None:
    if plan.get("version") != 1 or plan.get("kind") != PLAN_KIND:
        raise HookError("invalid_hook_plan")
    if plan.get("anchor") != ANCHOR:
        raise HookError("hook_plan_anchor_mismatch")
    if type(plan.get("pf_was_enabled")) is not bool:
        raise HookError("invalid_hook_plan")
    if build_root_after(plan["root_before"], ANCHOR) != plan["root_after"]:
        raise HookError("hook_plan_content_mismatch")
    pf.syntax(plan["root_after"])


def save_state(store: Store, state: dict, **updates) -> None:
    state.update(updates)
    store.write("state", state)


def restore(plan: dict, pf: PF, store: Store) -> None:
    check_plan(plan, pf)
    state = store.read("state")
    if state.get("plan_sha256") != plan.get("plan_sha256"):
        raise HookError("journal_plan_mismatch")
    if state.get("phase") == "restored":
        return
    root = pf.root()
    if root not in (plan["root_before"], plan["root_after"]):
        raise HookError("foreign_rule_change_recovery_refused")
    token = store.receipt_token() if state.get("enable_attempted") else None
    if token:
        reference_tokens(pf.references())
    if root == plan["root_after"]:
        if not state.get("root_attempted"):
            raise HookError("root_not_owned")
        pf.load_root(plan["root_before"])
    if pf.root() != plan["root_before"]:
        raise HookError("root_restore_verification_failed")
    if token:
        save_state(store, state, phase="release_pending")
        refs = reference_tokens(pf.references())
        if token in refs:
            save_state(store, state, release_attempted=True)
            pf.release(token)
            if token in reference_tokens(pf.references()):
                raise HookError("reference_release_verification_failed")
        elif state.get("release_attempted") is not True:
            save_state(store, state, reference_already_absent=True)
        # Drop exclusive receipt so a later restage/apply can create a new -E file.
        receipt = store._path("receipt")
        if receipt.exists():
            receipt.unlink()
    save_state(store, state, phase="restored", hook_installed=False)


def apply_hook(plan: dict, pf: PF, store: Store, confirmed_plan_sha256: str) -> dict:
    check_plan(plan, pf)
    if confirmed_plan_sha256 != plan["plan_sha256"]:
        raise HookError("reviewed_plan_digest_required")
    if time.time() - plan["created_at"] > 300 or time.time() < plan["created_at"]:
        raise HookError("plan_expired_restage_required")
    if (
        pf.root() != plan["root_before"]
        or pf.enabled() != plan["pf_was_enabled"]
        or fingerprint(sorted(reference_tokens(pf.references()))) != plan["references_before_sha256"]
    ):
        raise HookError("system_changed_restage_required")
    if store.has("state"):
        prev = store.read("state").get("phase")
        if prev == "installed_unverified":
            raise HookError("hook_already_installed_restore_first")
        if prev in ("root_pending", "enable_pending", "release_pending"):
            raise HookError("hook_operation_incomplete_restore_or_inspect")
    state = {
        "plan_sha256": plan["plan_sha256"],
        "phase": "prepared",
        "hook_installed": False,
        "routing_verified": False,
        "accepted": False,
    }
    store.write("state", state, exclusive=not store.has("state"))
    try:
        save_state(store, state, phase="root_pending", root_attempted=True)
        pf.load_root(plan["root_after"])
        if pf.root() != plan["root_after"]:
            raise HookError("root_load_verification_failed")
        if not plan["pf_was_enabled"]:
            if pf.enabled() or fingerprint(sorted(reference_tokens(pf.references()))) != plan[
                "references_before_sha256"
            ]:
                raise HookError("pf_changed_before_enable")
            save_state(store, state, phase="enable_pending", enable_attempted=True)
            pf.enable_with_receipt(store)
        if not pf.enabled():
            raise HookError("pf_not_enabled_after_hook")
        if pf.root() != plan["root_after"]:
            raise HookError("rules_changed_during_hook_apply")
        save_state(
            store,
            state,
            phase="installed_unverified",
            hook_installed=True,
            installed_at=time.time(),
        )
        return state
    except BaseException:
        restore(plan, pf, store)
        raise


def hook_status(pf: PF, store: Store | None = None) -> dict:
    enabled = pf.enabled()
    root = pf.root()
    hooked = bool(re.search(rf'^anchor "{re.escape(ANCHOR)}"(?: quick)? all$', root, re.M))
    phase = None
    if store is not None and store.has("state"):
        try:
            phase = store.read("state").get("phase")
        except HookError:
            phase = "journal_unreadable"
    return {
        "pf_enabled": enabled,
        "root_references_anchor": hooked,
        "hook_installed": hooked and enabled,
        "armed": False,  # ruleset apply is a separate step
        "journal_phase": phase,
        "anchor": ANCHOR,
    }


# --- CLI ---


def cmd_stage(args: argparse.Namespace, pf: PF | None = None) -> int:
    store = Store(journal_dir_from_env(args.journal_dir))
    adapter = pf or PF()
    try:
        with store.lock():
            plan = stage(adapter, store)
    except HookError as exc:
        return die(str(exc))
    return ok(
        "hook_staged",
        pf_modified=False,
        armed=False,
        hook_installed=False,
        plan_sha256=plan["plan_sha256"],
        pf_was_enabled=plan["pf_was_enabled"],
        root_before_sha256=plan["root_before_sha256"],
        root_after_sha256=plan["root_after_sha256"],
        journal_dir=str(store.directory),
        note="review root_after then hook-apply with matching --plan-sha256; no live mutation yet",
    )


def cmd_apply(args: argparse.Namespace, pf: PF | None = None) -> int:
    # Confirm flags before privilege so non-root reviewers can exercise refusals.
    if not args.i_confirm_pf_arming_user_confirm_v1:
        return die("missing_flag_i_confirm_pf_arming_user_confirm_v1")
    if not args.i_acknowledge_network_mutation:
        return die("missing_flag_i_acknowledge_network_mutation")
    if not args.plan_sha256 or not re.fullmatch(r"[0-9a-f]{64}", args.plan_sha256):
        return die("plan_sha256_required_64_hex")
    store = Store(journal_dir_from_env(args.journal_dir))
    adapter = pf or PF()
    try:
        with store.lock():
            plan = store.read("plan")
            check_plan(plan, adapter)
            if args.plan_sha256 != plan["plan_sha256"]:
                return die("reviewed_plan_digest_required")
            if pf is None and os.geteuid() != 0:
                return die("root_required_for_hook_apply", plan_validated=True)
            state = apply_hook(plan, adapter, store, args.plan_sha256)
    except HookError as exc:
        return die(str(exc), pf_modified=True)
    return ok(
        "hook_installed_unverified",
        pf_modified=True,
        armed=False,
        hook_installed=True,
        pf_enabled=True,
        root_references_anchor=True,
        journal_phase=state.get("phase"),
        plan_sha256=args.plan_sha256,
        note="anchor referenced; load fail-closed rules via apply next; routing_verified remains false",
    )


def cmd_restore(args: argparse.Namespace, pf: PF | None = None) -> int:
    if not args.i_confirm_restore_hook:
        return die("missing_flag_i_confirm_restore_hook")
    store = Store(journal_dir_from_env(args.journal_dir))
    adapter = pf or PF()
    try:
        with store.lock():
            if pf is None and os.geteuid() != 0:
                return die("root_required_for_hook_restore")
            plan = store.read("plan")
            restore(plan, adapter, store)
    except HookError as exc:
        return die(str(exc), pf_modified=True)
    return ok(
        "hook_restored",
        pf_modified=True,
        armed=False,
        hook_installed=False,
        note="root_before restored; any fail-closed anchor rules should be unloaded separately",
    )


def cmd_status(args: argparse.Namespace, pf: PF | None = None) -> int:
    store = Store(journal_dir_from_env(args.journal_dir))
    adapter = pf or PF()
    try:
        info = hook_status(adapter, store if store.directory.exists() else None)
    except HookError as exc:
        return die(str(exc))
    return ok("hook_status", pf_modified=False, **info)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("stage", help="Snapshot root + write journal (no PF mutation)")
    s.add_argument("--journal-dir", default=None)

    a = sub.add_parser("apply", help="Install root hook (+ -E if PF was disabled)")
    a.add_argument("--journal-dir", default=None)
    a.add_argument("--plan-sha256", required=True)
    a.add_argument("--i-confirm-pf-arming-user-confirm-v1", action="store_true")
    a.add_argument("--i-acknowledge-network-mutation", action="store_true")

    r = sub.add_parser("restore", help="Restore root_before and release our -E token")
    r.add_argument("--journal-dir", default=None)
    r.add_argument("--i-confirm-restore-hook", action="store_true")

    t = sub.add_parser("status", help="PF enabled + whether root references our anchor")
    t.add_argument("--journal-dir", default=None)
    return parser


def main(argv: list[str] | None = None, pf: PF | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.cmd == "stage":
            return cmd_stage(args, pf=pf)
        if args.cmd == "apply":
            return cmd_apply(args, pf=pf)
        if args.cmd == "restore":
            return cmd_restore(args, pf=pf)
        if args.cmd == "status":
            return cmd_status(args, pf=pf)
    except Exception:  # noqa: BLE001 — CLI boundary
        return die("local_operation_failed", detail="unexpected")
    return die("invalid_command")


if __name__ == "__main__":
    sys.exit(main())
