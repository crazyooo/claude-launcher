#!/usr/bin/env python3
"""Install / uninstall Claude protect L4 LaunchDaemon.

Default is plan/preview only. Mutate requires --i-confirm-install or
--i-confirm-uninstall plus root.

Does not stop 你的代理客户端. Does not claim protection_verified.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

LABEL = "com.crazyooo.claude-protect-guard"
PLIST_NAME = f"{LABEL}.plist"
DEST_BIN = Path("/usr/local/bin/claude-protect-guard")
DEST_PLIST = Path(f"/Library/LaunchDaemons/{PLIST_NAME}")
SRC_DIR = Path(__file__).resolve().parent
REPO_TOOLS = SRC_DIR.parent
SRC_GUARD = REPO_TOOLS / "claude_protect_guard.py"
SRC_PLIST = SRC_DIR / PLIST_NAME


def ok(status: str, **extra) -> int:
    payload = {
        "version": 1,
        "product": "claude_protect_l4_daemon",
        "status": status,
        "protection_verified": False,
        "routing_verified": False,
        "accepted": False,
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def die(reason: str, **extra) -> int:
    payload = {
        "version": 1,
        "product": "claude_protect_l4_daemon",
        "status": "blocked",
        "reason": reason,
        "protection_verified": False,
        "routing_verified": False,
        "accepted": False,
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 78


def plan() -> dict:
    return {
        "label": LABEL,
        "src_guard": str(SRC_GUARD),
        "src_plist": str(SRC_PLIST),
        "dest_bin": str(DEST_BIN),
        "dest_plist": str(DEST_PLIST),
        "bin_exists": DEST_BIN.is_file(),
        "plist_exists": DEST_PLIST.is_file(),
        "src_guard_ok": SRC_GUARD.is_file(),
        "src_plist_ok": SRC_PLIST.is_file(),
        "load_command": f"sudo launchctl bootstrap system {DEST_PLIST}",
        "unload_command": f"sudo launchctl bootout system/{LABEL}",
        "notes": [
            "Default watch targets 127.0.0.1:1082 and Claude Desktop/CLI path patterns.",
            "Install copies claude_protect_guard.py to /usr/local/bin/claude-protect-guard.",
            "Does not auto-stop 你的代理客户端; only Claude processes on proxy failure.",
        ],
    }


def cmd_plan(_args: argparse.Namespace) -> int:
    return ok("plan", **plan())


def cmd_status(_args: argparse.Namespace) -> int:
    loaded = False
    try:
        proc = subprocess.run(
            ["/bin/launchctl", "print", f"system/{LABEL}"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        loaded = proc.returncode == 0 and "state = running" in (proc.stdout or "")
    except OSError:
        loaded = False
    p = plan()
    p.update(
        {
            "daemon_print_ok": loaded,
            "installed_bin": DEST_BIN.is_file(),
            "installed_plist": DEST_PLIST.is_file(),
        }
    )
    return ok("status", **p)


def cmd_install(args: argparse.Namespace) -> int:
    if not args.i_confirm_install:
        return die("install_requires_confirm", need=["--i-confirm-install"], plan=plan())
    if os.geteuid() != 0:
        return die("install_requires_root", plan=plan())
    if not SRC_GUARD.is_file() or not SRC_PLIST.is_file():
        return die("source_missing", plan=plan())
    DEST_BIN.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(SRC_GUARD, DEST_BIN)
    os.chmod(DEST_BIN, 0o755)
    text = DEST_BIN.read_text(encoding="utf-8")
    if not text.startswith("#!"):
        return die("guard_missing_shebang")
    # Prefer /usr/bin/python3 shebang for LaunchDaemon reliability.
    if text.startswith("#!/usr/bin/env python3"):
        DEST_BIN.write_text("#!/usr/bin/python3\n" + text.split("\n", 1)[1], encoding="utf-8")
        os.chmod(DEST_BIN, 0o755)
    shutil.copy2(SRC_PLIST, DEST_PLIST)
    os.chmod(DEST_PLIST, 0o644)
    subprocess.run(["/bin/launchctl", "bootout", f"system/{LABEL}"], check=False, capture_output=True)
    load = subprocess.run(
        ["/bin/launchctl", "bootstrap", "system", str(DEST_PLIST)],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if load.returncode != 0:
        return die("launchctl_bootstrap_failed", stderr=(load.stderr or "")[-1000:])
    return ok(
        "installed",
        label=LABEL,
        dest_bin=str(DEST_BIN),
        dest_plist=str(DEST_PLIST),
        note="daemon loaded; verify with status; protection_verified stays false",
    )


def cmd_uninstall(args: argparse.Namespace) -> int:
    if not args.i_confirm_uninstall:
        return die("uninstall_requires_confirm", need=["--i-confirm-uninstall"])
    if os.geteuid() != 0:
        return die("uninstall_requires_root")
    subprocess.run(["/bin/launchctl", "bootout", f"system/{LABEL}"], check=False, capture_output=True)
    if DEST_PLIST.exists():
        DEST_PLIST.unlink()
    if DEST_BIN.exists():
        DEST_BIN.unlink()
    return ok("uninstalled", label=LABEL)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("plan").set_defaults(func=cmd_plan)
    sub.add_parser("status").set_defaults(func=cmd_status)
    i = sub.add_parser("install")
    i.add_argument("--i-confirm-install", action="store_true")
    i.set_defaults(func=cmd_install)
    u = sub.add_parser("uninstall")
    u.add_argument("--i-confirm-uninstall", action="store_true")
    u.set_defaults(func=cmd_uninstall)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
