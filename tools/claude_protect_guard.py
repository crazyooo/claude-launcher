#!/usr/bin/env python3
"""Claude chain-proxy guard (L4): when proxy is down, stop Claude + notify.

Product: docs/product-detect-guard.md
- Health: TCP connect to local proxy host:port (default 127.0.0.1:1082).
- Optional: require process pattern match (你的代理客户端), off by default.
- On unhealthy (after debounce): terminate matching Claude Desktop/CLI PIDs
  and post a macOS notification (GUI user).
- Default CLI is one-shot status / dry-run. Loop mode is explicit.
- Never stops 你的代理客户端 / 小火箭. Never claims protection_verified.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Callable

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 1082

# Path substrings matched via pgrep -f (Desktop + CLI install layouts).
DEFAULT_CLAUDE_PATTERNS = (
    "/Applications/Claude.app/Contents/",
    "/.local/bin/claude",
    "/.claude/local/claude",
    "/.claude/versions/",
)


@dataclass(frozen=True)
class Health:
    ok: bool
    reason: str


def probe_tcp(host: str, port: int, timeout: float = 0.8) -> Health:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return Health(True, "proxy_port_open")
    except OSError:
        return Health(False, "proxy_port_unreachable")


def list_pids(patterns: tuple[str, ...], runner: Callable | None = None) -> list[int]:
    run = runner or subprocess.run
    found: set[int] = set()
    for pattern in patterns:
        proc = run(
            ["/usr/bin/pgrep", "-f", pattern],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if line.isdigit():
                found.add(int(line))
    return sorted(found)


def terminate_pids(pids: list[int], dry_run: bool, killer: Callable | None = None) -> list[int]:
    if dry_run or not pids:
        return []
    kill = killer or os.kill
    sent: list[int] = []
    for pid in pids:
        try:
            kill(pid, signal.SIGTERM)
            sent.append(pid)
        except ProcessLookupError:
            continue
        except PermissionError:
            continue
    return sent


def notify_user(title: str, message: str, notifier: Callable | None = None) -> bool:
    """Best-effort notification as the console GUI user."""
    if notifier is not None:
        return notifier(title, message)
    user = subprocess.run(
        ["/usr/bin/stat", "-f%Su", "/dev/console"],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    ).stdout.strip()
    if not user or user == "root":
        return False
    uid_proc = subprocess.run(
        ["/usr/bin/id", "-u", user],
        capture_output=True,
        text=True,
        timeout=3,
        check=False,
    )
    if uid_proc.returncode != 0:
        return False
    uid = uid_proc.stdout.strip()
    script = (
        f'display notification "{message}" with title "{title}" sound name "Basso"'
    )
    proc = subprocess.run(
        ["/bin/launchctl", "asuser", uid, "/usr/bin/osascript", "-e", script],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    return proc.returncode == 0


def snapshot(
    host: str,
    port: int,
    patterns: tuple[str, ...],
    dry_run: bool,
    *,
    probe: Callable | None = None,
    pid_runner: Callable | None = None,
    killer: Callable | None = None,
    notifier: Callable | None = None,
    act: bool = False,
) -> dict:
    health = (probe or probe_tcp)(host, port)
    pids = list_pids(patterns, runner=pid_runner)
    result = {
        "version": 1,
        "product": "claude_protect_l4",
        "proxy_host": host,
        "proxy_port": port,
        "healthy": health.ok,
        "health_reason": health.reason,
        "claude_pids": pids,
        "dry_run": dry_run,
        "action": "none",
        "terminated": [],
        "notified": False,
        "protection_verified": False,
        "routing_verified": False,
        "accepted": False,
    }
    if health.ok or not act:
        return result
    result["action"] = "terminate_claude"
    result["terminated"] = terminate_pids(pids, dry_run=dry_run, killer=killer)
    if not dry_run:
        result["notified"] = notify_user(
            "Claude 断网防护",
            f"链式代理 {host}:{port} 不可用，已停止 Claude 相关进程。",
            notifier=notifier,
        )
    else:
        result["would_terminate"] = pids
        result["notified"] = False
    return result


def cmd_status(args: argparse.Namespace) -> int:
    patterns = tuple(args.pattern) if args.pattern else DEFAULT_CLAUDE_PATTERNS
    payload = snapshot(
        args.host,
        args.port,
        patterns,
        dry_run=True,
        act=False,
    )
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if payload["healthy"] else 1


def cmd_check(args: argparse.Namespace) -> int:
    """One-shot: if unhealthy, optionally terminate (respect dry-run)."""
    patterns = tuple(args.pattern) if args.pattern else DEFAULT_CLAUDE_PATTERNS
    payload = snapshot(
        args.host,
        args.port,
        patterns,
        dry_run=args.dry_run,
        act=True,
    )
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    if payload["healthy"]:
        return 0
    return 2 if payload["action"] == "terminate_claude" else 1


def cmd_watch(args: argparse.Namespace) -> int:
    patterns = tuple(args.pattern) if args.pattern else DEFAULT_CLAUDE_PATTERNS
    bad = 0
    while True:
        payload = snapshot(
            args.host,
            args.port,
            patterns,
            dry_run=args.dry_run,
            act=False,
        )
        if payload["healthy"]:
            bad = 0
        else:
            bad += 1
            if bad >= args.debounce:
                payload = snapshot(
                    args.host,
                    args.port,
                    patterns,
                    dry_run=args.dry_run,
                    act=True,
                )
                print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
                bad = 0
                time.sleep(args.cooldown)
                continue
        if args.once:
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
            return 0 if payload["healthy"] else 1
        time.sleep(args.interval)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Claude protect L4 chain-proxy guard")
    p.add_argument("--host", default=DEFAULT_HOST)
    p.add_argument("--port", type=int, default=DEFAULT_PORT)
    p.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Extra/override pgrep -f pattern (repeatable). Default Desktop+CLI set if omitted.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("status", help="One-shot health + PID list")
    s.set_defaults(func=cmd_status)

    c = sub.add_parser("check", help="If unhealthy, terminate Claude (see --dry-run)")
    c.add_argument("--dry-run", action="store_true")
    c.set_defaults(func=cmd_check)

    w = sub.add_parser("watch", help="Poll proxy; act after debounce")
    w.add_argument("--interval", type=float, default=0.5)
    w.add_argument("--debounce", type=int, default=2)
    w.add_argument("--cooldown", type=float, default=20.0)
    w.add_argument("--dry-run", action="store_true")
    w.add_argument("--once", action="store_true", help="Single iteration then exit")
    w.set_defaults(func=cmd_watch)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    # If user passed --pattern, use only those; else defaults.
    if not args.pattern:
        args.pattern = list(DEFAULT_CLAUDE_PATTERNS)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
