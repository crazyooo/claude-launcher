#!/usr/bin/env python3
"""Claude Anthropic PF protect (L3): block direct egress on physical NICs.

Product: docs/product-detect-guard.md
- Block Anthropic ranges on physical interfaces only.
- Pass loopback; do not touch other destinations.
- Default: generate / dry-run / status. Mutate requires dual confirm + root.
- Never claims routing_verified / protection_verified / accepted.
- Never auto-stops 你的代理客户端 / 小火箭.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

ANCHOR = "claude_protect_anthropic"
POLICY_VERSION = 1
WINDOW = "claude-protect-pf-user-confirm-v1"

# Anthropic published ranges (see macos-claude-failclosed / public docs).
DEFAULT_V4 = "160.79.104.0/21"
DEFAULT_V6 = "2607:6bc0::/48"

# Interface names that are never treated as physical egress for this policy.
VIRTUAL_IF_PREFIXES = (
    "lo",
    "utun",
    "awdl",
    "llw",
    "bridge",
    "ap",
    "gif",
    "stf",
    "p2p",
    "ipsec",
    "vlan",
    "vmnet",
    "veth",
    "feth",
    "zt",
    "wg",
    "anpi",  # Apple internal NIC proxies
    "nan",  # Neighbor Awareness Networking
)


def die(reason: str, **extra) -> int:
    payload = {
        "version": 1,
        "status": "blocked",
        "reason": reason,
        "pf_modified": False,
        "armed": False,
        "routing_verified": False,
        "protection_verified": False,
        "launch_authorized": False,
        "accepted": False,
        "product": "claude_protect_l3",
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
        "product": "claude_protect_l3",
    }
    payload.update(extra)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2))
    return 0


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def is_virtual_if(name: str) -> bool:
    lower = name.lower()
    return any(lower == p or lower.startswith(p) for p in VIRTUAL_IF_PREFIXES)


def list_interfaces_ifconfig(text: str) -> list[str]:
    """Parse `ifconfig -l` whitespace-separated names."""
    names = [n for n in text.split() if n and re.fullmatch(r"[A-Za-z0-9._-]+", n)]
    return names


def list_hardware_port_devices(text: str) -> list[str]:
    """Parse `networksetup -listallhardwareports` Device lines.

    Skips Thunderbolt Bridge (aggregate); keeps Wi-Fi / Ethernet / USB LAN /
    individual Thunderbolt ethernet devices that can carry default routes.
    """
    devices: list[str] = []
    current_port = ""
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("Hardware Port:"):
            current_port = line.split(":", 1)[1].strip()
            continue
        if line.startswith("Device:"):
            name = line.split(":", 1)[1].strip()
            if not name or is_virtual_if(name):
                current_port = ""
                continue
            if "bridge" in current_port.lower():
                current_port = ""
                continue
            devices.append(name)
            current_port = ""
    return sorted(set(devices))


def physical_interfaces(
    ifconfig_l: str | None = None,
    hardware_ports: str | None = None,
) -> list[str]:
    """Prefer networksetup hardware ports; fall back to filtered ifconfig -l."""
    if hardware_ports is None:
        proc = subprocess.run(
            ["/usr/sbin/networksetup", "-listallhardwareports"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            hardware_ports = proc.stdout
    if hardware_ports:
        devices = list_hardware_port_devices(hardware_ports)
        if devices:
            return devices

    if ifconfig_l is None:
        proc = subprocess.run(
            ["/sbin/ifconfig", "-l"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError("ifconfig_list_failed")
        ifconfig_l = proc.stdout
    phys = [n for n in list_interfaces_ifconfig(ifconfig_l) if not is_virtual_if(n)]
    return sorted(set(phys))


def generate_pfconf(
    interfaces: list[str],
    v4: str = DEFAULT_V4,
    v6: str = DEFAULT_V6,
) -> str:
    if not interfaces:
        raise ValueError("no_physical_interfaces")
    lines = [
        f"# claude_protect L3 anchor={ANCHOR} policy={POLICY_VERSION}",
        f"# physical_ifs={','.join(interfaces)}",
        f"table <anthropic_net> persist {{ {v4}, {v6} }}",
        "pass out quick on lo0 all",
        "pass out quick to 127.0.0.1",
        "pass out quick to ::1",
    ]
    for iface in interfaces:
        # One block line per physical NIC — Anthropic only.
        lines.append(f"block drop out quick on {iface} to <anthropic_net>")
    return "\n".join(lines) + "\n"


def parse_canonical_conf(conf: str) -> dict:
    """Reject non-canonical / overly broad rules before any root apply."""
    if "\\" in conf or "\r" in conf or "\0" in conf:
        raise ValueError("pf_conf_not_canonical")
    body = [ln for ln in conf.splitlines() if ln and not ln.startswith("#")]
    if not body or not body[0].startswith("table <anthropic_net> persist"):
        raise ValueError("pf_conf_not_canonical")
    if "pass out quick on lo0 all" not in body:
        raise ValueError("pf_conf_not_canonical")
    blocks = [ln for ln in body if ln.startswith("block drop out quick on ")]
    if not blocks:
        raise ValueError("pf_conf_not_canonical")
    ifaces = []
    for ln in blocks:
        match = re.fullmatch(
            r"block drop out quick on ([A-Za-z0-9._-]+) to <anthropic_net>",
            ln,
        )
        if not match:
            raise ValueError("pf_conf_not_canonical")
        iface = match.group(1)
        if is_virtual_if(iface):
            raise ValueError("pf_conf_blocks_virtual_interface")
        ifaces.append(iface)
    # Forbid accidental whole-egress blocks.
    for ln in body:
        if re.search(r"\bblock\b", ln) and "to <anthropic_net>" not in ln:
            raise ValueError("pf_conf_non_anthropic_block")
        if "block drop out all" in ln or re.search(r"block drop out quick from any to any", ln):
            raise ValueError("pf_conf_overbroad")
    return {"interfaces": ifaces, "sha256": sha256_text(conf)}


def cmd_generate(args: argparse.Namespace) -> int:
    try:
        ifaces = (
            [x.strip() for x in args.interfaces.split(",") if x.strip()]
            if args.interfaces
            else physical_interfaces()
        )
        ifaces = [i for i in ifaces if not is_virtual_if(i)]
        conf = generate_pfconf(ifaces, args.v4, args.v6)
        meta = parse_canonical_conf(conf)
    except (RuntimeError, ValueError) as exc:
        return die(str(exc))
    out = {
        "anchor": ANCHOR,
        "policy_version": POLICY_VERSION,
        "interfaces": meta["interfaces"],
        "conf_sha256": meta["sha256"],
        "conf": conf,
        "armed": False,
        "pf_modified": False,
        "notes": [
            "L3 only blocks Anthropic ranges on listed physical NICs.",
            "Other apps and non-Anthropic destinations are untouched.",
            "Apply requires dual confirm + root; default path is dry-run.",
        ],
    }
    if args.output:
        path = Path(args.output)
        path.write_text(conf, encoding="utf-8")
        out["written"] = str(path)
    return ok("generated", **out)


def cmd_dry_run(args: argparse.Namespace) -> int:
    conf_path = Path(args.conf)
    if not conf_path.is_file():
        return die("conf_missing")
    conf = conf_path.read_text(encoding="utf-8")
    try:
        meta = parse_canonical_conf(conf)
    except ValueError as exc:
        return die(str(exc))
    # Syntax-check inside the named anchor (same shape as apply); never load.
    proc = subprocess.run(
        ["/sbin/pfctl", "-n", "-v", "-o", "none", "-a", ANCHOR, "-f", "-"],
        input=conf,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"},
    )
    payload = {
        "conf_sha256": meta["sha256"],
        "interfaces": meta["interfaces"],
        "pfctl_exit": proc.returncode,
        "pfctl_stderr": (proc.stderr or "")[-2000:],
        "armed": False,
        "pf_modified": False,
        "note": "dry-run only; not loaded into kernel",
    }
    if proc.returncode != 0:
        return die("pfctl_dry_run_rejected", **payload)
    return ok("dry_run_ok", **payload)


def pfctl(*args: str, source: str | None = None) -> str:
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
        raise RuntimeError("pfctl_unavailable_or_timeout") from exc
    if result.returncode:
        raise RuntimeError("pfctl_rejected")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError("pfctl_output_too_large")
    return result.stdout


def pf_enabled() -> bool:
    match = re.search(r"^Status: (Enabled|Disabled)\b", pfctl("-s", "info"), re.M)
    if not match:
        raise RuntimeError("pf_status_unknown")
    return match.group(1) == "Enabled"


def anchor_hooked() -> bool:
    pattern = rf'^anchor "{re.escape(ANCHOR)}"(?: quick)? all$'
    return re.search(pattern, pfctl("-s", "rules"), re.M) is not None


def cmd_status(_args: argparse.Namespace) -> int:
    try:
        rules = pfctl("-a", ANCHOR, "-s", "rules")
        enabled = pf_enabled()
        hooked = anchor_hooked()
    except RuntimeError as exc:
        # Non-root may fail some queries; fall back to soft status.
        soft = subprocess.run(
            ["/sbin/pfctl", "-a", ANCHOR, "-s", "rules"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        text = soft.stdout or ""
        return ok(
            "status",
            anchor=ANCHOR,
            armed=False,
            pf_modified=False,
            soft=True,
            reason=str(exc),
            rules_preview=text[:1500],
            rules_exit=soft.returncode,
        )
    nonempty = bool(rules.strip()) and ("block drop" in rules)
    armed = nonempty and enabled and hooked
    return ok(
        "status",
        anchor=ANCHOR,
        armed=armed,
        pf_enabled=enabled,
        root_references_anchor=hooked,
        rules_nonempty=nonempty,
        pf_modified=False,
        rules_preview=rules.strip().splitlines()[:30],
        note="armed requires pf enabled + root hook + nonempty Anthropic blocks",
    )


def cmd_apply(args: argparse.Namespace) -> int:
    if not args.i_confirm_apply or args.i_confirm_window != WINDOW:
        return die(
            "apply_requires_dual_confirm",
            need=["--i-confirm-apply", f"--i-confirm-window {WINDOW}"],
        )
    if not args.i_acknowledge_network_mutation:
        return die("missing_flag_i_acknowledge_network_mutation")
    conf_path = Path(args.conf)
    if not conf_path.is_file():
        return die("conf_missing")
    conf = conf_path.read_text(encoding="utf-8")
    try:
        meta = parse_canonical_conf(conf)
    except ValueError as exc:
        return die(str(exc))
    if args.conf_sha256 and args.conf_sha256 != meta["sha256"]:
        return die("conf_sha256_mismatch")
    # Validate refusals before privilege so non-root can exercise gates.
    if os.geteuid() != 0:
        return die("apply_requires_root", artifact_validated=True, conf_sha256=meta["sha256"])
    return apply_validated_conf(conf, meta)


def apply_validated_conf(conf: str, meta: dict) -> int:
    """Apply the exact bytes already validated in this process (no file reread)."""
    try:
        if not pf_enabled():
            return die(
                "pf_disabled_enable_token_journal_required",
                next_step="claude_protect_root_hook.py stage/apply first",
            )
        if not anchor_hooked():
            return die(
                "root_ruleset_does_not_reference_anchor",
                next_step="python3 tools/claude_protect_root_hook.py stage && … apply",
            )
        pfctl("-n", "-v", "-o", "none", "-a", ANCHOR, "-f", "-", source=conf)
        pfctl("-a", ANCHOR, "-o", "none", "-f", "-", source=conf)
        # Drop pre-existing states that would bypass new blocks (best-effort).
        try:
            pfctl("-k", "0.0.0.0/0", "-k", DEFAULT_V4)
        except RuntimeError:
            pass
        try:
            pfctl("-k", "::/0", "-k", DEFAULT_V6)
        except RuntimeError:
            pass
        rules = pfctl("-a", ANCHOR, "-s", "rules")
        effective = pf_enabled() and anchor_hooked() and bool(rules.strip())
    except RuntimeError as exc:
        return die(
            str(exc),
            pf_modified=True,
            next_step="run status; unload --i-confirm-unload if needed",
        )
    return ok(
        "applied_anchor" if effective else "anchor_loaded_not_effective",
        pf_modified=True,
        armed=effective,
        anchor=ANCHOR,
        conf_sha256=meta["sha256"],
        interfaces=meta["interfaces"],
        protection_verified=False,
        note="post-apply probe still required; protection_verified stays false",
    )


def protect_hook_module():
    # The installed wrapper uses python -I, which deliberately omits script-dir imports.
    directory = str(Path(__file__).resolve().parent)
    if directory not in sys.path:
        sys.path.insert(0, directory)
    import claude_protect_root_hook
    return claude_protect_root_hook


def cmd_enable(args: argparse.Namespace) -> int:
    """User-confirmed GUI enable: journal the root hook before loading our anchor."""
    if not args.i_confirm_apply or args.i_confirm_window != WINDOW:
        return die("apply_requires_dual_confirm")
    if not args.i_acknowledge_network_mutation:
        return die("missing_flag_i_acknowledge_network_mutation")
    try:
        fd = os.open(args.conf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 65_536:
                return die("enable_configuration_invalid")
            data = stream.read(65_537)
            if len(data) > 65_536:
                return die("enable_configuration_invalid")
            conf = data.decode("utf-8")
        meta = parse_canonical_conf(conf)
        if not args.conf_sha256 or args.conf_sha256 != meta["sha256"]:
            return die("conf_sha256_mismatch")
        # The GUI only enables the default Anthropic policy, never custom networks.
        if conf != generate_pfconf(meta["interfaces"]):
            return die("pf_conf_not_canonical")
        if meta["interfaces"] != physical_interfaces():
            return die("interfaces_changed_regenerate_required")
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        return die("enable_configuration_invalid", detail=str(exc))
    if os.geteuid() != 0:
        return die("apply_requires_root")

    module = protect_hook_module()
    hook = module.hook
    store = hook.Store(hook.journal_dir_from_env(None))
    adapter = hook.PF()
    hook_attempted = False
    try:
        with store.lock():
            current = hook.hook_status(adapter, store)
            phase = current.get("journal_phase")
            if phase in ("root_pending", "enable_pending", "release_pending", "journal_unreadable"):
                return die("hook_operation_incomplete_restore_or_inspect")
            if not current["hook_installed"]:
                if phase == "installed_unverified":
                    # After restart the journal can outlive PF. Only the owned,
                    # fingerprint-checked restoration path may clear that state.
                    hook_attempted = True
                    hook.restore(store.read("plan"), adapter, store)
                plan = hook.stage(adapter, store)
                hook_attempted = True
                hook.apply_hook(plan, adapter, store, plan["plan_sha256"])
            # Keep the hook lifecycle lock until the anchor operation completes.
            return apply_validated_conf(conf, meta)
    except (hook.HookError, OSError, ValueError) as exc:
        return die("enable_hook_failed", detail=str(exc), pf_modified=hook_attempted,
                   next_step="inspect status and hook journal before retrying")


def cmd_unload(args: argparse.Namespace) -> int:
    if not args.i_confirm_unload:
        return die("unload_requires_confirm", need=["--i-confirm-unload"])
    if os.geteuid() != 0:
        return die("unload_requires_root")
    try:
        pfctl("-a", ANCHOR, "-F", "rules")
        pfctl("-a", ANCHOR, "-F", "Tables")
    except RuntimeError as exc:
        return die(str(exc), pf_modified=False)
    return ok("unloaded_anchor", pf_modified=True, armed=False, anchor=ANCHOR)


def cmd_hook(args: argparse.Namespace) -> int:
    """Delegate to claude_protect_root_hook with remaining argv."""
    protect_hook = protect_hook_module()

    # Rebuild argv after `hook` subcommand: stage|apply|…
    rest = list(args.hook_argv)
    return protect_hook.main(rest)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Claude protect L3 PF (physical Anthropic block)")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Emit canonical pf conf")
    g.add_argument("--interfaces", default="", help="Comma list; default: auto physical")
    g.add_argument("--v4", default=DEFAULT_V4)
    g.add_argument("--v6", default=DEFAULT_V6)
    g.add_argument("--output", default="")
    g.set_defaults(func=cmd_generate)

    d = sub.add_parser("dry-run", help="Canonicalize + pfctl -n")
    d.add_argument("--conf", required=True)
    d.set_defaults(func=cmd_dry_run)

    s = sub.add_parser("status", help="Read-only anchor / armed status")
    s.set_defaults(func=cmd_status)

    a = sub.add_parser("apply", help="Load rules into anchor (root + dual confirm)")
    a.add_argument("--conf", required=True)
    a.add_argument("--conf-sha256", default="", help="Optional bind to generate digest")
    a.add_argument("--i-confirm-apply", action="store_true")
    a.add_argument("--i-confirm-window", default="")
    a.add_argument("--i-acknowledge-network-mutation", action="store_true")
    a.set_defaults(func=cmd_apply)

    e = sub.add_parser("enable", help="Journal root hook if needed, then apply confirmed default policy")
    e.add_argument("--conf", required=True)
    e.add_argument("--conf-sha256", required=True)
    e.add_argument("--i-confirm-apply", action="store_true")
    e.add_argument("--i-confirm-window", default="")
    e.add_argument("--i-acknowledge-network-mutation", action="store_true")
    e.set_defaults(func=cmd_enable)

    u = sub.add_parser("unload", help="Flush anchor rules/tables (root)")
    u.add_argument("--i-confirm-unload", action="store_true")
    u.set_defaults(func=cmd_unload)

    h = sub.add_parser("hook", help="Root hook lifecycle (see claude_protect_root_hook)")
    h.add_argument(
        "hook_argv",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded: stage|apply|restore|status …",
    )
    h.set_defaults(func=cmd_hook)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.cmd == "hook" and args.hook_argv and args.hook_argv[0] == "--":
        args.hook_argv = args.hook_argv[1:]
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
