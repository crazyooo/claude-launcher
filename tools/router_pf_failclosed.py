#!/usr/bin/env python3
"""Router fail-closed PF helper: generate / dry-run / apply / unload / hook-*.

Default is dry-run / generate / hook-stage only. Mutations require dual confirm + root.

Root hook (-E receipt) is a **separate** journaled step — see `router_pf_root_hook.py`
and subcommands `hook-stage` / `hook-apply` / `hook-restore` / `hook-status`.
`apply` still refuses when the main ruleset does not reference the anchor.

Distinct from legacy destination guards (`clguard_*` in pf_guard.py).
Anchor: claude_router_failclosed

Never claims routing_verified / accepted / protection_verified / launch_authorized.
Never auto-stops 你的代理客户端 / 小火箭.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
import router_pf_root_hook as root_hook  # noqa: E402

ANCHOR = "claude_router_failclosed"
TABLE = "claude_router_failclosed_dst"
WINDOW = "pf-arming-user-confirm-v1"
POLICY_VERSION = 1


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


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def canonical_public_unicast(value: str) -> str | None:
    """Canonical host address, or None when not a global unicast host.

    Same stdlib basis as pf_policy.validate: rejects RFC1918, CGNAT 100.64/10,
    benchmark/fake-ip 198.18/15 (Mihomo fake-ip range), documentation, ULA,
    link-local, unspecified and multicast (ipaddress reports ff0e:: as global).
    """
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if not ip.is_global or ip.is_multicast:
        return None
    return str(ip)


def normalize_addrs(values: list[str], transport_exclusions: set[str] = frozenset()) -> list[str]:
    out, seen = [], set()
    for raw in values:
        value = raw.strip()
        if not value:
            continue
        canonical = canonical_public_unicast(value)
        if canonical is None:
            raise ValueError(f"destination_address_not_public_unicast:{value}")
        if canonical in transport_exclusions:
            # Blocking our own upstream would kill the proxy while the core is alive.
            raise ValueError(f"destination_overlaps_proxy_transport:{canonical}")
        if canonical in seen:
            continue
        seen.add(canonical)
        out.append(canonical)
    return out


def proxy_transport_ips(plan: dict) -> set[str]:
    """Literal-IP proxy hosts. Hostname hosts cannot be excluded offline."""
    ips = set()
    for proxy in plan.get("proxies") or []:
        host = proxy.get("host") if isinstance(proxy, dict) else None
        if isinstance(host, str):
            try:
                ips.add(str(ipaddress.ip_address(host)))
            except ValueError:
                pass
    return ips


def parse_canonical_conf(conf: str) -> list[str]:
    """Accept only the exact shape generate_pfconf emits; return destination addresses.

    Shape matches pf_policy / pf_guard: one `block drop out quick inet|inet6 … to ADDR`
    line per public unicast host (macOS pf rejected our multi-line table braces).

    apply runs as root, so a self-consistent artifact (sha matches) is not enough:
    a hand-edited `block drop out all` must never reach pfctl.
    """
    if "\\" in conf or "\r" in conf or "\0" in conf:
        raise ValueError("pf_conf_not_canonical")
    body = [ln for ln in conf.splitlines() if ln and not ln.startswith("#")]
    if not body:
        raise ValueError("destination_table_empty_fill_required_before_apply")
    addrs: list[str] = []
    for line in body:
        match = re.fullmatch(
            r"block drop out quick (inet6|inet) from any to ([0-9a-fA-F.:]+)",
            line,
        )
        if not match:
            raise ValueError("pf_conf_not_canonical")
        family, value = match.group(1), match.group(2)
        canonical = canonical_public_unicast(value)
        if canonical is None or canonical != value:
            raise ValueError("pf_conf_not_canonical")
        if family == "inet6" and ":" not in value:
            raise ValueError("pf_conf_not_canonical")
        if family == "inet" and ":" in value:
            raise ValueError("pf_conf_not_canonical")
        addrs.append(value)
    if not addrs:
        raise ValueError("destination_table_empty_fill_required_before_apply")
    if addrs != sorted(addrs) or len(addrs) != len(set(addrs)):
        raise ValueError("pf_conf_not_canonical")
    return addrs


def subjects_from_plan(plan: dict) -> list[dict]:
    """Mirror RouterCoreExitFailClosed.recipe subject extraction (best-effort JSON)."""
    subjects = []
    for rule in plan.get("rules") or []:
        dest = (rule.get("destination") or {}).get("kind") or rule.get("destinationKind")
        if dest == "direct":
            continue
        if dest not in ("block", "proxy"):
            continue
        selector = rule.get("selector") or {}
        domain = selector.get("domain") or rule.get("domain")
        path = selector.get("processPath") or rule.get("processPath")
        rid = rule.get("id")
        if isinstance(domain, dict):
            kind = "domainExact" if domain.get("kind") == "exact" else "domainSuffix"
            subjects.append({"kind": kind, "value": domain.get("value", ""), "ruleID": rid})
        if isinstance(path, str) and path:
            subjects.append({"kind": "processPath", "value": path, "ruleID": rid})
        if domain is None and path is None:
            subjects.append({"kind": "defaultBlock", "value": f"rule:{rid}", "ruleID": rid})
    default = plan.get("defaultDestination") or {}
    dkind = default.get("kind") if isinstance(default, dict) else default
    if dkind in ("block", "proxy"):
        subjects.append({"kind": "defaultBlock", "value": "plan.defaultDestination", "ruleID": None})
    return subjects


def generate_pfconf(subjects: list[dict], plan_digest: str | None, addrs: list[str]) -> dict:
    blockers = []
    notes = [
        "Independent system-layer arming is not performed by generation alone.",
        "Internal Mihomo REJECT rules are insufficient proof.",
        f"anchor={ANCHOR}; distinct from legacy clguard_*.",
    ]
    has_domain = any(s["kind"] in ("domainExact", "domainSuffix") for s in subjects)
    has_process = any(s["kind"] == "processPath" for s in subjects)
    has_default = any(s["kind"] == "defaultBlock" for s in subjects)
    if not subjects:
        blockers.append("no_protected_subjects_fail_closed_not_applicable")
        body = "# fail-closed not applicable: no protected subjects\n"
        return {
            "applicable": False,
            "pf_conf": body,
            "source_sha256": sha256_text(body),
            "blockers": blockers,
            "notes": notes,
            "subject_count": 0,
        }
    if has_process:
        # Partial coverage is not fail-closed, and a domain+processPath rule would be
        # widened to every process by a destination-only pf block.
        blockers.append("process_path_subjects_unsupported_on_macos_pf")
    if has_default:
        blockers.append("default_block_subject_requires_explicit_destination_scope")
    if has_domain and not addrs:
        blockers.append("destination_table_empty_fill_required_before_apply")

    applicable = has_domain and not has_process and not has_default
    # Never emit loadable block rules when not applicable — reviewers must not
    # mistake a draft for an apply-ready ruleset.
    if not applicable:
        lines = [
            f"# {ANCHOR} — NOT applicable; no loadable rules emitted",
            f"# policyVersion={POLICY_VERSION}",
            f"# subjects={len(subjects)} planDigest={plan_digest or 'nil'}",
            f"# blockers={','.join(sorted(set(blockers)))}",
        ]
        body = "\n".join(lines) + "\n"
        return {
            "applicable": False,
            "pf_conf": body,
            "source_sha256": sha256_text(body),
            "blockers": sorted(set(blockers)),
            "notes": notes,
            "subject_count": len(subjects),
        }

    lines = [
        f"# {ANCHOR} — generated; do not hand-edit for apply",
        f"# policyVersion={POLICY_VERSION}",
        f"# subjects={len(subjects)} planDigest={plan_digest or 'nil'}",
        f"# table_name={TABLE} (logical; macOS emit is per-host block lines like pf_policy)",
    ]
    if not addrs:
        lines.append("# empty — fill with --address before apply")
    else:
        for addr in sorted(addrs):
            family = "inet6" if ":" in addr else "inet"
            lines.append(f"block drop out quick {family} from any to {addr}")
    body = "\n".join(lines) + "\n"
    return {
        "applicable": True,
        "pf_conf": body,
        "source_sha256": sha256_text(body),
        "blockers": sorted(set(blockers)),
        "notes": notes,
        "subject_count": len(subjects),
    }


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
    except (OSError, subprocess.TimeoutExpired):
        raise RuntimeError("pfctl_unavailable_or_timeout") from None
    if result.returncode:
        raise RuntimeError("pfctl_rejected")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError("pfctl_output_too_large")
    return result.stdout


def cmd_generate(args: argparse.Namespace) -> int:
    if args.plan_digest is not None and not re.fullmatch(r"[0-9a-f]{64}", args.plan_digest):
        return die("plan_digest_required_64_hex")
    plan_text = Path(args.plan).read_text() if args.plan else None
    plan = json.loads(plan_text) if plan_text else {"rules": [], "defaultDestination": {"kind": "direct"}}
    try:
        addrs = normalize_addrs(args.address or [], proxy_transport_ips(plan))
    except ValueError as exc:
        return die(str(exc))
    subjects = subjects_from_plan(plan)
    artifact = generate_pfconf(subjects, args.plan_digest, addrs)
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    conf_path = out_dir / "failclosed.pf.conf"
    meta_path = out_dir / "failclosed.artifact.json"
    conf_path.write_text(artifact["pf_conf"])
    meta = {
        "version": 1,
        "policy_version": POLICY_VERSION,
        "anchor": ANCHOR,
        "table": TABLE,
        "window_id": WINDOW,
        "plan_digest": args.plan_digest,
        # Operator-supplied digest is NOT recomputed here (Swift-only canonical form);
        # record the exact plan bytes so reviewers can bind digest ↔ file.
        "plan_file_sha256": sha256_text(plan_text) if plan_text else None,
        "addresses": sorted(addrs),
        "applicable": artifact["applicable"],
        "subject_count": artifact["subject_count"],
        "source_sha256": artifact["source_sha256"],
        "blockers": artifact["blockers"],
        "notes": artifact["notes"],
        "pf_conf_path": str(conf_path),
        "routing_verified": False,
        "accepted": False,
        "armed": False,
        "pf_modified": False,
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    return ok(
        "generated",
        pf_modified=False,
        armed=False,
        applicable=artifact["applicable"],
        source_sha256=artifact["source_sha256"],
        blockers=artifact["blockers"],
        artifact=str(meta_path),
        pf_conf=str(conf_path),
    )


def cmd_dry_run(args: argparse.Namespace) -> int:
    conf = Path(args.pf_conf).read_text()
    try:
        rendered = pfctl("-n", "-v", "-o", "none", "-a", ANCHOR, "-f", "-", source=conf)
    except RuntimeError as exc:
        return die(str(exc), pf_modified=False)
    return ok(
        "dry_run_ok",
        pf_modified=False,
        armed=False,
        anchor=ANCHOR,
        source_sha256=sha256_text(conf),
        rendered_line_count=len([ln for ln in rendered.splitlines() if ln.strip()]),
    )


def cmd_apply(args: argparse.Namespace) -> int:
    # Confirm flags / digest before privilege check so non-root reviewers can
    # exercise refusal paths without sudo.
    if not args.i_confirm_pf_arming_user_confirm_v1:
        return die("missing_flag_i_confirm_pf_arming_user_confirm_v1")
    if not args.i_acknowledge_network_mutation:
        return die("missing_flag_i_acknowledge_network_mutation")
    if not args.plan_digest or not re.fullmatch(r"[0-9a-f]{64}", args.plan_digest):
        return die("plan_digest_required_64_hex")
    meta = json.loads(Path(args.artifact).read_text())
    if meta.get("plan_digest") != args.plan_digest:
        return die("plan_digest_mismatch")
    if not meta.get("applicable"):
        return die("artifact_not_applicable", blockers=meta.get("blockers"))
    if "destination_table_empty_fill_required_before_apply" in (meta.get("blockers") or []):
        return die("destination_table_empty_fill_required_before_apply")
    conf_path = Path(meta.get("pf_conf_path") or args.pf_conf)
    conf = conf_path.read_text()
    if sha256_text(conf) != meta.get("source_sha256"):
        return die("pf_conf_sha256_mismatch")
    try:
        addrs = parse_canonical_conf(conf)
    except ValueError as exc:
        return die(str(exc))
    if addrs != sorted(meta.get("addresses") or []):
        return die("pf_conf_addresses_mismatch_artifact")
    if os.geteuid() != 0:
        return die("root_required_for_apply", artifact_validated=True)
    # An anchor nobody references, or a disabled pf, filters nothing. Installing the
    # root hook / acquiring a -E token needs pf_guard-style journaling: refuse here.
    try:
        if not pf_enabled():
            return die("pf_disabled_enable_token_journal_required")
        if not anchor_hooked():
            return die("root_ruleset_does_not_reference_anchor")
        pfctl("-n", "-v", "-o", "none", "-a", ANCHOR, "-f", "-", source=conf)
    except RuntimeError as exc:
        return die(str(exc), pf_modified=False)
    try:
        pfctl("-a", ANCHOR, "-o", "none", "-f", "-", source=conf)
        for addr in addrs:
            # Pre-existing states bypass new block rules; drop them like pf_guard does.
            pfctl("-k", "::/0" if ":" in addr else "0.0.0.0/0", "-k", addr)
        effective = pf_enabled() and anchor_hooked() and bool(pfctl("-a", ANCHOR, "-s", "rules").strip())
    except RuntimeError as exc:
        return die(str(exc), pf_modified=True, pf_rules_loaded="unknown",
                   next_step="run status, then unload --i-confirm-unload")
    return ok(
        "applied_anchor" if effective else "anchor_loaded_not_effective",
        pf_modified=True,
        armed=effective,
        pf_rules_loaded=True,
        anchor=ANCHOR,
        plan_digest=args.plan_digest,
        source_sha256=meta["source_sha256"],
        note="post_exit_reobservation_still_required; routing_verified remains false",
    )


def pf_enabled() -> bool:
    match = re.search(r"^Status: (Enabled|Disabled)\b", pfctl("-s", "info"), re.M)
    if not match:
        raise RuntimeError("pf_status_unknown")
    return match[1] == "Enabled"


def anchor_hooked() -> bool:
    pattern = rf'^anchor "{re.escape(ANCHOR)}"(?: quick)? all$'
    return re.search(pattern, pfctl("-s", "rules"), re.M) is not None


def cmd_unload(args: argparse.Namespace) -> int:
    if not args.i_confirm_unload:
        return die("missing_flag_i_confirm_unload")
    if os.geteuid() != 0:
        return die("root_required_for_unload")
    try:
        pfctl("-a", ANCHOR, "-F", "rules")
        pfctl("-a", ANCHOR, "-F", "Tables")
    except RuntimeError as exc:
        return die(str(exc), pf_modified=False)
    return ok("unloaded_anchor", pf_modified=True, armed=False, anchor=ANCHOR)


def cmd_status(args: argparse.Namespace) -> int:
    try:
        rules = pfctl("-a", ANCHOR, "-s", "rules")
        tables = pfctl("-a", ANCHOR, "-s", "Tables")
        enabled, hooked = pf_enabled(), anchor_hooked()
    except RuntimeError as exc:
        return die(str(exc))
    return ok(
        "status",
        pf_modified=False,
        armed=bool(rules.strip()) and enabled and hooked,
        pf_enabled=enabled,
        root_references_anchor=hooked,
        anchor=ANCHOR,
        rules_nonempty=bool(rules.strip()),
        tables_nonempty=bool(tables.strip()),
        rules_preview=rules.strip().splitlines()[:20],
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("generate", help="Write pf.conf + artifact JSON (no pfctl)")
    g.add_argument("--plan", help="Router plan JSON path (optional; default direct-only)")
    g.add_argument("--plan-digest", default=None)
    g.add_argument("--address", action="append", default=[], help="Public unicast IP for table (repeatable)")
    g.add_argument("--output", required=True, help="Output directory")

    d = sub.add_parser("dry-run", help="pfctl -n against generated conf (no load)")
    d.add_argument("--pf-conf", required=True)

    a = sub.add_parser("apply", help="Load anchor (root + dual confirm flags)")
    a.add_argument("--artifact", required=True)
    a.add_argument("--pf-conf", default=None)
    a.add_argument("--plan-digest", required=True)
    a.add_argument("--i-confirm-pf-arming-user-confirm-v1", action="store_true")
    a.add_argument("--i-acknowledge-network-mutation", action="store_true")

    u = sub.add_parser("unload", help="Flush rules/tables in anchor (root)")
    u.add_argument("--i-confirm-unload", action="store_true")

    sub.add_parser("status", help="Show anchor rules/tables (may need root on some hosts)")

    hs = sub.add_parser("hook-stage", help="Journal root hook plan (no PF mutation)")
    hs.add_argument("--journal-dir", default=None)

    ha = sub.add_parser("hook-apply", help="Install root hook + optional -E (dual confirm + root)")
    ha.add_argument("--journal-dir", default=None)
    ha.add_argument("--plan-sha256", required=True)
    ha.add_argument("--i-confirm-pf-arming-user-confirm-v1", action="store_true")
    ha.add_argument("--i-acknowledge-network-mutation", action="store_true")

    hr = sub.add_parser("hook-restore", help="Restore root_before + release our -E token")
    hr.add_argument("--journal-dir", default=None)
    hr.add_argument("--i-confirm-restore-hook", action="store_true")

    ht = sub.add_parser("hook-status", help="Whether root references fail-closed anchor")
    ht.add_argument("--journal-dir", default=None)

    args = parser.parse_args()
    try:
        if args.cmd == "generate":
            return cmd_generate(args)
        if args.cmd == "dry-run":
            return cmd_dry_run(args)
        if args.cmd == "apply":
            return cmd_apply(args)
        if args.cmd == "unload":
            return cmd_unload(args)
        if args.cmd == "status":
            return cmd_status(args)
        if args.cmd == "hook-stage":
            return root_hook.cmd_stage(args)
        if args.cmd == "hook-apply":
            return root_hook.cmd_apply(args)
        if args.cmd == "hook-restore":
            return root_hook.cmd_restore(args)
        if args.cmd == "hook-status":
            return root_hook.cmd_status(args)
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        return die("local_operation_failed", detail=type(exc).__name__)
    return die("invalid_command")


if __name__ == "__main__":
    sys.exit(main())
