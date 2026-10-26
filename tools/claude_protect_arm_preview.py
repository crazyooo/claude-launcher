#!/usr/bin/env python3
"""Preview-only L3 arming checklist. Never mutates PF.

Writes a JSON plan with exact commands for the operator to run under sudo.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

import claude_protect_pf as pf  # noqa: E402

OUT = Path("/tmp/claude-protect-arm-preview")


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    conf_path = OUT / "protect.pf"
    ifaces = pf.physical_interfaces()
    conf = pf.generate_pfconf(ifaces)
    meta = pf.parse_canonical_conf(conf)
    conf_path.write_text(conf, encoding="utf-8")
    # dry-run syntax (non-mutating pfctl -n); capture without double JSON on stdout
    import io
    from contextlib import redirect_stdout

    buf = io.StringIO()
    with redirect_stdout(buf):
        dry = pf.main(["dry-run", "--conf", str(conf_path)])
    plan = {
        "version": 1,
        "product": "claude_protect_arm_preview",
        "protection_verified": False,
        "routing_verified": False,
        "accepted": False,
        "interfaces": meta["interfaces"],
        "conf_sha256": meta["sha256"],
        "conf_path": str(conf_path),
        "dry_run_exit": dry,
        "steps": [
            {
                "id": 1,
                "title": "root hook stage (no mutation until apply)",
                "command": (
                    f"sudo /usr/bin/python3 -I -B {_TOOLS}/claude_protect_root_hook.py stage"
                ),
            },
            {
                "id": 2,
                "title": "review journal plan_sha256 then hook-apply",
                "command": (
                    "sudo /usr/bin/python3 -I -B "
                    f"{_TOOLS}/claude_protect_root_hook.py apply "
                    "--plan-sha256 <FROM_STAGE> "
                    "--i-confirm-pf-arming-user-confirm-v1 "
                    "--i-acknowledge-network-mutation"
                ),
                "note": "WINDOW for root hook module is still pf-arming-user-confirm-v1 flag names from shared hook; protect sets WINDOW constant — use flags printed by the hook CLI.",
            },
            {
                "id": 3,
                "title": "load Anthropic physical-NIC rules",
                "command": (
                    f"sudo /usr/bin/python3 -I -B {_TOOLS}/claude_protect_pf.py apply "
                    f"--conf {conf_path} --conf-sha256 {meta['sha256']} "
                    "--i-confirm-apply "
                    f"--i-confirm-window {pf.WINDOW} "
                    "--i-acknowledge-network-mutation"
                ),
            },
            {
                "id": 4,
                "title": "verify (expect Anthropic direct timeout; apple/baidu OK)",
                "command": (
                    "curl -4 -sS --noproxy '*' --max-time 6 -o /dev/null -w '%{http_code} %{exitcode}\\n' "
                    "https://160.79.104.10/ ; "
                    "curl -4 -sS --max-time 6 -o /dev/null -w '%{http_code}\\n' https://www.apple.com/"
                ),
            },
        ],
        "unload": (
            f"sudo /usr/bin/python3 -I -B {_TOOLS}/claude_protect_pf.py unload --i-confirm-unload"
        ),
    }
    out = OUT / "arm-preview.json"
    out.write_text(json.dumps(plan, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "preview_written", "path": str(out), **{k: plan[k] for k in ("conf_sha256", "interfaces", "dry_run_exit", "protection_verified")}}, indent=2, sort_keys=True))
    return 0 if dry == 0 else dry


if __name__ == "__main__":
    sys.exit(main())
