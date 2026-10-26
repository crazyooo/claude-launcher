#!/usr/bin/env python3
"""Journaled root hook for Claude protect L3 (`claude_protect_anthropic`).

Reuses `router_pf_root_hook` mechanics with a distinct anchor / journal / window
so it never collides with `claude_router_failclosed`.
"""
from __future__ import annotations

import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))

import router_pf_root_hook as hook  # noqa: E402

hook.ANCHOR = "claude_protect_anthropic"
hook.WINDOW = "claude-protect-pf-user-confirm-v1"
hook.PLAN_KIND = "claude_protect_root_hook"
hook.DEFAULT_JOURNAL = Path("/private/var/run/claude-launcher-claude-protect")
hook.JOURNAL_ENV = "CLAUDE_PROTECT_PF_JOURNAL"


def main(argv: list[str] | None = None) -> int:
    return hook.main(argv)


if __name__ == "__main__":
    sys.exit(main())
