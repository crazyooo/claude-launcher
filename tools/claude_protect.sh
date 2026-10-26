#!/bin/bash
# Status is passwordless; mutations use ordinary system sudo authorization.
set -euo pipefail
ENTRY=/Library/PrivilegedHelperTools/local.crazymax.claude-protect/claude-protect
cmd="${1:-}"
shift || true
case "$cmd" in
  pf|l3)
    if [[ "$#" -eq 1 && "$1" == status ]]; then exec /usr/bin/sudo -n "$ENTRY" status; fi
    echo "PF changes require administrator authorization." >&2
    exec /usr/bin/sudo "$ENTRY" "$@"
    ;;
  hook)
    if [[ "$#" -eq 1 && "$1" == status ]]; then exec /usr/bin/sudo "$ENTRY" hook-status; fi
    echo "Hook lifecycle commands require a separately reviewed administrator operation." >&2
    exit 78
    ;;
  daemon|l4-daemon)
    echo "Use tools/l4/install_guard_daemon.py with explicit administrator authorization; legacy entry retired." >&2
    exit 78
    ;;
  status)
    /usr/bin/sudo -n "$ENTRY" status
    /usr/bin/python3 -I -S -B "$(dirname "$0")/claude_protect_guard.py" status
    ;;
  *)
    echo "usage: $0 {pf|hook|status} [args...]" >&2
    exit 2
    ;;
esac
