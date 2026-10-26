#!/usr/bin/env python3
"""One-shot length-prefixed JSON talker for Claude Router control.sock (status/stop)."""
from __future__ import annotations

import json
import socket
import struct
import sys
import time

SOCK = "/Library/Application Support/Claude Router/run/control.sock"


def exchange(obj: dict, timeout: float = 90.0) -> dict:
    body = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode()
    frame = struct.pack(">I", len(body)) + body
    deadline = time.monotonic() + timeout
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(max(0.1, deadline - time.monotonic()))
        s.connect(SOCK)
        s.sendall(frame)
        s.shutdown(socket.SHUT_WR)
        header = b""
        while len(header) < 4:
            chunk = s.recv(4 - len(header))
            if not chunk:
                raise RuntimeError("eof_header")
            header += chunk
        (length,) = struct.unpack(">I", header)
        if not (0 < length <= 65536):
            raise RuntimeError(f"bad_length:{length}")
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                raise RuntimeError("eof_body")
            data += chunk
        # peer must half-close; drain until EOF
        while s.recv(1):
            raise RuntimeError("trailing_bytes")
    return json.loads(data.decode())


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(
            "usage: router_control_once.py status|stop <uuid>|preview-env <uuid> <review-uuid>|confirm-env <uuid> <review-uuid> <digest>",
            file=sys.stderr,
        )
        return 2
    cmd = argv[1]
    if cmd == "status":
        # Omit id — helper rejects JSON null / empty string for optional UUID.
        payload = {"version": 1, "action": "status"}
    elif cmd == "stop":
        if len(argv) < 3:
            print("stop requires instance uuid", file=sys.stderr)
            return 2
        payload = {"version": 1, "action": "stop", "id": argv[2]}
    elif cmd == "preview-env":
        if len(argv) < 4:
            print("preview-env requires instance uuid and review uuid", file=sys.stderr)
            return 2
        payload = {
            "version": 1,
            "action": "previewEnvironment",
            "id": argv[2],
            "review": argv[3],
        }
    elif cmd == "confirm-env":
        if len(argv) < 5:
            print("confirm-env requires instance, review, digest", file=sys.stderr)
            return 2
        payload = {
            "version": 1,
            "action": "confirmEnvironment",
            "id": argv[2],
            "review": argv[3],
            "digest": argv[4],
        }
    else:
        print("unknown command", file=sys.stderr)
        return 2
    print(json.dumps(exchange(payload), indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
