#!/usr/bin/env python3
"""Read-only, bounded mihomo controller diagnostics for the two provider plans.

No command in this module changes a proxy, firewall, route, process or VPN.
Controller readability never constitutes permission to launch Claude.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import plistlib
import re
import socket
import threading
import time
from urllib.parse import urlsplit


API_PATHS = ("/version", "/configs", "/rules", "/proxies", "/connections")
ROOTS = ("anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com")
MAX_BYTES = 4 * 1024 * 1024


class InspectionError(Exception):
    """Raised only with static diagnostic codes, never remote or credential text."""


@dataclass(frozen=True)
class Provider:
    identifier: str
    proxy_port: int | None
    controller: str | None = None
    expected_exit: str = "203.0.113.43"


PROVIDERS = {
    "longmao": Provider("longmao", 1082),
    # A spare port is not allocated until a future core installation validates it.
    "shadowrocket-config": Provider("shadowrocket-config", None),
}


def local_endpoint(value):
    try:
        if not isinstance(value, str) or value != value.strip() or any(c in value for c in "?#\\\r\n\t"):
            raise ValueError()
        url = urlsplit(value)
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "::1"}
                or url.port is None or not 1 <= url.port <= 65535
                or url.username is not None or url.password is not None
                or url.path not in {"", "/"}):
            raise ValueError()
        return url.hostname, url.port
    except (ValueError, TypeError):
        raise InspectionError("invalid_loopback_controller") from None


def read_token(variable):
    if not variable or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", variable):
        raise InspectionError("controller_auth_reference_required")
    token = os.environ.get(variable, "")
    if not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
        raise InspectionError("controller_auth_missing_or_invalid")
    return token


def decode_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    def no_constant(_):
        raise ValueError("nonfinite number")

    return json.loads(data, object_pairs_hook=unique, parse_constant=no_constant)


class ControllerReader:
    def __init__(self, address, token, timeout=3.0, budget=12.0):
        self.host, self.port = local_endpoint(address)
        if not isinstance(token, str) or not token or len(token) > 4096 or any(ord(c) < 33 or ord(c) > 126 for c in token):
            raise InspectionError("controller_auth_missing_or_invalid")
        self._token = token
        self.timeout = timeout
        self.deadline = time.monotonic() + budget

    def get(self, path):
        if path not in API_PATHS:
            raise InspectionError("controller_path_not_allowed")
        duration = min(self.timeout, self.deadline - time.monotonic())
        if duration <= 0:
            raise InspectionError("controller_deadline_exceeded")
        started = time.monotonic()
        connection = http.client.HTTPConnection(self.host, self.port, timeout=duration)
        timer = None
        try:
            # HTTPConnection uses this literal address directly, ignoring proxy environment.
            connection.connect()
            transport = connection.sock

            def interrupt_read():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            remaining = duration - (time.monotonic() - started)
            if remaining <= 0:
                raise InspectionError("controller_deadline_exceeded")
            timer = threading.Timer(remaining, interrupt_read)
            timer.daemon = True
            timer.start()
            connection.request("GET", path, headers={
                "Accept": "application/json", "Accept-Encoding": "identity",
                "Authorization": "Bearer " + self._token, "Connection": "close",
            })
            response = connection.getresponse()
            if response.status in {401, 403}:
                raise InspectionError("controller_auth_rejected")
            if 300 <= response.status < 400:
                raise InspectionError("controller_redirect_rejected")
            if response.status != 200:
                raise InspectionError("controller_http_failure")
            if response.getheader("Content-Encoding", "identity").lower() != "identity":
                raise InspectionError("controller_encoding_unsupported")
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise InspectionError("controller_not_json")
            length = response.getheader("Content-Length")
            if length is not None and (not length.isdecimal() or int(length) > MAX_BYTES):
                raise InspectionError("controller_body_too_large")
            body = response.read(MAX_BYTES + 1)
            if len(body) > MAX_BYTES:
                raise InspectionError("controller_body_too_large")
            if time.monotonic() - started >= duration:
                raise InspectionError("controller_deadline_exceeded")
            return decode_json(body)
        except InspectionError:
            raise
        except (OSError, http.client.HTTPException, ValueError, UnicodeError, RecursionError):
            raise InspectionError("controller_read_failed") from None
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()


def obj(value):
    if not isinstance(value, dict):
        raise InspectionError("controller_schema_invalid")
    return value


def seq(value):
    if not isinstance(value, list) or len(value) > 50000:
        raise InspectionError("controller_schema_invalid")
    return value


def string(value):
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise InspectionError("controller_schema_invalid")
    return value


def opaque(value):
    return hashlib.sha256(string(value).encode()).hexdigest()


def controlled_root(host):
    if not isinstance(host, str) or len(host) > 253:
        return None
    host = host.lower().rstrip(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
           for part in host.split(".")):
        return None
    return next((root for root in ROOTS if host == root or host.endswith("." + root)), None)


def evidence(documents):
    string(obj(documents["/version"]).get("version"))
    config = obj(documents["/configs"])
    if config.get("mode") not in {"rule", "global", "direct"}:
        raise InspectionError("controller_schema_invalid")
    rules = []
    for index, value in enumerate(seq(obj(documents["/rules"]).get("rules"))):
        rule = obj(value)
        kind, policy = string(rule.get("type")), string(rule.get("proxy"))
        root = controlled_root(rule.get("payload"))
        if root is not None and kind in {"Domain", "DomainSuffix"}:
            rules.append({"index": index, "type": kind, "domain_root": root,
                          "policy_id": opaque(policy), "mei_label": policy.lower() == "mei"})
    topology = []
    for name, value in obj(obj(documents["/proxies"]).get("proxies")).items():
        proxy = obj(value)
        kind = string(proxy.get("type"))
        members = [opaque(member) for member in seq(proxy.get("all", []))]
        selected, dialer = proxy.get("now"), proxy.get("dialer-proxy")
        topology.append({"id": opaque(name), "type_id": opaque(kind),
                         "mei_label": name.lower() == "mei",
                         "member_ids": members,
                         "selected_id": opaque(selected) if selected else None,
                         "dialer_id": opaque(dialer) if dialer else None})
    connections = []
    for value in seq(obj(documents["/connections"]).get("connections")):
        item = obj(value)
        root = controlled_root(obj(item.get("metadata")).get("host"))
        if root is None:
            continue
        chain = [string(member) for member in seq(item.get("chains"))]
        connections.append({"id": opaque(item.get("id")), "domain_root": root,
                            "chain_ids": [opaque(member) for member in chain],
                            "mei_label_in_chain": any(member.lower() == "mei" for member in chain),
                            "direct_label_in_chain": "DIRECT" in chain})
    return {"mode": config["mode"], "hostname_rule_candidates": rules,
            "proxy_topology": topology, "controlled_connections": connections,
            "chain_identity_verified": False,
            "collection_is_atomic": False}


def inspect(provider, token_variable=None, client_factory=ControllerReader):
    report = {"provider": provider.identifier, "expected_exit": provider.expected_exit,
              "observed_exit": None, "observability_ready": False,
              "provider_binding_verified": False, "protection_verified": False,
              "checked_at": datetime.now(timezone.utc).isoformat()}
    if not provider.controller:
        report["reason"] = "controller_unconfigured"
        return report
    try:
        local_endpoint(provider.controller)
        client = client_factory(provider.controller, read_token(token_variable))
        documents = {path: client.get(path) for path in API_PATHS}
        report["evidence"] = evidence(documents)
        report["observability_ready"] = True
        report["reason"] = "all_read_endpoints_available"
    except InspectionError as error:
        report["reason"] = str(error)
    return report


def discover_longmao(path=None):
    """Read saved non-secret settings only; do not attach to the private IPC socket."""
    path = path or Path.home() / "Library/Preferences/com.lmclient.app.plist"
    report = {"source": "saved_preferences", "runtime_verified": False}
    provider = PROVIDERS["longmao"]
    try:
        if path.stat().st_size > MAX_BYTES:
            raise ValueError()
        preferences = plistlib.loads(path.read_bytes())
        config = obj(decode_json(preferences["flutter.config"]))
        patch = obj(config["patchClashConfig"])
        port = patch.get("mixed-port")
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError()
        address = patch.get("external-controller", "")
        if not isinstance(address, str):
            raise ValueError()
        controller = "http://" + address if address else None
        if controller:
            local_endpoint(controller)
        mode = patch.get("mode")
        report.update({"mixed_port": port, "mode": mode if mode in {"rule", "global", "direct"} else "unknown",
                       "controller_configured": bool(controller),
                       "tun_configured": obj(patch.get("tun", {})).get("enable") is True})
        provider = replace(provider, proxy_port=port, controller=controller)
    except (OSError, KeyError, ValueError, TypeError, plistlib.InvalidFileException, InspectionError):
        report["reason"] = "saved_preferences_unreadable_or_unsupported"
    return provider, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=[*PROVIDERS, "all"], default="all")
    parser.add_argument("--controller", help="Explicit loopback HTTP controller; never activates it")
    parser.add_argument("--token-env", help="Environment variable holding the existing API secret")
    args = parser.parse_args()
    if args.controller and args.provider == "all":
        parser.error("--controller requires a single --provider")
    results = []
    for name in PROVIDERS if args.provider == "all" else [args.provider]:
        provider, saved = discover_longmao() if name == "longmao" else (PROVIDERS[name], None)
        if args.controller:
            provider = replace(provider, controller=args.controller)
        result = inspect(provider, args.token_env)
        if saved is not None:
            result["saved_settings"] = saved
        results.append(result)
    print(json.dumps({"default_provider": "longmao", "operation": "read_only_inspection",
                      "launch_authorized": False, "profiles": results}, ensure_ascii=False, indent=2))
    return 0 if all(result["observability_ready"] for result in results) else 78


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, TypeError, KeyError, OSError, RecursionError):
        print(json.dumps({"reason": "inspection_failed", "protection_verified": False}))
        raise SystemExit(78)
