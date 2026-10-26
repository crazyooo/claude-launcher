#!/usr/bin/env python3
"""Inspect Shadowrocket text offline. This command never installs or enables rules."""

import argparse
from dataclasses import dataclass
import hashlib
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit


CORE_SUFFIXES = ("anthropic.com", "claude.ai", "claude.com", "claudeusercontent.com")
TARGETS = (
    "claude.ai", "api.anthropic.com", "platform.claude.com",
    "console.anthropic.com", "files.claudeusercontent.com",
    "api.statsig.com", "events.statsigapi.net", "auth0.com", "sentry.io",
    "api.ipify.org", "ifconfig.me", "whoer.net", "browserleaks.com",
)
DOMAIN_KINDS = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD"}
KNOWN_KINDS = DOMAIN_KINDS | {
    "FINAL", "IP-CIDR", "IP-CIDR6", "IP-ASN", "GEOIP", "RULE-SET",
    "USER-AGENT", "PROCESS-NAME", "PROCESS-PATH", "MALFORMED",
}
PUBLIC_POLICIES = {"MEI", "DIRECT", "PROXY", "REJECT", "REJECT-DROP"}


def hostname(text):
    """Normalize DNS names; never treat a URL or an IP address as a hostname."""
    try:
        name = text.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return None
    if not name or len(name) > 253:
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
           for p in name.split(".")):
        return None
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return name
    return None


def under(name, root):
    return name == root or name.endswith("." + root)


@dataclass(frozen=True)
class Rule:
    line: int
    kind: str
    operand: str
    policy: str
    supported_shape: bool = True

    def reference(self):
        # Policies can contain private node names. Only public, task-known labels escape.
        return {
            "line": self.line,
            "kind": self.kind if self.kind in KNOWN_KINDS else "UNSUPPORTED",
            "policy": self.policy if self.policy in PUBLIC_POLICIES else "CUSTOM_OR_UNKNOWN",
        }

    def matches_hostname(self, host):
        """None means that runtime or unsupported configuration data is necessary."""
        if not self.supported_shape or not self.policy:
            return None
        if self.kind == "FINAL":
            return True
        if self.kind == "DOMAIN-KEYWORD":
            if not re.fullmatch(r"[a-zA-Z0-9.-]+", self.operand):
                return None
            return self.operand.lower() in host
        if self.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
            return None
        name = hostname(self.operand)
        if name is None:
            return None
        return host == name if self.kind == "DOMAIN" else under(host, name)


def parse(source):
    rules, general, definitions = [], {}, set()
    section = ""
    for number, raw in enumerate(source.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower().replace(" ", "").replace("-", "")
        elif section == "general" and "=" in line:
            key, value = line.split("=", 1)
            general[key.strip().lower()] = value.strip()
        elif section in {"proxy", "proxygroup"} and "=" in line:
            definitions.add(line.split("=", 1)[0].strip())
        elif section == "rule":
            parts = [part.strip() for part in line.split(",")]
            kind = parts[0].upper()
            if kind == "FINAL":
                if len(parts) == 2:
                    rules.append(Rule(number, kind, "", parts[1]))
                else:
                    rules.append(Rule(number, "MALFORMED", "", "", False))
            elif len(parts) >= 3:
                # Domain options are deliberately unsupported, rather than silently ignored.
                shape = len(parts) == 3 if kind in DOMAIN_KINDS else True
                rules.append(Rule(number, kind, parts[1], parts[2], shape))
            else:
                rules.append(Rule(number, "MALFORMED", "", "", False))
    return rules, general, definitions


def inspect_host(rules, host):
    normalized = hostname(host)
    if normalized is None:
        raise ValueError("invalid hostname")
    preceding = []
    for rule in rules:
        matches = rule.matches_hostname(normalized)
        if matches is None:
            preceding.append(rule.reference())
        elif matches:
            return {
                "status": "indeterminate" if preceding else "determinate",
                "hostname_candidate": rule.reference(),
                "earlier_unresolved": preceding,
            }
    return {"status": "indeterminate" if preceding else "no_match",
            "hostname_candidate": None, "earlier_unresolved": preceding}


def covers(earlier, later):
    if not earlier.supported_shape or not later.supported_shape:
        return False
    if later.kind not in {"DOMAIN", "DOMAIN-SUFFIX"}:
        return False
    name = hostname(later.operand)
    if name is None or not earlier.policy:
        return False
    if earlier.kind == "DOMAIN":
        return later.kind == "DOMAIN" and earlier.matches_hostname(name) is True
    if earlier.kind in {"DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "FINAL"}:
        return earlier.matches_hostname(name) is True
    return False


def audit(source, confirmed_ip=None):
    if confirmed_ip is not None:
        confirmed_ip = str(ipaddress.ip_address(confirmed_ip))
    rules, general, definitions = parse(source)
    shadowed = []
    for index, rule in enumerate(rules):
        predecessor = next((r for r in rules[:index] if covers(r, rule)), None)
        if predecessor:
            shadowed.append({"earlier": predecessor.reference(), "unreachable": rule.reference(),
                             "different_policy": predecessor.policy != rule.policy})
    endpoints = [v.strip() for key in ("dns-server", "fallback-dns-server")
                 for v in general.get(key, "").split(",") if v.strip()]
    encrypted = sum(urlsplit(v).scheme.lower() in {"https", "tls", "quic", "h3"}
                    for v in endpoints)
    shared = []
    for rule in rules:
        name = hostname(rule.operand) if rule.kind in {"DOMAIN", "DOMAIN-SUFFIX"} else None
        if rule.policy == "MEI" and name in {"auth0.com", "sentry.io", "statsigapi.net"}:
            shared.append({"domain": name, **rule.reference()})
    ipv6 = general.get("ipv6", "").lower()
    return {
        "schema": 1, "mode": "offline", "protection_verified": False,
        "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
        "rule_count": len(rules),
        "mei": {"definition_in_file": "MEI" in definitions,
                "user_confirmed_exit": confirmed_ip, "observed_exit": None,
                "chain_verified": False, "residential_verified": False},
        "targets": {host: inspect_host(rules, host) for host in TARGETS},
        "shadowed_rules": shadowed, "shared_service_expansion": shared,
        "ipv6": {"configured": ipv6 if ipv6 in {"true", "false"} else "unknown",
                 "runtime_verified": False},
        "dns": {"endpoint_count": len(endpoints), "encrypted_endpoint_count": encrypted,
                "mixed_transport": 0 < encrypted < len(endpoints), "runtime_verified": False},
        "limits": [
            "Hostname-only first-match analysis; unresolved earlier rules prevent a winning-policy claim.",
            "No remote rule sets, IP resolution, GEOIP, User-Agent, process or runtime inspection.",
            "User-confirmed MEI exit is intent, not an observed exit or proof of residential service.",
            "No firewall, route, proxy, IPv6 or application changes are performed.",
        ],
    }


def mihomo_fragment(report):
    """Generate only the core clauses proved present; never synthesize a working setup."""
    candidates = ("api.anthropic.com", "claude.ai", "platform.claude.com", "files.claudeusercontent.com")
    lines = ["# INCOMPLETE: NOT A RUNNABLE CONFIG; NO PROTECTION VERIFIED",
             "# Claude-Residential is undefined. Its nodes, chain and failover need verification.",
             "# Hostname samples do not prove complete domain or process coverage.", "rules:"]
    # Exact samples only: never expand an exact-domain source into a whole suffix.
    for host in candidates:
        item = report["targets"][host]
        match = item["hostname_candidate"]
        if item["status"] == "determinate" and match and match["policy"] == "MEI":
            lines.append(f"  - DOMAIN,{host},Claude-Residential")
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("--confirmed-mei-ip")
    parser.add_argument("--fragment", action="store_true")
    args = parser.parse_args()
    try:
        data = args.source.read_bytes()
        if len(data) > 1024 * 1024:
            raise ValueError("oversized input")
        report = audit(data.decode("utf-8-sig"), args.confirmed_mei_ip)
        if args.fragment:
            report["mihomo_fragment"] = mihomo_fragment(report)
    except (OSError, UnicodeError, ValueError):
        print(json.dumps({"error": "source_or_confirmed_ip_invalid", "protection_verified": False}))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
