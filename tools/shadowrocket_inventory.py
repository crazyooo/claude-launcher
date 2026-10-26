#!/usr/bin/env python3
"""Inspect the saved MEI chain passively; never print or generate credentials."""

import argparse
import ipaddress
import json
from pathlib import Path
import plistlib
from xml.parsers.expat import ExpatError


MAX_BYTES = 8 * 1024 * 1024
MAX_OBJECTS = 25000
MAX_VISITS = 100000
MAX_DEPTH = 64


class InventoryError(Exception):
    pass


class ArchiveReader:
    """Decode plist values, without instantiating any archived Objective-C class."""
    def __init__(self, raw):
        if len(raw) > MAX_BYTES:
            raise InventoryError("archive_too_large")
        try:
            archive = plistlib.loads(raw)
            if not isinstance(archive, dict) or archive.get("$archiver") != "NSKeyedArchiver":
                raise ValueError()
            self.objects = archive["$objects"]
            self.start = archive["$top"]["root"]
            if not isinstance(self.objects, list) or not 1 <= len(self.objects) <= MAX_OBJECTS:
                raise ValueError()
        except (ValueError, TypeError, KeyError, plistlib.InvalidFileException, RecursionError, OverflowError, ExpatError):
            raise InventoryError("archive_invalid") from None
        self.active = set()
        self.memo = {}
        self.visits = 0

    def read(self, value, depth=0):
        self.visits += 1
        if depth > MAX_DEPTH or self.visits > MAX_VISITS:
            raise InventoryError("archive_expansion_limit")
        if isinstance(value, plistlib.UID):
            index = value.data
            if not 0 <= index < len(self.objects):
                raise InventoryError("archive_bad_reference")
            if index in self.active:
                raise InventoryError("archive_cycle")
            if index in self.memo:
                return self.memo[index]
            if index == 0 and self.objects[0] == "$null":
                return None
            self.active.add(index)
            try:
                result = self.read(self.objects[index], depth + 1)
                self.memo[index] = result
                return result
            finally:
                self.active.remove(index)
        if value is None or type(value) in {bool, int, float}:
            return value
        if isinstance(value, (str, bytes)):
            if len(value) > 65536:
                raise InventoryError("archive_scalar_limit")
            return value
        if isinstance(value, list):
            return [self.read(item, depth + 1) for item in value]
        if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
            raise InventoryError("archive_unsupported_value")
        fields = set(value) - {"$class"}
        if fields == {"NS.string"}:
            result = self.read(value["NS.string"], depth + 1)
            if not isinstance(result, str):
                raise InventoryError("archive_invalid_string")
            return result
        if fields == {"NS.objects"}:
            result = self.read(value["NS.objects"], depth + 1)
            if not isinstance(result, list):
                raise InventoryError("archive_invalid_array")
            return result
        if "NS.keys" in fields:
            if fields != {"NS.keys", "NS.objects"}:
                raise InventoryError("archive_invalid_dictionary")
            keys = self.read(value["NS.keys"], depth + 1)
            values = self.read(value["NS.objects"], depth + 1)
            if (not isinstance(keys, list) or not isinstance(values, list) or len(keys) != len(values)
                    or any(not isinstance(key, str) for key in keys) or len(set(keys)) != len(keys)):
                raise InventoryError("archive_invalid_dictionary")
            return dict(zip(keys, values))
        return {key: self.read(item, depth + 1) for key, item in value.items() if key != "$class"}

    def nodes(self):
        root = self.read(self.start)
        pending, seen, nodes = [root], set(), []
        while pending:
            value = pending.pop()
            if not isinstance(value, (dict, list)) or id(value) in seen:
                continue
            seen.add(id(value))
            if isinstance(value, dict):
                if "host" in value and "type" in value:
                    nodes.append(value)
                pending.extend(value.values())
            else:
                pending.extend(value)
        return nodes


def present(node, field):
    return node.get(field) not in (None, "", [], {})


def enum(value, choices):
    return value.strip().lower() if isinstance(value, str) and value.strip().lower() in choices else "unknown"


def switch(value):
    return bool(value) if type(value) in {int, bool} and value in (0, 1) else None


def node_metadata(node, expected):
    try:
        host_matches = ipaddress.ip_address(node.get("host")) == expected
    except (ValueError, TypeError):
        host_matches = False
    try:
        port = node.get("port")
        port_valid = type(port) in {str, int} and str(port).isdecimal() and 1 <= int(port) <= 65535
    except (ValueError, TypeError):
        port_valid = False
    return {"protocol": enum(node.get("type"), {"socks5", "vless"}),
            "endpoint_matches_expected_ip": host_matches, "port_valid": port_valid,
            "tls_enabled": switch(node.get("tls")),
            "insecure_tls_enabled": switch(node.get("allowInsecure")),
            "transport": enum(node.get("obfs"), {"websocket", "none"}),
            "login_present": present(node, "user"), "credential_present": present(node, "password"),
            "tls_name_present": present(node, "peer"),
            "transport_parameter_present": present(node, "obfsParam")}


def inventory(raw, expected_ip="203.0.113.43"):
    result = {"operation": "passive_inventory", "chain_resolved": False,
              "conversion_ready": False, "network_verified": False,
              "protection_verified": False, "blockers": []}
    try:
        expected = ipaddress.ip_address(expected_ip)
        nodes = ArchiveReader(raw).nodes()
        matches = [node for node in nodes if isinstance(node.get("title"), str)
                   and node["title"].strip().lower() == "mei"]
        if len(matches) != 1:
            raise InventoryError("mei_not_found" if not matches else "mei_ambiguous")
        exit_node = matches[0]
        result["exit_node"] = node_metadata(exit_node, expected)
        reference = exit_node.get("chain")
        if not isinstance(reference, str) or not reference:
            raise InventoryError("upstream_reference_missing")
        matches = [node for node in nodes if node.get("uuid") == reference]
        if len(matches) != 1:
            raise InventoryError("upstream_not_found" if not matches else "upstream_ambiguous")
        upstream = matches[0]
        if upstream is exit_node:
            raise InventoryError("chain_self_reference")
        result["chain_resolved"] = True
        result["upstream_node"] = node_metadata(upstream, expected)
        checks = {
            "unexpected_exit_endpoint": result["exit_node"]["endpoint_matches_expected_ip"],
            "unsupported_exit_protocol": result["exit_node"]["protocol"] == "socks5",
            "invalid_exit_port": result["exit_node"]["port_valid"],
            "invalid_upstream_port": result["upstream_node"]["port_valid"],
            "upstream_credentials_missing": result["upstream_node"]["credential_present"],
            "unsupported_upstream_protocol": result["upstream_node"]["protocol"] == "vless",
            "upstream_tls_not_verified": result["upstream_node"]["tls_enabled"] is True,
            "upstream_certificate_validation_unconfirmed": result["upstream_node"]["insecure_tls_enabled"] is False,
            "unsupported_upstream_transport": result["upstream_node"]["transport"] == "websocket",
            "additional_chain_unreviewed": not present(upstream, "chain"),
        }
        result["blockers"].extend(code for code, valid in checks.items() if not valid)
        options = upstream.get("pluginParam")
        path = options.get("path") if isinstance(options, dict) else None
        explicit_path = isinstance(path, str) and path.startswith("/") and not any(ord(c) < 32 for c in path)
        result["upstream_node"]["explicit_websocket_path_present"] = explicit_path
        if not explicit_path:
            result["blockers"].append("websocket_path_not_explicit")
        result["blockers"].append("transport_mapping_not_implemented_or_verified")
    except InventoryError as error:
        result["blockers"].append(str(error))
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
        result["blockers"].append("archive_or_expected_ip_invalid")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="?", type=Path,
                        default=Path.home() / "Library/Group Containers/group.com.liguangming.Shadowrocket/ServerManager")
    args = parser.parse_args()
    try:
        with args.archive.open("rb") as stream:
            report = inventory(stream.read(MAX_BYTES + 1))
    except OSError:
        report = {"operation": "passive_inventory", "protection_verified": False,
                  "conversion_ready": False, "blockers": ["archive_unreadable"]}
    print(json.dumps(report, ensure_ascii=False, indent=2))
    # Success means that the inventory was read, never that conversion or launch is permitted.
    return 0 if report.get("chain_resolved") else 78


if __name__ == "__main__":
    raise SystemExit(main())
