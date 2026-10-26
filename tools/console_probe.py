#!/usr/bin/env python3
"""GUI adapter: bounded stdin credentials, fixed read-only API, allowlisted output."""
import hashlib
import json
from pathlib import Path
import sys
import time

# The bundled adapter runs under python -I; import only its sibling reader.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import providers as p


def summarize(documents, token):
    def text(value, limit=120):
        if value is None:
            return ""
        if not isinstance(value, str):
            raise p.InspectionError("controller_schema_invalid")
        value = value.replace(token, "[redacted]")
        return "".join(c for c in value if c.isprintable())[:limit]

    def count(value):
        if type(value) is not int or not 0 <= value <= 2**63 - 1:
            raise p.InspectionError("controller_schema_invalid")
        return value

    version = p.string(p.obj(documents["/version"]).get("version"))
    config = p.obj(documents["/configs"])
    if config.get("mode") not in {"rule", "global", "direct"}:
        raise p.InspectionError("controller_schema_invalid")
    tun = p.obj(config.get("tun", {})).get("enable")
    ipv6 = config.get("ipv6")
    if any(v is not None and type(v) is not bool for v in (tun, ipv6)):
        raise p.InspectionError("controller_schema_invalid")
    rules = p.seq(p.obj(documents["/rules"]).get("rules"))
    proxies = p.obj(p.obj(documents["/proxies"]).get("proxies"))
    connections = p.obj(documents["/connections"])
    rows = p.seq(connections.get("connections"))
    result = []
    for raw in rows[:40]:
        row = p.obj(raw)
        metadata = p.obj(row.get("metadata"))
        identifier = p.string(row.get("id"))
        chain = p.seq(row.get("chains", []))
        # Paths and rule payloads may expose usernames or private filesystem data.
        process = metadata.get("process") or ""
        result.append({
            "id": hashlib.sha256(identifier.encode()).hexdigest(),
            "process": text(process.rsplit("/", 1)[-1] if isinstance(process, str) else process, 60),
            "host": text(metadata.get("host") or metadata.get("destinationIP"), 120),
            "port": text(str(metadata.get("destinationPort", "")), 8),
            "network": text(metadata.get("network"), 12),
            "chains": [text(v, 48) for v in chain[:8]],
            "rule": text(row.get("rule"), 48),
            "upload": count(row.get("upload", 0)), "download": count(row.get("download", 0)),
        })
    return {"version": text(version, 60), "mode": config["mode"], "tun": tun, "ipv6": ipv6,
            "ruleCount": len(rules), "proxyCount": len(proxies), "totalConnections": len(rows),
            "upload": count(connections.get("uploadTotal", 0)),
            "download": count(connections.get("downloadTotal", 0)), "connections": result}


def collect(endpoint, token):
    started = time.time()
    reader = p.ControllerReader(endpoint, token)
    documents = {path: reader.get(path) for path in p.API_PATHS}
    result = summarize(documents, token)
    result.update(endpoint=endpoint, startedAt=started, completedAt=time.time())
    return result


def main():
    try:
        raw = sys.stdin.buffer.read(16385)
        if len(raw) > 16384:
            raise p.InspectionError("controller_input_too_large")
        config = p.obj(p.decode_json(raw))
        result = collect(config.get("endpoint"), config.get("token"))
        output = json.dumps(result, ensure_ascii=False)
        if len(output.encode()) > 120000:
            raise p.InspectionError("controller_output_too_large")
        print(output)
    except p.InspectionError as error:
        print(json.dumps({"error": str(error)}))
        return 1
    except Exception:
        print('{"error":"controller_read_failed"}')
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
