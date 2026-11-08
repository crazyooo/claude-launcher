#!/usr/bin/env python3
"""Claude Desktop account switcher (v1): A–D whole-directory snapshots.

Product boundary:
- Desktop only. Does not touch Claude Code CLI config.
- Whole-directory swap of ~/Library/Application Support/Claude.
- Default does not launch Claude; --open is explicit.
- Refuses to switch while Desktop is still running (no default force-kill).
- Never claims protection_verified / routing_verified.

Storage:
  ~/.claude-launcher/accounts/{A,B,C,D}/
  ~/.claude-launcher/current
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

PRODUCT = "claude_account_switch"
SLOTS = ("A", "B", "C", "D")
SLOT_HELP = "A、B、C 或 D"
DESKTOP_PATTERN = "/Applications/Claude.app/Contents/MacOS/Claude"
QUIT_WAIT_SECONDS = 15
USAGE_API = "https://api.anthropic.com/api/oauth/usage"
PROFILE_API = "https://api.anthropic.com/api/oauth/profile"
ORG_USAGE_API = "https://api.anthropic.com/api/organizations/{org}/usage"
DESKTOP_CLIENT_ID = "89355bc3-cbfd-4382-905b-976645cad410"
TOKEN_API = "https://api.anthropic.com/v1/oauth/token"
DEFAULT_SCOPE = "user:inference"
WEB_ACCOUNT_API = "https://claude.ai/api/account"
WEB_ORG_API = "https://claude.ai/api/organizations/{org}"
WEB_USAGE_API = "https://claude.ai/api/organizations/{org}/usage"
COOKIE_NAMES_AUTH = ("sessionKey", "sessionKeyLC", "lastActiveOrg")
COOKIE_NAMES_CF = ("cf_clearance", "__cf_bm")
COOKIE_NAMES_EXTRA = ("activitySessionId", "anthropic-device-id", "routingHint")
WEB_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Claude/4.23118.0 Chrome/132.0.0.0 Safari/537.36"
)


def fail(reason: str, **extra) -> dict:
    payload = {"product": PRODUCT, "ok": False, "reason": reason}
    payload.update(extra)
    return payload


def ok(**extra) -> dict:
    payload = {"product": PRODUCT, "ok": True}
    payload.update(extra)
    return payload


def emit(payload: dict, code: int = 0) -> int:
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return code


def home_dir() -> Path:
    override = os.environ.get("CLAUDE_ACCOUNT_HOME", "").strip()
    return Path(override) if override else Path.home()


def data_dir(home: Path | None = None) -> Path:
    override = os.environ.get("CLAUDE_ACCOUNT_DATA", "").strip()
    if override:
        return Path(override)
    root = home or home_dir()
    return root / "Library" / "Application Support" / "Claude"


def base_dir(home: Path | None = None) -> Path:
    override = os.environ.get("CLAUDE_ACCOUNT_BASE", "").strip()
    if override:
        return Path(override)
    root = home or home_dir()
    return root / ".claude-launcher"


def account_dir(base: Path, slot: str) -> Path:
    return base / "accounts" / slot


def current_path(base: Path) -> Path:
    return base / "current"


def ensure_base(base: Path) -> None:
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    (base / "accounts").mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(base, 0o700)
        os.chmod(base / "accounts", 0o700)
    except OSError:
        pass


def valid_slot(value: str | None) -> str | None:
    if value in SLOTS:
        return value
    return None


def read_current(base: Path) -> str | None:
    path = current_path(base)
    if not path.is_file():
        return None
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return valid_slot(value)


def write_current(base: Path, slot: str) -> None:
    path = current_path(base)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(slot + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def dir_nonempty(path: Path) -> bool:
    if not path.exists():
        return False
    if path.is_symlink():
        return True
    try:
        next(path.iterdir())
        return True
    except (StopIteration, OSError):
        return path.is_dir()


def has_desktop_archive(path: Path) -> bool:
    """True only when the slot holds a real Desktop data snapshot (not just sidecars)."""
    if not path.is_dir():
        return False
    return (
        (path / "config.json").is_file()
        or (path / "Cookies").is_file()
        or (path / "IndexedDB").is_dir()
        or (path / "Local Storage").is_dir()
    )


def slot_meta(path: Path) -> dict:
    if not path.is_dir():
        return {"has_archive": False, "size_bytes": 0, "mtime": None}
    archived = has_desktop_archive(path)
    size = 0
    mtime = None
    try:
        for root, _dirs, files in os.walk(path):
            for name in files:
                try:
                    size += (Path(root) / name).stat().st_size
                except OSError:
                    continue
        mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
    except OSError:
        return {"has_archive": archived, "size_bytes": 0, "mtime": None}
    return {"has_archive": archived, "size_bytes": size if archived else 0, "mtime": mtime if archived else None}


def _clean_text(value: str, limit: int = 80) -> str:
    value = re.split(r"[\x00-\x1f]", value)[0].strip().strip('"').strip()
    return value[:limit]


def is_default_organization_name(value: str | None) -> bool:
    """True for Claude's auto personal org labels like \"email's Organization\"."""
    if not isinstance(value, str):
        return True
    text = value.strip().strip("'").strip('"').strip()
    if not text:
        return True
    # Personal Free/Pro accounts get "{name or email}'s Organization".
    if re.search(r"'s\s+organization\s*$", text, flags=re.IGNORECASE):
        return True
    if text.lower() in {"organization", "personal", "default"}:
        return True
    return False


def meaningful_organization(value: str | None, limit: int = 120) -> str | None:
    if not isinstance(value, str):
        return None
    text = _clean_text(value, limit).strip("'").strip()
    if not text or is_default_organization_name(text):
        return None
    return text[:limit]


def extract_identity(root: Path) -> dict:
    """Best-effort local identity from Desktop data. Never returns tokens."""
    info: dict[str, str] = {}
    cfg = root / "config.json"
    if cfg.is_file():
        try:
            data = json.loads(cfg.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            uuid = data.get("lastKnownAccountUuid")
            if isinstance(uuid, str) and uuid.strip():
                info["account_uuid"] = uuid.strip()[:64]
            boot = data.get("bootSideSessions")
            if isinstance(boot, dict):
                account = boot.get("accountUuid")
                if isinstance(account, str) and account.strip():
                    info.setdefault("account_uuid", account.strip()[:64])

    idb = root / "IndexedDB"
    if idb.is_dir():
        for path in idb.rglob("*"):
            try:
                if not path.is_file() or path.stat().st_size > 12_000_000:
                    continue
                blob = path.read_bytes()
            except OSError:
                continue
            if b"email_address" not in blob and b"display_name" not in blob and b"full_name" not in blob:
                continue
            # Chromium IDB stores length-prefixed strings; keep the gap tiny so
            # the capture cannot start mid-value.
            email = re.search(
                rb"email_address[\x00-\x20\"]{0,8}([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
                blob,
            )
            if email:
                info["email"] = email.group(1).decode("ascii", "ignore")
            for key, field in ((b"display_name", "display_name"), (b"full_name", "full_name")):
                match = re.search(key + rb"[\x00-\x20\"]{0,8}([A-Za-z][A-Za-z0-9 ._\-]{0,59})", blob)
                if match:
                    text = _clean_text(match.group(1).decode("utf-8", "ignore"), 60)
                    if text and "@" not in text:
                        info[field] = text
            # Organization display often follows organization … name …
            org = re.search(
                rb"organization.{0,80}name[\x00-\x20\"]{0,8}([A-Za-z0-9@._%+\- ']{3,80})",
                blob,
            )
            if org:
                text = meaningful_organization(org.group(1).decode("utf-8", "ignore"), 80)
                if text and text.lower() not in {"chrome", "mozilla", "safari"}:
                    info["organization"] = text
            if info.get("email"):
                break

    # Prefer a readable label.
    label = info.get("display_name") or info.get("full_name") or info.get("email")
    if label:
        info["label"] = label
    if "organization" in info and is_default_organization_name(info.get("organization")):
        info.pop("organization", None)
    return info


def identity_path(slot_dir: Path) -> Path:
    return slot_dir / "identity.json"


def read_identity_file(slot_dir: Path) -> dict:
    path = identity_path(slot_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict):
        return {}
    allowed = ("email", "display_name", "full_name", "organization", "account_uuid", "label", "subscription")
    out = {
        key: str(data[key])[:120]
        for key in allowed
        if isinstance(data.get(key), str) and data[key].strip()
    }
    org = meaningful_organization(out.get("organization"))
    if org:
        out["organization"] = org
    else:
        out.pop("organization", None)
    return out


def write_identity_file(slot_dir: Path, identity: dict) -> None:
    if not identity:
        return
    path = identity_path(slot_dir)
    cleaned = dict(identity)
    org = meaningful_organization(cleaned.get("organization") if isinstance(cleaned.get("organization"), str) else None)
    if org:
        cleaned["organization"] = org
    else:
        cleaned.pop("organization", None)
    payload = {
        "product": PRODUCT,
        "version": 1,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **{
            key: cleaned[key]
            for key in (
                "email",
                "display_name",
                "full_name",
                "organization",
                "account_uuid",
                "label",
                "subscription",
            )
            if key in cleaned
        },
    }
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def resolve_slot_identity(slot_dir: Path, live: Path | None = None, is_current: bool = False) -> dict:
    """Sidecar first; fall back to scanning archive / live Desktop data."""
    cached = read_identity_file(slot_dir)
    if cached.get("email") or cached.get("label"):
        # Refresh from live when this is the active account and live has richer data.
        if is_current and live is not None and live.is_dir():
            fresh = extract_identity(live)
            if fresh.get("email") or fresh.get("label"):
                merged = {**cached, **fresh}
                write_identity_file(slot_dir, merged)
                return merged
        return cached
    scanned = extract_identity(slot_dir)
    if (not scanned.get("email") and not scanned.get("label")) and is_current and live is not None:
        scanned = extract_identity(live)
    if scanned:
        write_identity_file(slot_dir, scanned)
    return scanned


def usage_path(slot_dir: Path) -> Path:
    return slot_dir / "usage.json"


def read_usage_file(slot_dir: Path) -> dict:
    path = usage_path(slot_dir)
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def write_usage_file(slot_dir: Path, usage: dict) -> None:
    if not usage:
        return
    path = usage_path(slot_dir)
    payload = {
        "product": PRODUCT,
        "version": 1,
        **{key: usage[key] for key in usage if key not in {"access_token", "refresh_token", "token"}},
    }
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def read_keychain_secret(runner: Callable | None = None) -> bytes | None:
    run = runner or subprocess.run
    try:
        proc = run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-w",
                "-s",
                "Claude Safe Storage",
                "-a",
                "Claude Key",
            ],
            capture_output=True,
            timeout=35,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return (proc.stdout or b"").rstrip(b"\n")


def decrypt_v10(secret: bytes, blob: bytes, runner: Callable | None = None) -> bytes | None:
    """Decrypt Chromium/Electron safeStorage v10 using OpenSSL (works under python -S)."""
    import hashlib

    if not blob.startswith(b"v10") or len(blob) <= 3:
        return None
    ct = blob[3:]
    if len(ct) % 16 != 0:
        return None
    key = hashlib.pbkdf2_hmac("sha1", secret, b"saltysalt", 1003, dklen=16)
    iv = b" " * 16
    run = runner or subprocess.run
    try:
        proc = run(
            [
                "/usr/bin/openssl",
                "enc",
                "-aes-128-cbc",
                "-d",
                "-K",
                key.hex(),
                "-iv",
                iv.hex(),
                "-nopad",
            ],
            input=ct,
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0 or not proc.stdout:
        return None
    pt = proc.stdout
    pad = pt[-1]
    if pad < 1 or pad > 16 or len(pt) < pad:
        return None
    if any(b != pad for b in pt[-pad:]):
        return None
    return pt[:-pad]


def load_oauth_credential(desktop_root: Path, runner: Callable | None = None) -> dict | None:
    """Decrypt oauth:tokenCacheV2 from a Desktop data directory. Never logs tokens."""
    import base64

    cfg_path = desktop_root / "config.json"
    if not cfg_path.is_file():
        return None
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    raw = cfg.get("oauth:tokenCacheV2") or cfg.get("oauth:tokenCache")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        blob = base64.b64decode(raw)
    except Exception:
        return None
    secret = read_keychain_secret(runner=runner)
    if not secret:
        return None
    plaintext = decrypt_v10(secret, blob, runner=runner)
    if not plaintext:
        return None
    try:
        cache = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return None
    if not isinstance(cache, dict) or not cache:
        return None
    best_key = None
    best = None
    for key, entry in cache.items():
        if not isinstance(entry, dict):
            continue
        token = entry.get("token")
        if not isinstance(token, str) or not token:
            continue
        expires = entry.get("expiresAt")
        score = int(expires) if isinstance(expires, (int, float)) else 0
        if best is None or score > int(best.get("expiresAt") or 0) or (
            score == int(best.get("expiresAt") or 0) and (best_key is None or key < best_key)
        ):
            best_key = key
            best = entry
    if not best or not best_key:
        return None
    return {
        "cache_key": best_key,
        "token": best.get("token"),
        "refresh_token": best.get("refreshToken") if isinstance(best.get("refreshToken"), str) else None,
        "expires_at": best.get("expiresAt"),
        "subscription": best.get("subscriptionType") if isinstance(best.get("subscriptionType"), str) else None,
        "rate_limit_tier": best.get("rateLimitTier") if isinstance(best.get("rateLimitTier"), str) else None,
    }


def _http_json(url: str, headers: dict, body: dict | None = None, timeout: float = 12.0) -> tuple[int, dict | None, str]:
    import urllib.error
    import urllib.request

    data = None
    req_headers = dict(headers)
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        req_headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=req_headers, method="POST" if body is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(1 << 20)
            code = getattr(resp, "status", 200)
    except urllib.error.HTTPError as exc:
        raw = exc.read(1 << 20) if hasattr(exc, "read") else b""
        code = exc.code
    except Exception as exc:
        return 0, None, str(exc)
    try:
        parsed = json.loads(raw.decode("utf-8")) if raw else None
    except ValueError:
        parsed = None
    detail = raw.decode("utf-8", "ignore")[:200]
    return code, parsed if isinstance(parsed, dict) else None, detail


def refresh_access_token(refresh_token: str, scope: str = DEFAULT_SCOPE) -> dict | None:
    code, parsed, _detail = _http_json(
        TOKEN_API,
        {"anthropic-version": "2023-06-01"},
        {
            "grant_type": "refresh_token",
            "client_id": DESKTOP_CLIENT_ID,
            "refresh_token": refresh_token,
            "scope": scope or DEFAULT_SCOPE,
        },
    )
    if code < 200 or code >= 300 or not parsed:
        return None
    access = parsed.get("access_token")
    if not isinstance(access, str) or not access:
        return None
    return {
        "token": access,
        "refresh_token": parsed.get("refresh_token") if isinstance(parsed.get("refresh_token"), str) else None,
        "expires_in": parsed.get("expires_in"),
    }


def scope_from_cache_key(key: str) -> str:
    marker = "https://"
    idx = key.find(marker)
    if idx < 0:
        idx = key.find("http://")
        marker = "http://"
    if idx < 0:
        return DEFAULT_SCOPE
    rest = key[idx + len(marker) :]
    colon = rest.find(":")
    if colon < 0 or colon == len(rest) - 1:
        return DEFAULT_SCOPE
    return rest[colon + 1 :] or DEFAULT_SCOPE


def _window_summary(value: dict | None) -> dict:
    if not isinstance(value, dict):
        return {}
    out = {}
    util = value.get("utilization")
    if isinstance(util, (int, float)):
        out["utilization"] = round(float(util), 1)
    resets = value.get("resets_at")
    if isinstance(resets, str) and resets.strip():
        out["resets_at"] = resets.strip()[:64]
    elif isinstance(resets, (int, float)):
        out["resets_at"] = str(resets)
    return out


def normalize_plan(value: str | None) -> str:
    raw = (value or "").strip().lower()
    if not raw:
        return "free"
    aliases = {
        "free": "free",
        "none": "free",
        "claude_free": "free",
        "claude_ai": "free",
        "pro": "pro",
        "claude_pro": "pro",
        "max": "max",
        "claude_max": "max",
        "ultra": "max",
        "team": "team",
        "claude_team": "team",
        "enterprise": "enterprise",
        "claude_enterprise": "enterprise",
    }
    if raw in aliases:
        return aliases[raw]
    if raw.startswith("claude_"):
        return normalize_plan(raw[len("claude_") :])
    return raw[:40]


def summarize_usage_payload(
    payload: dict,
    subscription: str | None = None,
    tier: str | None = None,
    source: str = "anthropic_oauth_usage",
) -> dict:
    five = _window_summary(payload.get("five_hour") if isinstance(payload.get("five_hour"), dict) else None)
    seven = _window_summary(payload.get("seven_day") if isinstance(payload.get("seven_day"), dict) else None)
    sub = normalize_plan(subscription)
    summary = {
        "ok": True,
        "subscription": sub,
        "rate_limit_tier": tier or "",
        "session": five,
        "week": seven,
        "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": source,
    }
    return summary


def _cookie_plaintext(secret: bytes, encrypted_value: bytes, runner: Callable | None = None) -> str | None:
    """Decrypt Chromium cookie value (v10 + 32-byte host hash prefix)."""
    if not encrypted_value:
        return None
    pt = decrypt_v10(secret, encrypted_value, runner=runner)
    if not pt:
        return None
    if len(pt) > 32:
        pt = pt[32:]
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return None


def read_desktop_cookies(
    desktop_root: Path,
    names: tuple[str, ...] | list[str],
    *,
    runner: Callable | None = None,
) -> dict[str, str]:
    """Read selected cookie values from a Desktop Cookies DB. Never logs values."""
    import sqlite3
    import tempfile

    path = desktop_root / "Cookies"
    if not path.is_file():
        return {}
    secret = read_keychain_secret(runner=runner)
    if not secret:
        return {}
    wanted = set(names)
    out: dict[str, str] = {}
    tmp_dir = Path(tempfile.mkdtemp(prefix="claude-launcher-cookies-"))
    tmp = tmp_dir / "Cookies"
    try:
        shutil.copy2(path, tmp)
        con = sqlite3.connect(str(tmp))
        try:
            rows = con.execute(
                "SELECT name, encrypted_value, value FROM cookies WHERE name IN ({})".format(
                    ",".join("?" for _ in wanted)
                ),
                tuple(wanted),
            ).fetchall()
        finally:
            con.close()
    except Exception:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return {}
    shutil.rmtree(tmp_dir, ignore_errors=True)
    for name, enc, val in rows:
        if not isinstance(name, str) or name not in wanted:
            continue
        if isinstance(val, str) and val:
            out[name] = val
            continue
        if isinstance(enc, bytes) and enc:
            plain = _cookie_plaintext(secret, enc, runner=runner)
            if plain:
                out[name] = plain
    return out


def load_session_credential(
    desktop_root: Path,
    *,
    runner: Callable | None = None,
    cf_fallback_root: Path | None = None,
) -> dict | None:
    """Build a web-session credential from Desktop Cookies (no oauth token cache needed)."""
    auth = read_desktop_cookies(desktop_root, COOKIE_NAMES_AUTH + COOKIE_NAMES_CF + COOKIE_NAMES_EXTRA, runner=runner)
    session_key = auth.get("sessionKey")
    if not isinstance(session_key, str) or not session_key.startswith("sk-ant-"):
        return None
    # Cloudflare cookies expire; borrow from live Desktop when refreshing an archive slot.
    if cf_fallback_root and cf_fallback_root.exists() and cf_fallback_root != desktop_root:
        need_cf = [name for name in COOKIE_NAMES_CF if name not in auth]
        if need_cf:
            borrowed = read_desktop_cookies(cf_fallback_root, need_cf, runner=runner)
            auth.update(borrowed)
    parts = []
    for name in COOKIE_NAMES_AUTH + COOKIE_NAMES_CF + COOKIE_NAMES_EXTRA:
        value = auth.get(name)
        if isinstance(value, str) and value:
            parts.append(f"{name}={value}")
    if not parts:
        return None
    return {
        "session_key": session_key,
        "org_uuid": auth.get("lastActiveOrg") if isinstance(auth.get("lastActiveOrg"), str) else None,
        "cookie": "; ".join(parts),
    }


def _web_headers(cookie: str) -> dict:
    return {
        "Cookie": cookie,
        "User-Agent": WEB_UA,
        "Accept": "application/json",
        "Referer": "https://claude.ai/settings/usage",
        "Origin": "https://claude.ai",
    }


def _is_cloudflare_block(code: int, detail: str) -> bool:
    if code != 403:
        return False
    low = (detail or "").lower()
    return "just a moment" in low or "cloudflare" in low or "<html" in low


def plan_from_org_payload(org: dict | None) -> tuple[str, str]:
    if not isinstance(org, dict):
        return "free", ""
    plan = (
        org.get("analytics_subscription_plan")
        or org.get("plan_display_name")
        or org.get("billing_type")
        or ""
    )
    if isinstance(plan, str) and plan.strip().lower() in {"none", ""}:
        plan = "free"
    tier = org.get("rate_limit_tier") if isinstance(org.get("rate_limit_tier"), str) else ""
    return normalize_plan(plan if isinstance(plan, str) else None), tier or ""


def fetch_usage_via_session(session: dict) -> dict:
    cookie = session.get("cookie")
    if not isinstance(cookie, str) or not cookie:
        return fail("missing_token", detail="本地没有可用的登录会话")

    headers = _web_headers(cookie)
    code, account, detail = _http_json(WEB_ACCOUNT_API, headers)
    if _is_cloudflare_block(code, detail):
        return fail(
            "cloudflare_blocked",
            detail="网站防护拦截了额度请求。请先打开一次 Claude Desktop（保持登录），再点刷新额度。",
        )
    if code < 200 or code >= 300 or not account:
        low = (detail or "").lower()
        if "account_banned" in low:
            return fail(
                "session_invalid",
                detail="该存档的登录会话已失效或被拒绝。请切换到该账号重新登录后，再点刷新额度。",
            )
        return fail(
            "usage_unavailable",
            detail=f"账号接口不可用（HTTP {code}）" + (f"：{detail}" if detail else ""),
        )

    org_uuid = session.get("org_uuid")
    org_payload = None
    memberships = account.get("memberships")
    if isinstance(memberships, list) and memberships:
        first = memberships[0] if isinstance(memberships[0], dict) else {}
        candidate = first.get("organization") if isinstance(first, dict) else None
        if isinstance(candidate, dict):
            org_payload = candidate
            if not org_uuid and isinstance(candidate.get("uuid"), str):
                org_uuid = candidate["uuid"]

    if isinstance(org_uuid, str) and org_uuid:
        ocode, richer, _ = _http_json(WEB_ORG_API.format(org=org_uuid), headers)
        if ocode >= 200 and ocode < 300 and isinstance(richer, dict):
            org_payload = richer

    plan, tier = plan_from_org_payload(org_payload)
    usage_payload: dict = {}
    if isinstance(org_uuid, str) and org_uuid:
        ucode, usage_body, _ = _http_json(WEB_USAGE_API.format(org=org_uuid), headers)
        if ucode >= 200 and ucode < 300 and isinstance(usage_body, dict):
            usage_payload = usage_body

    summary = summarize_usage_payload(usage_payload, subscription=plan, tier=tier, source="claude_web_session")
    # Optional identity enrichment for callers (no secrets).
    identity = {}
    email = account.get("email_address")
    if isinstance(email, str) and "@" in email:
        identity["email"] = email.strip()[:120]
    for key, src in (("display_name", "display_name"), ("full_name", "full_name")):
        val = account.get(src)
        if isinstance(val, str) and val.strip():
            identity[key] = val.strip()[:80]
    if isinstance(org_payload, dict):
        org_name = meaningful_organization(org_payload.get("name") if isinstance(org_payload.get("name"), str) else None)
        if org_name:
            identity["organization"] = org_name
    uuid = account.get("uuid")
    if isinstance(uuid, str) and uuid.strip():
        identity["account_uuid"] = uuid.strip()[:64]
    if identity.get("display_name") or identity.get("full_name"):
        identity["label"] = identity.get("display_name") or identity.get("full_name")

    return ok(status="usage", usage=summary, identity=identity)


def fetch_usage_summary(credential: dict) -> dict:
    token = credential.get("token")
    if not isinstance(token, str) or not token:
        return fail("missing_token", detail="本地没有可用的登录令牌")

    headers = {
        "Authorization": "Bearer " + token,
        "anthropic-beta": "oauth-2025-04-20",
        "anthropic-version": "2023-06-01",
    }
    code, payload, detail = _http_json(USAGE_API, headers)
    if code in (401, 403) and credential.get("refresh_token"):
        refreshed = refresh_access_token(
            credential["refresh_token"],
            scope_from_cache_key(str(credential.get("cache_key") or "")),
        )
        if refreshed and refreshed.get("token"):
            token = refreshed["token"]
            headers["Authorization"] = "Bearer " + token
            code, payload, detail = _http_json(USAGE_API, headers)
    if code < 200 or code >= 300 or not payload:
        return fail(
            "usage_unavailable",
            detail=f"用量接口不可用（HTTP {code}）" + (f"：{detail}" if detail else ""),
        )

    # Prefer organization usage payload when available (Desktop meter source).
    org = None
    pcode, profile, _ = _http_json(PROFILE_API, headers)
    if pcode >= 200 and pcode < 300 and isinstance(profile, dict):
        organization = profile.get("organization")
        if isinstance(organization, dict) and isinstance(organization.get("uuid"), str):
            org = organization["uuid"]
    if org:
        ocode, richer, _ = _http_json(ORG_USAGE_API.format(org=org), headers)
        if ocode >= 200 and ocode < 300 and isinstance(richer, dict):
            # Fill missing windows from the first payload.
            for key in ("five_hour", "seven_day"):
                if not isinstance(richer.get(key), dict) and isinstance(payload.get(key), dict):
                    richer[key] = payload[key]
            payload = richer

    return ok(
        status="usage",
        usage=summarize_usage_payload(
            payload,
            subscription=credential.get("subscription"),
            tier=credential.get("rate_limit_tier"),
        ),
    )


def desktop_root_for_slot(base: Path, data: Path, slot: str, current: str | None) -> Path:
    if current == slot and data.exists():
        return data
    return account_dir(base, slot)


def refresh_usage_for_slot(
    slot: str,
    *,
    confirmed: bool = False,
    home: Path | None = None,
    runner: Callable | None = None,
) -> dict:
    target = valid_slot(slot)
    if not target:
        return fail("invalid_slot", detail=f"账号必须是 {SLOT_HELP}")
    if not confirmed:
        return fail("confirmation_required", detail="需要 --i-confirm-refresh-usage")

    root = home or home_dir()
    base = base_dir(root)
    data = data_dir(root)
    ensure_base(base)
    current = read_current(base)
    desktop_root = desktop_root_for_slot(base, data, target, current)
    if not desktop_root.exists():
        return fail("slot_missing", detail="该账号还没有本地数据，请先登录或切换到该槽位")

    credential = load_oauth_credential(desktop_root, runner=runner)
    if not credential:
        # Fall back to the other copy when current live has no token cache yet.
        alt = account_dir(base, target) if desktop_root == data else data
        if alt.exists() and alt != desktop_root:
            credential = load_oauth_credential(alt, runner=runner)

    result: dict | None = None
    if credential:
        result = fetch_usage_summary(credential)
        credential.clear()
        if not result.get("ok") and result.get("reason") in {"missing_token", "usage_unavailable"}:
            # Newer Desktop builds often omit oauth:tokenCache*; try web session next.
            result = None

    if result is None:
        session = load_session_credential(desktop_root, runner=runner, cf_fallback_root=data)
        if not session:
            alt = account_dir(base, target) if desktop_root == data else data
            if alt.exists() and alt != desktop_root:
                session = load_session_credential(alt, runner=runner, cf_fallback_root=data)
        if not session:
            return fail(
                "missing_token",
                detail="本地没有可用登录会话。请打开 Claude Desktop 并保持登录，退出一次后再点刷新（首次可能要求钥匙串授权）。免费账号也会显示订阅，不要求先升级 Pro。",
                slot=target,
            )
        result = fetch_usage_via_session(session)
        session.clear()

    if not result.get("ok"):
        return result

    usage = result.get("usage") if isinstance(result.get("usage"), dict) else {}
    slot_dir = account_dir(base, target)
    slot_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    write_usage_file(slot_dir, usage)
    # Keep a compact subscription label on identity sidecar when present.
    identity = read_identity_file(slot_dir)
    if usage.get("subscription"):
        identity["subscription"] = str(usage["subscription"])[:40]
    extra_identity = result.get("identity") if isinstance(result.get("identity"), dict) else {}
    for key in ("email", "display_name", "full_name", "label", "organization", "account_uuid"):
        val = extra_identity.get(key)
        if isinstance(val, str) and val.strip():
            identity[key] = val.strip()[:120]
    if identity:
        write_identity_file(slot_dir, identity)
    return ok(status="usage_refreshed", current=current, slot=target, usage=usage)


def desktop_running(runner: Callable | None = None) -> bool:
    run = runner or subprocess.run
    try:
        proc = run(
            ["/usr/bin/pgrep", "-f", DESKTOP_PATTERN],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return any(line.strip().isdigit() for line in (proc.stdout or "").splitlines())


def quit_desktop(runner: Callable | None = None, sleeper: Callable | None = None, wait: int = QUIT_WAIT_SECONDS) -> bool:
    """Gracefully quit Claude Desktop. Returns True if not running afterwards."""
    run = runner or subprocess.run
    sleep = sleeper or time.sleep
    if not desktop_running(runner=run):
        return True
    try:
        run(
            ["/usr/bin/osascript", "-e", 'tell application "Claude" to quit'],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pass
    for _ in range(max(1, wait)):
        if not desktop_running(runner=run):
            return True
        sleep(1)
    return not desktop_running(runner=run)


def open_desktop(runner: Callable | None = None) -> bool:
    run = runner or subprocess.run
    try:
        proc = run(
            ["/usr/bin/open", "-a", "Claude"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def copy_tree(src: Path, dst: Path) -> None:
    """Copy directory tree. Prefer APFS clonefile when available."""
    if dst.exists() or dst.is_symlink():
        raise FileExistsError(str(dst))
    # cp -cRp is clonefile on APFS; fall back to copytree.
    try:
        proc = subprocess.run(
            ["/bin/cp", "-cRp", str(src), str(dst)],
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
        )
        if proc.returncode == 0 and dst.exists():
            return
        if dst.exists():
            shutil.rmtree(dst)
    except (OSError, subprocess.TimeoutExpired):
        if dst.exists():
            shutil.rmtree(dst, ignore_errors=True)
    # Preserve symlinks as links; do not follow them into foreign trees.
    shutil.copytree(src, dst, symlinks=True, ignore_dangling_symlinks=True)


def archive_live(data: Path, base: Path, slot: str) -> dict | None:
    """Move/copy live Desktop data into accounts/<slot>. Fail closed on interruption."""
    if not valid_slot(slot):
        return fail("invalid_slot", slot=slot)
    ensure_base(base)
    staged = account_dir(base, slot).with_name(slot + ".new")
    current = account_dir(base, slot)
    previous = account_dir(base, slot).with_name(slot + ".previous")

    if staged.exists() or staged.is_symlink() or previous.exists() or previous.is_symlink():
        return fail(
            "interrupted_archive_present",
            detail=f"存在待恢复快照，拒绝覆盖：检查 {staged} / {previous}",
            slot=slot,
        )
    if not data.exists():
        # Nothing to archive; treat as empty current identity.
        current.mkdir(parents=True, exist_ok=True, mode=0o700)
        return None

    moved = False
    try:
        os.rename(data, staged)
        moved = True
    except OSError:
        if staged.exists() or staged.is_symlink():
            return fail("archive_move_incomplete", slot=slot, path=str(staged))
        try:
            copy_tree(data, staged)
        except OSError as exc:
            return fail("archive_copy_failed", slot=slot, detail=str(exc))

    had_old = False
    if current.exists() or current.is_symlink():
        try:
            os.rename(current, previous)
            had_old = True
        except OSError:
            if moved:
                try:
                    os.rename(staged, data)
                except OSError:
                    pass
            return fail("archive_cannot_park_old", slot=slot)

    try:
        os.rename(staged, current)
    except OSError:
        if had_old:
            try:
                os.rename(previous, current)
            except OSError:
                pass
        if moved:
            try:
                os.rename(staged, data)
            except OSError:
                pass
        return fail("archive_commit_failed", slot=slot)

    if had_old:
        # Preserve sidecars from a previous sidecar-only slot dir before wiping it.
        if not has_desktop_archive(previous):
            old_usage = read_usage_file(previous)
            old_identity = read_identity_file(previous)
            if old_usage and not read_usage_file(current):
                write_usage_file(current, old_usage)
            if old_identity:
                merged = {**old_identity, **extract_identity(current)}
                write_identity_file(current, merged)
        shutil.rmtree(previous, ignore_errors=True)
    try:
        os.chmod(current, 0o700)
    except OSError:
        pass
    write_identity_file(current, extract_identity(current))
    return None


def restore_slot(base: Path, data: Path, slot: str, empty_ok: bool = True) -> dict | None:
    """Restore accounts/<slot> into the live Desktop data directory."""
    source = account_dir(base, slot)
    staged = data.with_name(data.name + ".new")
    if staged.exists() or staged.is_symlink():
        return fail("interrupted_restore_present", path=str(staged))

    # Sidecar-only dirs (usage.json / identity.json) are not Desktop archives.
    if has_desktop_archive(source):
        try:
            copy_tree(source, staged)
        except OSError as exc:
            return fail("restore_copy_failed", slot=slot, detail=str(exc))
    elif empty_ok:
        staged.mkdir(parents=True, exist_ok=True, mode=0o700)
        # Keep pre-existing usage/identity sidecars in the slot dir; do not copy them into live.
    else:
        return fail("slot_missing", slot=slot)

    # Replace live directory.
    if data.exists() or data.is_symlink():
        trash = data.with_name(data.name + ".replaced")
        if trash.exists() or trash.is_symlink():
            return fail("interrupted_restore_present", path=str(trash))
        try:
            os.rename(data, trash)
        except OSError as exc:
            shutil.rmtree(staged, ignore_errors=True)
            return fail("restore_cannot_park_live", detail=str(exc))
        try:
            os.rename(staged, data)
        except OSError as exc:
            try:
                os.rename(trash, data)
            except OSError:
                pass
            shutil.rmtree(staged, ignore_errors=True)
            return fail("restore_commit_failed", detail=str(exc))
        shutil.rmtree(trash, ignore_errors=True)
    else:
        try:
            os.rename(staged, data)
        except OSError as exc:
            shutil.rmtree(staged, ignore_errors=True)
            return fail("restore_commit_failed", detail=str(exc))
    return None


def status_payload(
    home: Path | None = None,
    runner: Callable | None = None,
) -> dict:
    root = home or home_dir()
    base = base_dir(root)
    data = data_dir(root)
    ensure_base(base)
    current = read_current(base)
    live_identity = extract_identity(data) if dir_nonempty(data) else {}
    slots = {}
    for slot in SLOTS:
        path = account_dir(base, slot)
        meta = slot_meta(path)
        identity = {}
        usage = {}
        # Sidecars (identity/usage) may exist without a full Desktop archive.
        if meta.get("has_archive") or current == slot or path.is_dir():
            identity = resolve_slot_identity(path, live=data, is_current=(current == slot))
            usage = read_usage_file(path)
            # Strip any accidental secret-looking fields from older files.
            usage = {
                key: usage[key]
                for key in (
                    "ok",
                    "subscription",
                    "rate_limit_tier",
                    "session",
                    "week",
                    "fetched_at",
                    "source",
                    "product",
                    "version",
                )
                if key in usage
            }
        slots[slot] = {
            "slot": slot,
            "is_current": current == slot,
            **meta,
            "identity": identity,
            "usage": usage,
        }
    return ok(
        status="status",
        current=current,
        live_exists=dir_nonempty(data),
        live_path=str(data),
        live_identity=live_identity,
        base_path=str(base),
        desktop_running=desktop_running(runner=runner),
        slots=slots,
        note="账号切换不是检测通过，也不代表防直连已开启。显示名来自本机缓存，不验证服务端。",
    )


def switch_to(
    target: str,
    *,
    open_after: bool = False,
    confirmed: bool = False,
    home: Path | None = None,
    runner: Callable | None = None,
    sleeper: Callable | None = None,
) -> dict:
    slot = valid_slot(target)
    if not slot:
        return fail("invalid_slot", detail=f"账号必须是 {SLOT_HELP}")
    if not confirmed:
        return fail("confirmation_required", detail="需要 --i-confirm-switch")

    root = home or home_dir()
    base = base_dir(root)
    data = data_dir(root)
    ensure_base(base)

    if not quit_desktop(runner=runner, sleeper=sleeper):
        return fail("desktop_still_running", detail="请先退出 Claude Desktop 后再切换")

    current = read_current(base)
    # First use: adopt nonempty live data as A when current is unset.
    if current is None and dir_nonempty(data):
        err = archive_live(data, base, "A")
        if err:
            return err
        write_current(base, "A")
        current = "A"
        # Live data was moved into A; recreate empty live only if staying on A below.

    if current == slot:
        # Ensure live data exists for the current slot.
        if not data.exists():
            err = restore_slot(base, data, slot, empty_ok=True)
            if err:
                return err
        opened = False
        if open_after:
            opened = open_desktop(runner=runner)
        return ok(
            status="already_current",
            current=slot,
            opened=opened if open_after else False,
            message=f"当前已是账号 {slot}",
        )

    if current in SLOTS and dir_nonempty(data):
        err = archive_live(data, base, current)
        if err:
            return err
    elif current in SLOTS and data.exists() and not dir_nonempty(data):
        # Empty live dir: still park as archive so restore can replace cleanly.
        try:
            if data.exists():
                shutil.rmtree(data)
        except OSError as exc:
            return fail("cannot_clear_empty_live", detail=str(exc))

    err = restore_slot(base, data, slot, empty_ok=True)
    if err:
        return err
    write_current(base, slot)

    opened = False
    open_error = None
    if open_after:
        opened = open_desktop(runner=runner)
        if not opened:
            open_error = "open_failed"

    result = ok(
        status="switched",
        current=slot,
        previous=current,
        opened=opened if open_after else False,
        message=f"已切换到账号 {slot}" + (" 并尝试打开 Claude" if open_after else "；未自动打开 Claude"),
    )
    if open_error:
        result["open_error"] = open_error
    return result


def adopt_live(
    slot: str,
    *,
    confirmed: bool = False,
    home: Path | None = None,
    runner: Callable | None = None,
    sleeper: Callable | None = None,
) -> dict:
    """Archive current live Desktop data as <slot> and mark it current (no target restore)."""
    target = valid_slot(slot)
    if not target:
        return fail("invalid_slot", detail=f"账号必须是 {SLOT_HELP}")
    if not confirmed:
        return fail("confirmation_required", detail="需要 --i-confirm-adopt")

    root = home or home_dir()
    base = base_dir(root)
    data = data_dir(root)
    ensure_base(base)

    if not quit_desktop(runner=runner, sleeper=sleeper):
        return fail("desktop_still_running", detail="请先退出 Claude Desktop 后再归档")
    if not dir_nonempty(data):
        return fail("live_empty", detail="当前没有可归档的 Claude Desktop 数据")

    existing = account_dir(base, target)
    if has_desktop_archive(existing) or existing.is_symlink():
        return fail("slot_occupied", slot=target, detail="目标槽位已有归档，请先切换走或手动清理")

    err = archive_live(data, base, target)
    if err:
        return err
    # archive_live moves live away; restore it back so the user keeps working as that identity.
    err = restore_slot(base, data, target, empty_ok=False)
    if err:
        return err
    write_current(base, target)
    return ok(status="adopted", current=target, message=f"已将当前 Desktop 身份归档为账号 {target}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Claude Desktop A/B account switcher")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Show current slot and archives")

    sw = sub.add_parser("switch", help="Switch live Desktop data to slot A–D")
    sw.add_argument("--to", required=True, choices=SLOTS)
    sw.add_argument("--open", action="store_true", help="Open Claude Desktop after switch")
    sw.add_argument("--i-confirm-switch", action="store_true")

    ad = sub.add_parser("adopt", help="Archive current live Desktop data as a slot")
    ad.add_argument("--as", dest="slot", required=True, choices=SLOTS)
    ad.add_argument("--i-confirm-adopt", action="store_true")

    ru = sub.add_parser("refresh-usage", help="Refresh subscription/quota via Anthropic usage API")
    ru.add_argument("--slot", required=True, choices=SLOTS)
    ru.add_argument("--i-confirm-refresh-usage", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "status":
        return emit(status_payload())
    if args.command == "switch":
        payload = switch_to(args.to, open_after=args.open, confirmed=args.i_confirm_switch)
        return emit(payload, 0 if payload.get("ok") else 1)
    if args.command == "adopt":
        payload = adopt_live(args.slot, confirmed=args.i_confirm_adopt)
        return emit(payload, 0 if payload.get("ok") else 1)
    if args.command == "refresh-usage":
        payload = refresh_usage_for_slot(args.slot, confirmed=args.i_confirm_refresh_usage)
        return emit(payload, 0 if payload.get("ok") else 1)
    return emit(fail("unknown_command"), 2)


if __name__ == "__main__":
    sys.exit(main())
