#!/usr/bin/env python3
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import plistlib
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import providers as p


def fixture():
    return {
        "/version": {"version": "test"}, "/configs": {"mode": "rule", "secret": "SECRET"},
        "/rules": {"rules": [{"type": "DomainSuffix", "payload": "anthropic.com", "proxy": "MEI"}]},
        "/proxies": {"proxies": {"MEI": {"type": "Selector", "now": "PRIVATE_NODE", "all": ["PRIVATE_NODE"]},
                                    "PRIVATE_NODE": {"type": "Socks5", "password": "SECRET", "dialer-proxy": "PRIVATE_HOP"}}},
        "/connections": {"connections": [
            {"id": "PRIVATE_ID", "metadata": {"host": "api.anthropic.com", "processPath": "/PRIVATE_PATH"}, "chains": ["PRIVATE_NODE", "MEI"]},
            {"id": "OTHER", "metadata": {"host": "private.example"}, "chains": ["PRIVATE_NODE"]},
        ]},
    }


@contextmanager
def server(responder):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            calls.append((self.command, self.path, self.headers.get("Authorization")))
            try:
                responder(self)
            except (BrokenPipeError, ConnectionResetError):
                pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    httpd.daemon_threads = True
    worker = threading.Thread(target=httpd.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}", calls
    finally:
        httpd.shutdown()
        httpd.server_close()
        worker.join(timeout=1)


def respond_json(request, value, status=200, headers=None):
    data = json.dumps(value).encode()
    request.send_response(status)
    request.send_header("Content-Type", "application/json")
    request.send_header("Content-Length", str(len(data)))
    for key, value in (headers or {}).items():
        request.send_header(key, value)
    request.end_headers()
    request.wfile.write(data)


class ProviderTests(unittest.TestCase):
    def test_unconfigured_profiles_never_connect(self):
        def forbidden(*_):
            self.fail("must not connect")
        for profile in p.PROVIDERS.values():
            report = p.inspect(profile, client_factory=forbidden)
            self.assertFalse(report["observability_ready"])
            self.assertFalse(report["protection_verified"])

    def test_endpoints_are_literal_loopback_only(self):
        self.assertEqual(p.local_endpoint("http://[::1]:9090"), ("::1", 9090))
        for value in ("http://localhost:9090", "http://example.com:80", "http://192.0.2.1:80",
                      "https://127.0.0.1:9090", "http://u:password@127.0.0.1:90",
                      "http://127.0.0.1:90/configs", "http://[::1%lo0]:90",
                      "http://127.0.0.1", "http://127.0.0.1:90?", "http://127.0.0.1:0"):
            with self.assertRaises(p.InspectionError, msg=value):
                p.local_endpoint(value)

    def test_auth_is_required_before_connecting(self):
        profile = replace(p.PROVIDERS["longmao"], controller="http://127.0.0.1:9090")
        with patch.dict("os.environ", {}, clear=True):
            report = p.inspect(profile, "MISSING", client_factory=lambda *_: self.fail("must not connect"))
        self.assertEqual(report["reason"], "controller_auth_missing_or_invalid")
        with self.assertRaises(p.InspectionError):
            p.ControllerReader(profile.controller, "token\r\nInjected: yes")

    def test_real_http_reads_only_fixed_paths_and_ignores_proxy_env(self):
        data = fixture()
        with server(lambda r: respond_json(r, data[r.path])) as (url, calls):
            with patch.dict("os.environ", {"TEST_TOKEN": "fixture-token", "HTTP_PROXY": "http://127.0.0.1:1", "ALL_PROXY": "http://127.0.0.1:1"}):
                result = p.inspect(replace(p.PROVIDERS["longmao"], controller=url), "TEST_TOKEN")
        self.assertTrue(result["observability_ready"])
        self.assertFalse(result["provider_binding_verified"])
        self.assertFalse(result["protection_verified"])
        self.assertEqual([call[:2] for call in calls], [("GET", path) for path in p.API_PATHS])
        self.assertTrue(all(call[2] == "Bearer fixture-token" for call in calls))
        encoded = json.dumps(result)
        for private in ("SECRET", "PRIVATE_NODE", "PRIVATE_HOP", "PRIVATE_ID", "PRIVATE_PATH", "private.example", "fixture-token"):
            self.assertNotIn(private, encoded)
        self.assertEqual(len(result["evidence"]["controlled_connections"]), 1)

    def test_redirect_never_receives_auth(self):
        with server(lambda r: respond_json(r, {}, 302, {"Location": "/proxies"})) as (url, calls):
            with self.assertRaisesRegex(p.InspectionError, "redirect_rejected"):
                p.ControllerReader(url, "fixture").get("/version")
        self.assertEqual(len(calls), 1)

    def test_error_body_is_not_reported(self):
        with server(lambda r: respond_json(r, {"error": "SECRET"}, 401)) as (url, _):
            with patch.dict("os.environ", {"TEST_TOKEN": "fixture"}):
                result = p.inspect(replace(p.PROVIDERS["longmao"], controller=url), "TEST_TOKEN")
        self.assertEqual(result["reason"], "controller_auth_rejected")
        self.assertNotIn("SECRET", json.dumps(result))

    def test_body_limit_precedes_reading(self):
        def oversized(r):
            r.send_response(200)
            r.send_header("Content-Type", "application/json")
            r.send_header("Content-Length", str(p.MAX_BYTES + 1))
            r.end_headers()
        with server(oversized) as (url, _):
            with self.assertRaisesRegex(p.InspectionError, "body_too_large"):
                p.ControllerReader(url, "fixture").get("/connections")

    def test_trickling_body_has_wall_clock_deadline(self):
        def trickle(r):
            r.send_response(200)
            r.send_header("Content-Type", "application/json")
            r.send_header("Content-Length", "1000")
            r.end_headers()
            for _ in range(20):
                r.wfile.write(b" ")
                r.wfile.flush()
                time.sleep(.04)
        with server(trickle) as (url, _):
            started = time.monotonic()
            with self.assertRaises(p.InspectionError):
                p.ControllerReader(url, "fixture", timeout=.15).get("/version")
            self.assertLess(time.monotonic() - started, 1)

    def test_unsupported_http_shapes_and_json_fail_closed(self):
        for headers, body in (({"Content-Type": "text/html"}, b"SECRET"),
                              ({"Content-Type": "application/json", "Content-Encoding": "gzip"}, b"{}"),
                              ({"Content-Type": "application/json"}, b'{"x":1,"x":2}')):
            def responder(r):
                r.send_response(200)
                for key, value in headers.items(): r.send_header(key, value)
                r.send_header("Content-Length", str(len(body)))
                r.end_headers()
                r.wfile.write(body)
            with server(responder) as (url, _):
                with self.assertRaises(p.InspectionError):
                    p.ControllerReader(url, "fixture").get("/version")

    def test_schema_and_host_scope(self):
        for host in ("notanthropic.com", "anthropic.com.evil.example", "a..anthropic.com", "user@claude.ai"):
            self.assertIsNone(p.controlled_root(host))
        data = fixture()
        data["/rules"] = {}
        with self.assertRaises(p.InspectionError): p.evidence(data)
        reader = p.ControllerReader("http://127.0.0.1:9", "fixture")
        with self.assertRaisesRegex(p.InspectionError, "path_not_allowed"): reader.get("/shutdown")

    def test_saved_settings_output_excludes_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "preferences.plist"
            config = {"patchClashConfig": {"mixed-port": 1082, "mode": "rule", "external-controller": "", "tun": {"enable": True}, "secret": "SECRET"}}
            path.write_bytes(plistlib.dumps({"flutter.config": json.dumps(config), "flutter.password": "SECRET"}))
            provider, saved = p.discover_longmao(path)
            self.assertIsNone(provider.controller)
            self.assertEqual(provider.proxy_port, 1082)
            self.assertTrue(saved["tun_configured"])
            self.assertNotIn("SECRET", json.dumps(saved))


if __name__ == "__main__":
    unittest.main()
