#!/usr/bin/env python3
"""Test-only TLS echo peer. Generates ephemeral credentials; binds only loopback."""

import base64
import datetime as dt
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import sys
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


NAME = "tls-fixture.invalid"
MODES = {"normal", "expired", "wrong_nonce", "truncated", "blackhole", "silent_echo",
         "tls12", "tls13", "tls11"}


def write_private(root, name, value):
    with (root / name).open("xb") as stream:
        stream.write(value)


def record(root, name, value):
    pending = root / (name + ".pending")
    with pending.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, sort_keys=True)
    os.replace(pending, root / name)


def make_context(root, mode):
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router ephemeral fixture CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=5)).not_valid_after(now + dt.timedelta(days=5))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = mode == "expired"
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAME)]))
        .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=3) if expired else now - dt.timedelta(hours=1))
        .not_valid_after(now - dt.timedelta(days=2) if expired else now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(NAME)]), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    write_private(root, "leaf.pem", leaf.public_bytes(serialization.Encoding.PEM) +
                  ca.public_bytes(serialization.Encoding.PEM))
    write_private(root, "key.pem", key.private_bytes(serialization.Encoding.PEM,
                  serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if mode == "tls12":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    if mode == "tls13":
        context.minimum_version = ssl.TLSVersion.TLSv1_3
    if mode == "tls11":
        # Deliberately obsolete protocol, confined to this negative test's loopback listener.
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_1
        context.set_ciphers("ALL:@SECLEVEL=0")
    context.load_cert_chain(str(root / "leaf.pem"), str(root / "key.pem"))
    return context, ca.public_bytes(serialization.Encoding.DER)


def exact(connection, count):
    value = b""
    while len(value) < count:
        chunk = connection.recv(count - len(value))
        if not chunk:
            raise EOFError("incomplete test request")
        value += chunk
    return value


def unique_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def serve(root, mode, family):
    context, anchor = make_context(root, mode)
    report = {"sni": None, "version": None, "peer": None, "nonce": None, "eof": False}
    context.set_servername_callback(lambda connection, name, original: report.update(sni=name))
    host = "127.0.0.1" if family == 4 else "::1"
    try:
        with socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_STREAM) as listener:
            if family == 6:
                listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.settimeout(8)
            listener.bind((host, 0))
            listener.listen(1)
            record(root, "ready.json", {"host": host, "port": listener.getsockname()[1],
                                       "anchor": base64.b64encode(anchor).decode("ascii")})
            raw, peer = listener.accept()
            with raw:
                raw.settimeout(6)
                report["peer"] = peer[0]
                record(root, "accepted.json", {"accepted": True})
                if mode == "blackhole":
                    while raw.recv(4096):
                        pass
                    report["eof"] = True
                else:
                    with context.wrap_socket(raw, server_side=True) as connection:
                        report["version"] = connection.version()
                        size = struct.unpack("!I", exact(connection, 4))[0]
                        if not 1 <= size <= 512:
                            raise ValueError("invalid frame length")
                        request = json.loads(exact(connection, size), object_pairs_hook=unique_keys)
                        if (set(request) != {"version", "nonce"} or type(request["version"]) is not int
                                or request["version"] != 1):
                            raise ValueError("invalid request")
                        nonce = str(uuid.UUID(request["nonce"]))
                        if request["nonce"] != nonce:
                            raise ValueError("noncanonical nonce")
                        report["nonce"] = nonce
                        if mode == "silent_echo":
                            record(root, "request.json", {"received": True})
                            while connection.recv(4096):
                                pass
                            report["eof"] = True
                            return
                        if mode == "wrong_nonce":
                            nonce = str(uuid.uuid4())
                        body = json.dumps({"version": 1, "nonce": nonce, "peerIP": peer[0]},
                                          separators=(",", ":")).encode()
                        frame = struct.pack("!I", len(body)) + body
                        if mode == "truncated":
                            connection.sendall(frame[:7])
                        else:
                            for offset in range(0, len(frame), 3):
                                connection.sendall(frame[offset:offset + 3])
                            report["eof"] = connection.recv(1) == b""
    except Exception as error:
        # Record only error classification; no arbitrary peer content or private credentials.
        report["error_kind"] = type(error).__name__
        if isinstance(error, ssl.SSLError):
            report["ssl_library"] = error.library
            report["ssl_reason"] = error.reason
    finally:
        record(root, "report.json", report)


def main():
    if os.getuid() == 0 or os.geteuid() != os.getuid() or len(sys.argv) != 4:
        raise SystemExit("unprivileged test fixture only")
    root, mode, family = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3])
    if mode not in MODES or family not in {4, 6} or not root.is_dir() or root.is_symlink():
        raise SystemExit("invalid fixture input")
    if root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise SystemExit("fixture directory must be private")
    os.umask(0o077)
    serve(root, mode, family)


if __name__ == "__main__":
    main()
