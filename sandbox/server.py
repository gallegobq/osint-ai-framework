"""Narrow, dependency-free execution boundary for approved SOC probes.

The service intentionally exposes no shell, command arguments, file upload, or
generic URL fetcher. Every tool is a Python function registered in TOOL_HANDLERS.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)
MAX_REQUEST_BYTES = 16_384
MAX_HEADER_BYTES = 65_536
SOCKET_TIMEOUT_SECONDS = float(os.getenv("SANDBOX_SOCKET_TIMEOUT_SECONDS", "10"))


def normalize_public_hostname(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("target must be a hostname string")
    candidate = value.strip().lower().rstrip(".")
    try:
        hostname = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("target is not a valid internationalized hostname") from exc
    if not DOMAIN_PATTERN.fullmatch(hostname):
        raise ValueError("target is not a valid hostname")
    return hostname


def resolve_public_addresses(hostname: str) -> list[str]:
    try:
        records = socket.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise RuntimeError("target could not be resolved") from exc
    addresses = sorted(
        {record[4][0] for record in records},
        key=lambda value: (ipaddress.ip_address(value).version, value),
    )
    if not addresses:
        raise RuntimeError("target did not resolve to an address")
    if any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise ValueError("target resolved to a non-public address")
    return addresses


def flatten_name(value: tuple) -> str:
    parts: list[str] = []
    for group in value:
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts)


def open_tls(
    address: str,
    hostname: str,
    *,
    verify: bool,
) -> ssl.SSLSocket:
    raw = socket.create_connection(
        (address, 443),
        timeout=SOCKET_TIMEOUT_SECONDS,
    )
    raw.settimeout(SOCKET_TIMEOUT_SECONDS)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        return context.wrap_socket(raw, server_hostname=hostname)
    except Exception:
        raw.close()
        raise


def read_http_headers(tls: ssl.SSLSocket, hostname: str) -> tuple[int, dict[str, str]]:
    request = (
        f"HEAD / HTTP/1.1\r\nHost: {hostname}\r\n"
        "User-Agent: Linterna-SOC-Sandbox/1.0\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode("ascii")
    tls.sendall(request)
    payload = bytearray()
    while b"\r\n\r\n" not in payload:
        chunk = tls.recv(4096)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > MAX_HEADER_BYTES:
            raise RuntimeError("HTTP response headers exceeded the sandbox limit")
    header_block = bytes(payload).split(b"\r\n\r\n", 1)[0]
    lines = header_block.decode("iso-8859-1", errors="replace").split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise RuntimeError("target did not return a valid HTTP response")
    try:
        status = int(lines[0].split(" ", 2)[1])
    except (IndexError, ValueError) as exc:
        raise RuntimeError("target returned an invalid HTTP status") from exc
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        if normalized_key and normalized_key not in headers:
            headers[normalized_key] = value.strip()[:2000]
    return status, headers


def tls_http_baseline(target: object) -> dict[str, Any]:
    hostname = normalize_public_hostname(target)
    addresses = resolve_public_addresses(hostname)
    selected_address = addresses[0]
    verification_error: str | None = None
    verified = True

    try:
        tls = open_tls(selected_address, hostname, verify=True)
    except ssl.SSLCertVerificationError as exc:
        verified = False
        verification_error = str(exc.verify_message)[:300]
        tls = open_tls(selected_address, hostname, verify=False)

    try:
        certificate = tls.getpeercert() if verified else {}
        certificate_der = tls.getpeercert(binary_form=True) or b""
        tls_version = tls.version()
        cipher = tls.cipher()
        http_status, headers = read_http_headers(tls, hostname)
    finally:
        tls.close()

    security_headers = {
        name: headers.get(name)
        for name in (
            "strict-transport-security",
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
            "permissions-policy",
        )
    }
    issues: list[dict[str, str]] = []
    if not verified:
        issues.append(
            {
                "severity": "high",
                "code": "certificate_verification_failed",
                "detail": verification_error or "certificate verification failed",
            }
        )
    required_headers = {
        "strict-transport-security": "medium",
        "content-security-policy": "medium",
        "x-content-type-options": "low",
        "x-frame-options": "low",
        "referrer-policy": "low",
    }
    for header, severity in required_headers.items():
        if not security_headers[header]:
            issues.append(
                {
                    "severity": severity,
                    "code": f"missing_{header.replace('-', '_')}",
                    "detail": f"The root response did not include {header}.",
                }
            )

    return {
        "tool": "tls_http_baseline",
        "profile": "single-host-low-impact-v1",
        "target": hostname,
        "port": 443,
        "resolved_addresses": addresses,
        "selected_address": selected_address,
        "tls": {
            "version": tls_version,
            "cipher": cipher[0] if cipher else None,
            "certificate_verified": verified,
            "certificate_verification_error": verification_error,
            "certificate_sha256": hashlib.sha256(certificate_der).hexdigest(),
            "subject": flatten_name(certificate.get("subject", ())),
            "issuer": flatten_name(certificate.get("issuer", ())),
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
            "subject_alt_names": [
                value
                for kind, value in certificate.get("subjectAltName", ())[:100]
                if kind == "DNS"
            ],
        },
        "http": {
            "method": "HEAD",
            "path": "/",
            "status": http_status,
            "security_headers": security_headers,
        },
        "issues": issues,
        "limits": {
            "redirects_followed": 0,
            "request_count": 1,
            "tls_handshakes": 1 if verified else 2,
        },
    }


TOOL_HANDLERS = {"tls_http_baseline": tls_http_baseline}


class SandboxHandler(BaseHTTPRequestHandler):
    server_version = "LinternaSandbox/1.0"

    def log_message(self, format: str, *args: object) -> None:
        # Do not log targets or request bodies from authorized engagements.
        print(f"sandbox request: {self.command} {self.path} {args[1] if len(args) > 1 else '-'}")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self.send_json(404, {"error": "not_found"})
            return
        self.send_json(200, {"status": "healthy", "tools": sorted(TOOL_HANDLERS)})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/v1/run":
            self.send_json(404, {"error": "not_found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_json(400, {"error": "invalid_content_length"})
            return
        if length < 2 or length > MAX_REQUEST_BYTES:
            self.send_json(413, {"error": "request_size_rejected"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict) or set(payload) != {"tool", "target"}:
                raise ValueError("request must contain only tool and target")
            handler = TOOL_HANDLERS.get(payload["tool"])
            if handler is None:
                raise ValueError("tool is not allowlisted")
            result = handler(payload["target"])
        except ValueError as exc:
            self.send_json(422, {"error": "validation_failed", "detail": str(exc)[:300]})
            return
        except Exception as exc:
            self.send_json(
                502,
                {"error": "probe_failed", "detail": type(exc).__name__},
            )
            return
        self.send_json(200, result)


def main() -> None:
    server = ThreadingHTTPServer(("0.0.0.0", 8090), SandboxHandler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
