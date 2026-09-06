import ipaddress
import json
import socket
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.settings import settings


REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _require_public_https(url: str) -> str:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Collector endpoints must use absolute HTTPS URLs.")
    if parsed.username or parsed.password:
        raise ValueError("Collector endpoint credentials are not allowed in URLs.")
    if parsed.port not in (None, 443):
        raise ValueError("Collector endpoints must use the standard HTTPS port.")

    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                parsed.hostname,
                443,
                type=socket.SOCK_STREAM,
            )
        }
    except OSError as exc:
        raise RuntimeError("Collector endpoint could not be resolved.") from exc
    if not addresses or any(
        not ipaddress.ip_address(address).is_global for address in addresses
    ):
        raise ValueError("Collector endpoint resolved to a non-public address.")
    return parsed.hostname.lower()


class SafeHttpClient:
    """Bounded HTTPS client for fixed public OSINT provider endpoints."""

    def __init__(self, *, max_bytes: int | None = None):
        self.max_bytes = max_bytes or settings.osint_max_response_bytes

    def get_text(
        self,
        url: str,
        *,
        params: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        allowed_hosts: set[str],
        allow_public_redirects: bool = False,
    ) -> str:
        current_url = url
        current_params = params
        request_headers = {
            "Accept": "application/json",
            "User-Agent": settings.osint_user_agent,
            **(headers or {}),
        }

        with httpx.Client(
            timeout=settings.osint_http_timeout_seconds,
            follow_redirects=False,
            headers=request_headers,
        ) as client:
            for redirect_count in range(4):
                host = _require_public_https(current_url)
                if host not in allowed_hosts and not (
                    allow_public_redirects and redirect_count > 0
                ):
                    raise ValueError("Collector endpoint host is not allowlisted.")

                with client.stream(
                    "GET",
                    current_url,
                    params=current_params,
                ) as response:
                    if response.status_code in REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location or redirect_count == 3:
                            raise RuntimeError("Invalid collector endpoint redirect.")
                        current_url = urljoin(str(response.url), location)
                        current_params = None
                        continue

                    response.raise_for_status()
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > self.max_bytes:
                            raise RuntimeError(
                                "Collector response exceeded the configured limit."
                            )
                        chunks.append(chunk)
                    return b"".join(chunks).decode(
                        response.encoding or "utf-8",
                        errors="replace",
                    )

        raise RuntimeError("Collector endpoint redirect limit exceeded.")

    def get_json(self, *args, **kwargs) -> object:
        return json.loads(self.get_text(*args, **kwargs))
