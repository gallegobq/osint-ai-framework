from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from starlette.requests import Request
from starlette.responses import Response

from app.auth.jwt import create_access_token
from app.core.settings import settings
from app.middleware.rate_limit import RateLimitMiddleware


def _request(
    *,
    client: str = "203.0.113.10",
    authorization: str | None = None,
    forwarded_for: str | None = None,
) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode("ascii")))
    if forwarded_for is not None:
        headers.append((b"x-forwarded-for", forwarded_for.encode("ascii")))
    return Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/v1/projects",
            "raw_path": b"/api/v1/projects",
            "query_string": b"",
            "headers": headers,
            "client": (client, 1234),
            "server": ("testserver", 80),
        }
    )


async def _next(_request: Request) -> Response:
    return Response(status_code=200)


@pytest.mark.asyncio
async def test_invalid_bearer_values_cannot_create_new_rate_limit_buckets(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    middleware = RateLimitMiddleware(AsyncMock())
    middleware._increment = AsyncMock(return_value=1)  # type: ignore[method-assign]

    await middleware.dispatch(
        _request(authorization="Bearer invalid-one"),
        _next,
    )
    await middleware.dispatch(
        _request(authorization="Bearer invalid-two"),
        _next,
    )

    assert middleware._increment.await_count == 2
    identities = [
        item.args[2] for item in middleware._increment.await_args_list
    ]
    assert identities == ["203.0.113.10", "203.0.113.10"]
    await middleware.redis.aclose()


@pytest.mark.asyncio
async def test_valid_access_token_adds_a_separate_user_bucket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "rate_limit_user_enabled", True)
    middleware = RateLimitMiddleware(AsyncMock())
    middleware._increment = AsyncMock(return_value=1)  # type: ignore[method-assign]
    token, _jti = create_access_token("7")

    await middleware.dispatch(
        _request(authorization=f"Bearer {token}"),
        _next,
    )

    scopes = [
        (item.args[1], item.args[2])
        for item in middleware._increment.await_args_list
    ]
    assert scopes == [("ip", "203.0.113.10"), ("user", "7")]
    await middleware.redis.aclose()


def test_forwarded_for_requires_a_configured_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "trust_proxy_headers", True)
    monkeypatch.setattr(settings, "trusted_proxy_networks", ["10.0.0.0/8"])
    middleware = RateLimitMiddleware(AsyncMock())

    trusted = _request(
        client="10.1.2.3",
        forwarded_for="198.51.100.8",
    )
    untrusted = _request(
        client="192.0.2.10",
        forwarded_for="198.51.100.8",
    )

    assert middleware._client_ip(trusted) == "198.51.100.8"
    assert middleware._client_ip(untrusted) == "192.0.2.10"
