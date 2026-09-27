import hashlib
import ipaddress
import logging
import time
from collections.abc import Sequence

from jwt.exceptions import InvalidTokenError
from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.auth.jwt import decode_token
from app.core.settings import settings


logger = logging.getLogger("osint.rate_limit")
AUTH_PATHS = {"/api/v1/auth/login", "/api/v1/auth/token", "/api/v1/auth/refresh"}
READINESS_PATH = "/api/v1/health/ready"
LIVENESS_PATH = "/api/v1/health"


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)
        self.trusted_proxy_networks = tuple(
            ipaddress.ip_network(value, strict=False)
            for value in settings.trusted_proxy_networks
        )

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.rate_limit_enabled or request.url.path == LIVENESS_PATH:
            return await call_next(request)

        category, limit, window = self._request_limit(request.url.path)
        client = self._client_ip(request)
        scopes = [("ip", client, limit, window)]

        subject = self._authenticated_subject(request)
        if (
            category == "general"
            and settings.rate_limit_user_enabled
            and subject is not None
        ):
            scopes.append(
                (
                    "user",
                    subject,
                    settings.rate_limit_user_requests,
                    settings.rate_limit_user_window_seconds,
                )
            )

        counts: list[tuple[str, int, int, int]] = []
        try:
            for scope, identity, scope_limit, scope_window in scopes:
                count = await self._increment(
                    category,
                    scope,
                    identity,
                    scope_window,
                )
                counts.append((scope, count, scope_limit, scope_window))
        except Exception:
            logger.exception("Rate-limit backend unavailable.")
            if category == "auth" and settings.rate_limit_fail_closed:
                return JSONResponse(
                    status_code=503,
                    content={
                        "success": False,
                        "error": {
                            "code": "RATE_LIMIT_UNAVAILABLE",
                            "message": "Authentication is temporarily unavailable.",
                        },
                    },
                )
            return await call_next(request)

        exceeded = next(
            (
                (scope, count, scope_limit, scope_window)
                for scope, count, scope_limit, scope_window in counts
                if count > scope_limit
            ),
            None,
        )
        if exceeded is not None:
            scope, _count, scope_limit, scope_window = exceeded
            return JSONResponse(
                status_code=429,
                headers={
                    "Retry-After": str(self._retry_after(scope_window)),
                    "X-RateLimit-Limit": str(scope_limit),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Scope": scope,
                },
                content={
                    "success": False,
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": "Too many requests. Try again later.",
                    },
                },
            )

        response = await call_next(request)
        scope, count, scope_limit, _scope_window = min(
            counts,
            key=lambda item: (item[2] - item[1]) / item[2],
        )
        response.headers["X-RateLimit-Limit"] = str(scope_limit)
        response.headers["X-RateLimit-Remaining"] = str(
            max(0, scope_limit - count)
        )
        response.headers["X-RateLimit-Scope"] = scope
        return response

    def _request_limit(self, path: str) -> tuple[str, int, int]:
        if path in AUTH_PATHS:
            return (
                "auth",
                settings.rate_limit_auth_requests,
                settings.rate_limit_auth_window_seconds,
            )
        if path == READINESS_PATH:
            return (
                "readiness",
                settings.readiness_rate_limit_requests,
                settings.readiness_rate_limit_window_seconds,
            )
        return (
            "general",
            settings.rate_limit_requests,
            settings.rate_limit_window_seconds,
        )

    async def _increment(
        self,
        category: str,
        scope: str,
        identity: str,
        window: int,
    ) -> int:
        identity_hash = hashlib.sha256(identity.encode()).hexdigest()[:24]
        bucket = int(time.time()) // window
        key = f"rate:{category}:{scope}:{identity_hash}:{bucket}"
        count = await self.redis.incr(key)
        if count == 1:
            await self.redis.expire(key, window + 5)
        return count

    def _client_ip(self, request: Request) -> str:
        peer = request.client.host if request.client else "unknown"
        try:
            peer_address = ipaddress.ip_address(peer)
        except ValueError:
            return peer

        if not settings.trust_proxy_headers or not self._is_trusted_proxy(
            peer_address
        ):
            return str(peer_address)

        forwarded = request.headers.get("x-forwarded-for")
        if not forwarded:
            return str(peer_address)

        try:
            forwarded_addresses = [
                ipaddress.ip_address(item.strip())
                for item in forwarded.split(",")
                if item.strip()
            ]
        except ValueError:
            logger.warning("Ignoring malformed X-Forwarded-For header.")
            return str(peer_address)

        if not forwarded_addresses:
            return str(peer_address)

        chain = [*forwarded_addresses, peer_address]
        for address in reversed(chain):
            if not self._is_trusted_proxy(address):
                return str(address)
        return str(forwarded_addresses[0])

    def _is_trusted_proxy(
        self,
        address: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ) -> bool:
        networks: Sequence[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = self.trusted_proxy_networks
        return any(
            address.version == network.version and address in network
            for network in networks
        )

    @staticmethod
    def _authenticated_subject(request: Request) -> str | None:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return None
        try:
            payload = decode_token(token)
            if payload.get("type") != "access":
                return None
            subject = int(payload["sub"])
            if subject <= 0:
                return None
        except (InvalidTokenError, KeyError, TypeError, ValueError):
            return None
        return str(subject)

    @staticmethod
    def _retry_after(window: int) -> int:
        return window - (int(time.time()) % window)
