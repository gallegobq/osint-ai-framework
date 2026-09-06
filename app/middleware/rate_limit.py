import hashlib
import logging
import time

from redis.asyncio import Redis
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.settings import settings


logger = logging.getLogger("osint.rate_limit")
AUTH_PATHS = {"/api/v1/auth/login", "/api/v1/auth/token", "/api/v1/auth/refresh"}


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self.redis = Redis.from_url(settings.redis_url, decode_responses=True)

    async def dispatch(self, request: Request, call_next) -> Response:
        if not settings.rate_limit_enabled or request.url.path in {
            "/api/v1/health",
            "/api/v1/health/ready",
        }:
            return await call_next(request)

        auth_request = request.url.path in AUTH_PATHS
        limit = (
            settings.rate_limit_auth_requests
            if auth_request
            else settings.rate_limit_requests
        )
        window = (
            settings.rate_limit_auth_window_seconds
            if auth_request
            else settings.rate_limit_window_seconds
        )
        client = request.client.host if request.client else "unknown"
        client_hash = hashlib.sha256(client.encode()).hexdigest()[:24]
        category = "auth" if auth_request else "general"
        bucket = int(time.time()) // window
        key = f"rate:{category}:{client_hash}:{bucket}"
        try:
            count = await self.redis.incr(key)
            if count == 1:
                await self.redis.expire(key, window + 5)
        except Exception:
            logger.exception("Rate-limit backend unavailable.")
            if auth_request and settings.rate_limit_fail_closed:
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

        if count > limit:
            return JSONResponse(
                status_code=429,
                headers={"Retry-After": str(window)},
                content={
                    "success": False,
                    "error": {
                        "code": "RATE_LIMITED",
                        "message": "Too many requests. Try again later.",
                    },
                },
            )
        response = await call_next(request)
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - count))
        return response
