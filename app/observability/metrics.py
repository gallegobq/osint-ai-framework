from collections import defaultdict
from threading import Lock
from time import perf_counter

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_lock = Lock()
_requests: dict[tuple[str, str, int], int] = defaultdict(int)
_duration_count: dict[tuple[str, str], int] = defaultdict(int)
_duration_sum: dict[tuple[str, str], float] = defaultdict(float)


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        started = perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            method = request.method
            elapsed = perf_counter() - started
            with _lock:
                _requests[(method, route_path, status_code)] += 1
                _duration_count[(method, route_path)] += 1
                _duration_sum[(method, route_path)] += elapsed


def render_prometheus() -> str:
    lines = [
        "# HELP osint_http_requests_total Total HTTP requests.",
        "# TYPE osint_http_requests_total counter",
    ]
    with _lock:
        for (method, route, status), count in sorted(_requests.items()):
            lines.append(
                "osint_http_requests_total"
                f'{{method="{method}",route="{route}",status="{status}"}} {count}'
            )
        lines.extend(
            [
                "# HELP osint_http_request_duration_seconds Request duration.",
                "# TYPE osint_http_request_duration_seconds summary",
            ]
        )
        for (method, route), count in sorted(_duration_count.items()):
            labels = f'method="{method}",route="{route}"'
            lines.append(
                f"osint_http_request_duration_seconds_count{{{labels}}} {count}"
            )
            lines.append(
                "osint_http_request_duration_seconds_sum"
                f"{{{labels}}} {_duration_sum[(method, route)]:.9f}"
            )
    return "\n".join(lines) + "\n"
