from time import perf_counter

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


class TimerMiddleware(BaseHTTPMiddleware):
    """
    Middleware que mide el tiempo de procesamiento
    de cada petición HTTP.
    """

    async def dispatch(
        self,
        request: Request,
        call_next,
    ) -> Response:

        start = perf_counter()

        response = await call_next(request)

        elapsed = perf_counter() - start

        response.headers["X-Process-Time"] = f"{elapsed:.6f}s"

        return response
