from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.router import api_router
from app.core.handlers import register_exception_handlers
from app.middleware.timing import TimerMiddleware
from app.middleware.cors import register_cors
from app.middleware.logging import RequestContextMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.observability.metrics import MetricsMiddleware
from app.core.settings import settings
from app.core.logger import configure_logging


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """
    Gestiona el ciclo de vida de la aplicación.

    El código anterior a `yield` se ejecuta al iniciar.
    El código posterior a `yield` se ejecuta al apagar.
    """

    # ===============================
    # Startup
    # ===============================

    yield

    # ===============================
    # Shutdown
    # ===============================


def create_app() -> FastAPI:
    """
    Construye y configura la aplicación.
    """

    configure_logging()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        lifespan=lifespan,
    )

    # ===============================
    # Middlewares
    # ===============================

    app.add_middleware(TimerMiddleware)
    app.add_middleware(MetricsMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts,
    )
    register_cors(app)

    # ===============================
    # Exception Handlers
    # ===============================

    register_exception_handlers(app)

    # ===============================
    # Routers
    # ===============================

    app.include_router(
        api_router,
        prefix="/api/v1",
    )

    # La interfaz se sirve desde el mismo origen que la API para que la
    # instalación local no necesite un segundo runtime ni configuración CORS.
    web_directory = Path(__file__).resolve().parents[1] / "web"
    app.mount(
        "/",
        StaticFiles(directory=web_directory, html=True),
        name="web",
    )

    return app
