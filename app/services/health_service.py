import urllib.error
import urllib.request

from redis import Redis
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.constants import ALEMBIC_HEAD
from app.core.settings import settings


class HealthService:
    """Application readiness checks that do not expose infrastructure data."""

    def __init__(self, db: Session):
        self.db = db

    def database_is_ready(self) -> bool:
        try:
            self.db.execute(text("SELECT 1"))
            revision = self.db.scalar(
                text("SELECT version_num FROM alembic_version")
            )
        except SQLAlchemyError:
            return False

        return revision == ALEMBIC_HEAD

    def _redis_is_ready(self) -> bool:
        try:
            client = Redis.from_url(
                settings.redis_url,
                socket_connect_timeout=settings.readiness_timeout_seconds,
                socket_timeout=settings.readiness_timeout_seconds,
            )
            return bool(client.ping())
        except Exception:
            return False

    def _http_is_ready(self, url: str) -> bool:
        try:
            with urllib.request.urlopen(
                url, timeout=settings.readiness_timeout_seconds
            ) as response:
                return 200 <= response.status < 300
        except (OSError, urllib.error.URLError):
            return False

    def readiness(self) -> dict[str, str]:
        database = self.database_is_ready()
        redis = self._redis_is_ready()
        ollama = self._http_is_ready(f"{settings.ollama_url.rstrip('/')}/api/version")
        sandbox = (
            self._http_is_ready(f"{settings.soc_sandbox_url.rstrip('/')}/health")
            if settings.soc_sandbox_enabled
            else True
        )
        components = {
            "database": "ok" if database else "unavailable",
            "redis": "ok" if redis else "unavailable",
            "ollama": "ok" if ollama else "unavailable",
            "sandbox": "ok" if sandbox else "disabled_or_unavailable",
        }
        required_ready = database and redis
        optional_ready = ollama and sandbox
        health_status = (
            "ready"
            if required_ready and optional_ready
            else "degraded"
            if required_ready
            else "not_ready"
        )
        return {"status": health_status, **components}
