from typing import Annotated

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Response, status
from fastapi.responses import PlainTextResponse

from app.core.settings import settings
from app.dependencies.health import get_health_service
from app.services.health_service import HealthService
from app.observability.metrics import render_prometheus

router = APIRouter(tags=["Health"])


@router.get("/health")
def health():
    return {
        "status": "ok",
        "application": settings.app_name,
        "version": settings.app_version,
    }


@router.get("/health/ready")
def readiness(
    response: Response,
    service: Annotated[
        HealthService,
        Depends(get_health_service),
    ],
):
    ready = service.database_is_ready()

    if not ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if ready else "not_ready",
        "database": "ok" if ready else "unavailable",
    }


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(
    authorization: Annotated[str | None, Header()] = None,
) -> PlainTextResponse:
    token = settings.metrics_token
    if token is not None:
        supplied = (authorization or "").removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, token.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return PlainTextResponse(
        render_prometheus(), media_type="text/plain; version=0.0.4"
    )
