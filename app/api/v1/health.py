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
    result = service.readiness()

    if result["status"] == "not_ready":
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return result


@router.get("/metrics", response_class=PlainTextResponse)
def metrics(
    authorization: Annotated[str | None, Header()] = None,
) -> PlainTextResponse:
    if not settings.metrics_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    token = settings.metrics_token
    if token is not None and token.get_secret_value().strip():
        supplied = (authorization or "").removeprefix("Bearer ")
        if not hmac.compare_digest(supplied, token.get_secret_value()):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return PlainTextResponse(
        render_prometheus(), media_type="text/plain; version=0.0.4"
    )
