from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.reports import get_report_service
from app.dependencies.soc_exports import get_soc_export_service
from app.models.user import User
from app.schemas.report import InvestigationReport
from app.services.report_service import ReportService
from app.services.soc_export_service import SocExportService


router = APIRouter(prefix="/investigations", tags=["Reports"])


@router.get("/{investigation_id}/report", response_model=InvestigationReport)
def get_report(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Reports.READ)),
    ],
    service: Annotated[ReportService, Depends(get_report_service)],
) -> InvestigationReport:
    return service.build(current_user, investigation_id)


@router.get(
    "/{investigation_id}/report.md",
    response_class=PlainTextResponse,
)
def get_markdown_report(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Reports.READ)),
    ],
    service: Annotated[ReportService, Depends(get_report_service)],
) -> str:
    return service.render_markdown(
        service.build(current_user, investigation_id)
    )


@router.get("/{investigation_id}/report.stix.json")
def get_stix_report(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Reports.READ)),
    ],
    service: Annotated[SocExportService, Depends(get_soc_export_service)],
) -> JSONResponse:
    return JSONResponse(
        service.build_stix(current_user, investigation_id),
        media_type="application/stix+json",
        headers={
            "Content-Disposition": (
                f'attachment; filename="investigation-{investigation_id}.stix.json"'
            )
        },
    )


@router.get("/{investigation_id}/report.ndjson")
def get_siem_ndjson_report(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Reports.READ)),
    ],
    service: Annotated[SocExportService, Depends(get_soc_export_service)],
) -> Response:
    return Response(
        service.build_ndjson(current_user, investigation_id),
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": (
                f'attachment; filename="investigation-{investigation_id}.ndjson"'
            )
        },
    )


@router.get("/{investigation_id}/report.cef")
def get_siem_cef_report(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Reports.READ)),
    ],
    service: Annotated[SocExportService, Depends(get_soc_export_service)],
) -> PlainTextResponse:
    return PlainTextResponse(
        service.build_cef(current_user, investigation_id),
        headers={
            "Content-Disposition": (
                f'attachment; filename="investigation-{investigation_id}.cef"'
            )
        },
    )
