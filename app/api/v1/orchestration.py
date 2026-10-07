from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.auth.authorization import get_authorization_service
from app.core.exceptions import ForbiddenException
from app.core.permissions import Permissions
from app.dependencies.orchestration import get_orchestration_service
from app.models.user import User
from app.osint.profiles import scan_profile_catalog
from app.schemas.orchestration import (
    ScanProfileRead,
    SearchDiscoveryGraphRead,
    SearchRunCreate,
    SearchRunRead,
    ChatSearchCreate,
    ChatSearchRead,
)
from app.services.orchestration_service import OrchestrationService
from app.services.authorization_service import AuthorizationService


router = APIRouter(tags=["OSINT Orchestration"])


@router.post("/investigations/{investigation_id}/chat", response_model=ChatSearchRead)
def chat_search(
    investigation_id: int,
    data: ChatSearchCreate,
    current_user: Annotated[User, Depends(require_permission(Permissions.Collection.EXECUTE))],
    service: Annotated[OrchestrationService, Depends(get_orchestration_service)],
) -> ChatSearchRead:
    return service.chat(current_user, investigation_id, data)


@router.get("/search-profiles", response_model=list[ScanProfileRead])
def list_search_profiles(
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
) -> list[ScanProfileRead]:
    del current_user
    return [
        ScanProfileRead.model_validate(item)
        for item in scan_profile_catalog()
    ]


@router.post(
    "/investigations/{investigation_id}/search-runs",
    response_model=SearchRunRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_search_run(
    investigation_id: int,
    data: SearchRunCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.EXECUTE)),
    ],
    authorization: Annotated[
        AuthorizationService,
        Depends(get_authorization_service),
    ],
    service: Annotated[
        OrchestrationService,
        Depends(get_orchestration_service),
    ],
) -> SearchRunRead:
    if (
        data.allow_active
        and not current_user.is_superuser
        and not authorization.has_permission(
            current_user.id,
            Permissions.Collection.EXECUTE_ACTIVE,
        )
    ):
        raise ForbiddenException()
    return service.create(current_user, investigation_id, data)


@router.get(
    "/investigations/{investigation_id}/search-runs",
    response_model=list[SearchRunRead],
)
def list_search_runs(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        OrchestrationService,
        Depends(get_orchestration_service),
    ],
) -> list[SearchRunRead]:
    return service.list(current_user, investigation_id)


@router.get("/search-runs/{run_id}", response_model=SearchRunRead)
def get_search_run(
    run_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        OrchestrationService,
        Depends(get_orchestration_service),
    ],
) -> SearchRunRead:
    return service.get(current_user, run_id)


@router.get(
    "/search-runs/{run_id}/discoveries",
    response_model=SearchDiscoveryGraphRead,
)
def get_search_discovery_graph(
    run_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        OrchestrationService,
        Depends(get_orchestration_service),
    ],
) -> SearchDiscoveryGraphRead:
    return service.discovery_graph(current_user, run_id)
