from typing import Annotated

from fastapi import APIRouter, Depends, Query, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.evidence import get_evidence_service
from app.models.user import User
from app.schemas.evidence import (
    EntityCreate,
    EntityRead,
    EntityRelationCreate,
    EntityRelationRead,
    EvidenceCreate,
    EvidenceRead,
)
from app.services.evidence_service import EvidenceService


router = APIRouter(prefix="/investigations", tags=["Evidence"])


@router.post(
    "/{investigation_id}/evidence",
    response_model=EvidenceRead,
    status_code=status.HTTP_201_CREATED,
)
def add_evidence(
    investigation_id: int,
    data: EvidenceCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.CREATE)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> EvidenceRead:
    return service.add(current_user, investigation_id, data)


@router.get("/{investigation_id}/evidence", response_model=list[EvidenceRead])
def list_evidence(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.READ)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
    kind: Annotated[str | None, Query(min_length=2, max_length=50)] = None,
    search: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 200,
) -> list[EvidenceRead]:
    return service.list(
        current_user,
        investigation_id,
        kind=kind,
        search=search,
        limit=limit,
    )


@router.post(
    "/{investigation_id}/entities",
    response_model=EntityRead,
    status_code=status.HTTP_201_CREATED,
)
def add_entity(
    investigation_id: int,
    data: EntityCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.UPDATE)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> EntityRead:
    return service.add_entity(current_user, investigation_id, data)


@router.get("/{investigation_id}/entities", response_model=list[EntityRead])
def list_entities(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.READ)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> list[EntityRead]:
    return service.list_entities(current_user, investigation_id)


@router.post(
    "/{investigation_id}/relations",
    response_model=EntityRelationRead,
    status_code=status.HTTP_201_CREATED,
)
def add_relation(
    investigation_id: int,
    data: EntityRelationCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.UPDATE)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> EntityRelationRead:
    return service.add_relation(current_user, investigation_id, data)


@router.get(
    "/{investigation_id}/relations",
    response_model=list[EntityRelationRead],
)
def list_relations(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Evidence.READ)),
    ],
    service: Annotated[EvidenceService, Depends(get_evidence_service)],
) -> list[EntityRelationRead]:
    return service.list_relations(current_user, investigation_id)
