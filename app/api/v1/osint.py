from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.collection import get_collection_service
from app.models.user import User
from app.schemas.job import CollectionJobCreate, CollectionJobRead
from app.services.collection_service import CollectionService


router = APIRouter(tags=["OSINT Collection"])


@router.get("/collectors")
def list_collectors(
    _current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        CollectionService,
        Depends(get_collection_service),
    ],
) -> list[dict[str, object]]:
    return service.available_collectors()


@router.post(
    "/investigations/{investigation_id}/collection-jobs",
    response_model=CollectionJobRead,
    status_code=status.HTTP_202_ACCEPTED,
)
def create_collection_job(
    investigation_id: int,
    data: CollectionJobCreate,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.EXECUTE)),
    ],
    service: Annotated[
        CollectionService,
        Depends(get_collection_service),
    ],
) -> CollectionJobRead:
    return service.create(current_user, investigation_id, data)


@router.get(
    "/investigations/{investigation_id}/collection-jobs",
    response_model=list[CollectionJobRead],
)
def list_collection_jobs(
    investigation_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        CollectionService,
        Depends(get_collection_service),
    ],
) -> list[CollectionJobRead]:
    return service.list(current_user, investigation_id)


@router.get("/collection-jobs/{job_id}", response_model=CollectionJobRead)
def get_collection_job(
    job_id: int,
    current_user: Annotated[
        User,
        Depends(require_permission(Permissions.Collection.READ)),
    ],
    service: Annotated[
        CollectionService,
        Depends(get_collection_service),
    ],
) -> CollectionJobRead:
    return service.get(current_user, job_id)
