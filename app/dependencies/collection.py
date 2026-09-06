from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import (
    build_audit_service,
    build_investigation_service,
)
from app.dependencies.database import get_db
from app.osint.registry import CollectorRegistry
from app.repositories.job_repository import CollectionJobRepository
from app.services.collection_service import CollectionService
from app.workers.dispatcher import CeleryJobDispatcher


def get_collection_service(
    db: Annotated[Session, Depends(get_db)],
) -> CollectionService:
    return CollectionService(
        repository=CollectionJobRepository(db),
        investigations=build_investigation_service(db),
        audit_service=build_audit_service(db),
        registry=CollectorRegistry(),
        dispatcher=CeleryJobDispatcher(),
    )
