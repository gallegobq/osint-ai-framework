from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_evidence_service
from app.dependencies.database import get_db
from app.services.evidence_service import EvidenceService


def get_evidence_service(
    db: Annotated[Session, Depends(get_db)],
) -> EvidenceService:
    return build_evidence_service(db)
