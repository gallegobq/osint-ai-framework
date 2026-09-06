from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_investigation_service
from app.dependencies.database import get_db
from app.repositories.entity_repository import EntityRepository
from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.soc_repository import FindingRepository
from app.services.soc_export_service import SocExportService


def get_soc_export_service(
    db: Annotated[Session, Depends(get_db)],
) -> SocExportService:
    return SocExportService(
        investigations=build_investigation_service(db),
        entities=EntityRepository(db),
        evidence=EvidenceRepository(db),
        findings=FindingRepository(db),
    )
