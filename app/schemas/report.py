from datetime import datetime

from pydantic import BaseModel

from app.schemas.evidence import (
    EntityRead,
    EntityRelationRead,
    EvidenceRead,
)
from app.schemas.investigation import InvestigationRead
from app.schemas.job import AnalysisJobRead


class InvestigationReport(BaseModel):
    generated_at: datetime
    investigation: InvestigationRead
    evidence: list[EvidenceRead]
    entities: list[EntityRead]
    relations: list[EntityRelationRead]
    analyses: list[AnalysisJobRead]
    warnings: list[str]
