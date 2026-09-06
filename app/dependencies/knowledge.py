from typing import Annotated

from fastapi import Depends
from sqlalchemy.orm import Session

from app.core.container import build_audit_service, build_project_service
from app.dependencies.database import get_db
from app.llm.factory import build_llm_provider
from app.repositories.knowledge_repository import (
    KnowledgeChunkRepository,
    KnowledgeDocumentRepository,
)
from app.services.knowledge_service import KnowledgeService


def get_knowledge_service(
    db: Annotated[Session, Depends(get_db)],
) -> KnowledgeService:
    return KnowledgeService(
        documents=KnowledgeDocumentRepository(db),
        chunks=KnowledgeChunkRepository(db),
        projects=build_project_service(db),
        audit=build_audit_service(db),
        provider=build_llm_provider(),
    )

