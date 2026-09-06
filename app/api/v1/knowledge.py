from typing import Annotated

from fastapi import APIRouter, Depends, status

from app.auth.authorization import require_permission
from app.core.permissions import Permissions
from app.dependencies.knowledge import get_knowledge_service
from app.models.user import User
from app.schemas.knowledge import (
    KnowledgeDocumentCreate,
    KnowledgeDocumentRead,
    RagQuery,
    RagQueryResult,
)
from app.services.knowledge_service import KnowledgeService


router = APIRouter(prefix="/projects", tags=["Linterna SOC Knowledge"])


@router.post(
    "/{project_id}/soc-knowledge/documents",
    response_model=KnowledgeDocumentRead,
    status_code=status.HTTP_201_CREATED,
)
def ingest_document(
    project_id: int,
    data: KnowledgeDocumentCreate,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Knowledge.INGEST))
    ],
    service: Annotated[KnowledgeService, Depends(get_knowledge_service)],
) -> KnowledgeDocumentRead:
    return service.ingest(current_user, project_id, data)


@router.get(
    "/{project_id}/soc-knowledge/documents",
    response_model=list[KnowledgeDocumentRead],
)
def list_documents(
    project_id: int,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Knowledge.READ))
    ],
    service: Annotated[KnowledgeService, Depends(get_knowledge_service)],
) -> list[KnowledgeDocumentRead]:
    return service.list(current_user, project_id)


@router.post(
    "/{project_id}/soc-knowledge/query",
    response_model=RagQueryResult,
)
def query_knowledge(
    project_id: int,
    data: RagQuery,
    current_user: Annotated[
        User, Depends(require_permission(Permissions.Knowledge.QUERY))
    ],
    service: Annotated[KnowledgeService, Depends(get_knowledge_service)],
) -> RagQueryResult:
    return service.query(current_user, project_id, data)

