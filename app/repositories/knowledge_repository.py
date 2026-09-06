from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.knowledge import KnowledgeChunk, KnowledgeDocument
from app.repositories.base_repository import BaseRepository


class KnowledgeDocumentRepository(BaseRepository[KnowledgeDocument]):
    def __init__(self, db: Session):
        super().__init__(KnowledgeDocument, db)

    def get_by_hash(
        self, project_id: int, content_hash: str
    ) -> KnowledgeDocument | None:
        return self.db.scalar(
            select(KnowledgeDocument).where(
                KnowledgeDocument.project_id == project_id,
                KnowledgeDocument.content_hash == content_hash,
            )
        )

    def list_by_project(self, project_id: int) -> list[KnowledgeDocument]:
        statement = (
            select(KnowledgeDocument)
            .where(KnowledgeDocument.project_id == project_id)
            .order_by(
                KnowledgeDocument.updated_at.desc(),
                KnowledgeDocument.id.desc(),
            )
        )
        return list(self.db.scalars(statement).all())


class KnowledgeChunkRepository(BaseRepository[KnowledgeChunk]):
    def __init__(self, db: Session):
        super().__init__(KnowledgeChunk, db)

    def count_by_project(self, project_id: int) -> int:
        return int(
            self.db.scalar(
                select(func.count(KnowledgeChunk.id)).where(
                    KnowledgeChunk.project_id == project_id
                )
            )
            or 0
        )

    def list_by_project(
        self, project_id: int, *, limit: int
    ) -> list[KnowledgeChunk]:
        statement = (
            select(KnowledgeChunk)
            .options(joinedload(KnowledgeChunk.document))
            .where(KnowledgeChunk.project_id == project_id)
            .order_by(KnowledgeChunk.id.asc())
            .limit(limit)
        )
        return list(self.db.scalars(statement).all())

