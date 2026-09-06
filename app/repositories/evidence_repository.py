import hashlib

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.evidence import Evidence, EvidenceSource
from app.repositories.base_repository import BaseRepository


class EvidenceRepository(BaseRepository[Evidence]):
    def __init__(self, db: Session):
        super().__init__(Evidence, db)

    def list_by_investigation(
        self,
        investigation_id: int,
        *,
        kind: str | None = None,
        search: str | None = None,
        limit: int = 200,
    ) -> list[Evidence]:
        statement = select(Evidence).where(
            Evidence.investigation_id == investigation_id
        )
        if kind is not None:
            statement = statement.where(Evidence.kind == kind)
        if search is not None:
            escaped = (
                search.replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_")
            )
            pattern = f"%{escaped}%"
            statement = statement.where(
                or_(
                    Evidence.title.ilike(pattern, escape="\\"),
                    Evidence.content.ilike(pattern, escape="\\"),
                )
            )
        statement = statement.order_by(
            Evidence.collected_at.desc(), Evidence.id.desc()
        ).limit(limit)
        return list(self.db.scalars(statement).all())

    def get_by_hash(
        self,
        investigation_id: int,
        content_hash: str,
    ) -> Evidence | None:
        return self.db.scalar(
            select(Evidence).where(
                Evidence.investigation_id == investigation_id,
                Evidence.content_hash == content_hash,
            )
        )


class EvidenceSourceRepository(BaseRepository[EvidenceSource]):
    def __init__(self, db: Session):
        super().__init__(EvidenceSource, db)

    def get_by_identity(
        self,
        investigation_id: int,
        collector: str,
        locator: str,
    ) -> EvidenceSource | None:
        locator_hash = hashlib.sha256(locator.encode("utf-8")).hexdigest()
        return self.db.scalar(
            select(EvidenceSource).where(
                EvidenceSource.investigation_id == investigation_id,
                EvidenceSource.collector == collector,
                EvidenceSource.locator_hash == locator_hash,
            )
        )
