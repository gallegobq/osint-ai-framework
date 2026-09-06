from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.evidence import Entity, EntityRelation
from app.repositories.base_repository import BaseRepository


class EntityRepository(BaseRepository[Entity]):
    def __init__(self, db: Session):
        super().__init__(Entity, db)

    def list_by_investigation(self, investigation_id: int) -> list[Entity]:
        statement = (
            select(Entity)
            .where(Entity.investigation_id == investigation_id)
            .order_by(Entity.canonical_name.asc(), Entity.id.asc())
        )
        return list(self.db.scalars(statement).all())

    def get_by_identity(
        self,
        investigation_id: int,
        entity_type: str,
        canonical_name: str,
    ) -> Entity | None:
        return self.db.scalar(
            select(Entity).where(
                Entity.investigation_id == investigation_id,
                Entity.entity_type == entity_type,
                Entity.canonical_name == canonical_name,
            )
        )


class EntityRelationRepository(BaseRepository[EntityRelation]):
    def __init__(self, db: Session):
        super().__init__(EntityRelation, db)

    def list_by_investigation(
        self,
        investigation_id: int,
    ) -> list[EntityRelation]:
        statement = (
            select(EntityRelation)
            .where(EntityRelation.investigation_id == investigation_id)
            .order_by(EntityRelation.id.asc())
        )
        return list(self.db.scalars(statement).all())
