from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.investigation import Investigation
from app.repositories.base_repository import BaseRepository


class InvestigationRepository(BaseRepository[Investigation]):
    def __init__(self, db: Session):
        super().__init__(Investigation, db)

    def list_by_project(self, project_id: int) -> list[Investigation]:
        statement = (
            select(Investigation)
            .where(Investigation.project_id == project_id)
            .order_by(Investigation.updated_at.desc(), Investigation.id.desc())
        )
        return list(self.db.scalars(statement).all())
