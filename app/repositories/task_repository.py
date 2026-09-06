from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationTask
from app.repositories.base_repository import BaseRepository


class TaskRepository(BaseRepository[InvestigationTask]):
    def __init__(self, db: Session):
        super().__init__(InvestigationTask, db)

    def list_by_investigation(
        self,
        investigation_id: int,
    ) -> list[InvestigationTask]:
        statement = (
            select(InvestigationTask)
            .where(
                InvestigationTask.investigation_id == investigation_id
            )
            .order_by(InvestigationTask.created_at.asc())
        )
        return list(self.db.scalars(statement).all())
