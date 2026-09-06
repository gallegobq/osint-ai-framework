from datetime import datetime

from sqlalchemy import case, select
from sqlalchemy.orm import Session

from app.models.soc import Finding, SearchSchedule
from app.repositories.base_repository import BaseRepository


class FindingRepository(BaseRepository[Finding]):
    def __init__(self, db: Session):
        super().__init__(Finding, db)

    def list_by_investigation(self, investigation_id: int) -> list[Finding]:
        statement = (
            select(Finding)
            .where(Finding.investigation_id == investigation_id)
            .order_by(
                case(
                    (Finding.severity == "critical", 5),
                    (Finding.severity == "high", 4),
                    (Finding.severity == "medium", 3),
                    (Finding.severity == "low", 2),
                    else_=1,
                ).desc(),
                Finding.created_at.desc(),
            )
        )
        return list(self.db.scalars(statement).all())


class SearchScheduleRepository(BaseRepository[SearchSchedule]):
    def __init__(self, db: Session):
        super().__init__(SearchSchedule, db)

    def list_by_investigation(
        self, investigation_id: int
    ) -> list[SearchSchedule]:
        statement = (
            select(SearchSchedule)
            .where(SearchSchedule.investigation_id == investigation_id)
            .order_by(SearchSchedule.created_at.desc())
        )
        return list(self.db.scalars(statement).all())

    def list_due(self, now: datetime, *, limit: int = 25) -> list[SearchSchedule]:
        statement = (
            select(SearchSchedule)
            .where(
                SearchSchedule.enabled.is_(True),
                SearchSchedule.next_run_at <= now,
            )
            .order_by(SearchSchedule.next_run_at.asc())
            .limit(limit)
        )
        return list(self.db.scalars(statement).all())
