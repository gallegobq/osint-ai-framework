from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.job import AnalysisJob, CollectionJob, SearchRun
from app.repositories.base_repository import BaseRepository


class CollectionJobRepository(BaseRepository[CollectionJob]):
    def __init__(self, db: Session):
        super().__init__(CollectionJob, db)

    def list_by_investigation(
        self,
        investigation_id: int,
    ) -> list[CollectionJob]:
        statement = (
            select(CollectionJob)
            .where(CollectionJob.investigation_id == investigation_id)
            .order_by(CollectionJob.created_at.desc())
        )
        return list(self.db.scalars(statement).all())

    def list_by_search_run(self, search_run_id: int) -> list[CollectionJob]:
        statement = (
            select(CollectionJob)
            .where(CollectionJob.search_run_id == search_run_id)
            .order_by(CollectionJob.created_at.asc())
        )
        return list(self.db.scalars(statement).all())

    def claim(self, job_id: int, now: datetime) -> bool:
        result = self.db.execute(
            update(CollectionJob)
            .where(
                CollectionJob.id == job_id,
                CollectionJob.status.in_(("queued", "failed")),
            )
            .values(
                status="running",
                attempts=CollectionJob.attempts + 1,
                started_at=now,
                completed_at=None,
                error=None,
            )
        )
        self.db.commit()
        self.db.expire_all()
        return result.rowcount == 1


class SearchRunRepository(BaseRepository[SearchRun]):
    def __init__(self, db: Session):
        super().__init__(SearchRun, db)

    def list_by_investigation(self, investigation_id: int) -> list[SearchRun]:
        statement = (
            select(SearchRun)
            .where(SearchRun.investigation_id == investigation_id)
            .order_by(SearchRun.created_at.desc())
        )
        return list(self.db.scalars(statement).all())

    def claim(self, run_id: int, now: datetime) -> bool:
        result = self.db.execute(
            update(SearchRun)
            .where(
                SearchRun.id == run_id,
                SearchRun.status.in_(("queued", "failed")),
            )
            .values(
                status="running",
                started_at=now,
                completed_at=None,
                error=None,
            )
        )
        self.db.commit()
        self.db.expire_all()
        return result.rowcount == 1


class AnalysisJobRepository(BaseRepository[AnalysisJob]):
    def __init__(self, db: Session):
        super().__init__(AnalysisJob, db)

    def list_by_investigation(
        self,
        investigation_id: int,
    ) -> list[AnalysisJob]:
        statement = (
            select(AnalysisJob)
            .where(AnalysisJob.investigation_id == investigation_id)
            .order_by(AnalysisJob.created_at.desc())
        )
        return list(self.db.scalars(statement).all())

    def claim(self, job_id: int, now: datetime) -> bool:
        result = self.db.execute(
            update(AnalysisJob)
            .where(
                AnalysisJob.id == job_id,
                AnalysisJob.status.in_(("queued", "failed")),
            )
            .values(
                status="running",
                started_at=now,
                completed_at=None,
                error=None,
            )
        )
        self.db.commit()
        self.db.expire_all()
        return result.rowcount == 1
