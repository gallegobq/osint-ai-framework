from sqlalchemy import select
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
