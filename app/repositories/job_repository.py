import hashlib
import json
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.models.job import (
    AnalysisJob,
    CollectionJob,
    SearchDiscovery,
    SearchDiscoveryEdge,
    SearchRun,
)
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


class SearchDiscoveryRepository(BaseRepository[SearchDiscovery]):
    def __init__(self, db: Session):
        super().__init__(SearchDiscovery, db)

    def get_or_create(
        self,
        *,
        search_run_id: int,
        target_type: str,
        target_value: str,
        depth: int,
    ) -> tuple[SearchDiscovery, bool, bool]:
        value_hash = hashlib.sha256(target_value.encode("utf-8")).hexdigest()
        existing = self.db.scalar(
            select(SearchDiscovery).where(
                SearchDiscovery.search_run_id == search_run_id,
                SearchDiscovery.target_type == target_type,
                SearchDiscovery.value_hash == value_hash,
            )
        )
        if existing is not None:
            depth_lowered = depth < existing.min_depth
            if existing.target_value != target_value:
                raise RuntimeError("Discovery identity hash collision.")
            if depth_lowered:
                existing.min_depth = depth
                self.db.flush()
            return existing, False, depth_lowered
        return (
            self.create(
                SearchDiscovery(
                    search_run_id=search_run_id,
                    target_type=target_type,
                    target_value=target_value,
                    value_hash=value_hash,
                    min_depth=depth,
                )
            ),
            True,
            False,
        )

    def add_edge(
        self,
        *,
        search_run_id: int,
        parent_discovery_id: int | None,
        child_discovery_id: int,
        collection_job_id: int | None,
        evidence_id: int | None,
        relation: str,
        depth: int,
    ) -> tuple[SearchDiscoveryEdge, bool]:
        identity = {
            "child_discovery_id": child_discovery_id,
            "collection_job_id": collection_job_id,
            "depth": depth,
            "evidence_id": evidence_id,
            "parent_discovery_id": parent_discovery_id,
            "relation": relation,
            "search_run_id": search_run_id,
        }
        edge_hash = hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode(
                "utf-8"
            )
        ).hexdigest()
        existing = self.db.scalar(
            select(SearchDiscoveryEdge).where(
                SearchDiscoveryEdge.search_run_id == search_run_id,
                SearchDiscoveryEdge.edge_hash == edge_hash,
            )
        )
        if existing is not None:
            return existing, False
        edge = SearchDiscoveryEdge(edge_hash=edge_hash, **identity)
        self.db.add(edge)
        self.db.flush()
        self.db.refresh(edge)
        return edge, True

    def list_nodes(self, search_run_id: int) -> list[SearchDiscovery]:
        statement = (
            select(SearchDiscovery)
            .where(SearchDiscovery.search_run_id == search_run_id)
            .order_by(
                SearchDiscovery.min_depth.asc(),
                SearchDiscovery.target_type.asc(),
                SearchDiscovery.target_value.asc(),
                SearchDiscovery.id.asc(),
            )
        )
        return list(self.db.scalars(statement).all())

    def list_edges(self, search_run_id: int) -> list[SearchDiscoveryEdge]:
        statement = (
            select(SearchDiscoveryEdge)
            .where(SearchDiscoveryEdge.search_run_id == search_run_id)
            .order_by(
                SearchDiscoveryEdge.depth.asc(),
                SearchDiscoveryEdge.id.asc(),
            )
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
