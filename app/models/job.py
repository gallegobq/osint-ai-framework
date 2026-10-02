from datetime import datetime

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base_model import BaseModel


class CollectionJob(BaseModel):
    __tablename__ = "collection_jobs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name="ck_collection_jobs_status",
        ),
        CheckConstraint("attempts >= 0", name="ck_collection_jobs_attempts"),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    search_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("search_runs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    input_discovery_id: Mapped[int | None] = mapped_column(
        ForeignKey(
            "search_discoveries.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_collection_jobs_input_discovery_id",
        ),
        nullable=True,
        index=True,
    )
    collector: Mapped[str] = mapped_column(String(50), nullable=False)
    query: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", index=True
    )
    attempts: Mapped[int] = mapped_column(nullable=False, default=0)
    result_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation = relationship("Investigation")
    requested_by = relationship("User")
    search_run = relationship("SearchRun", back_populates="collection_jobs")


class SearchRun(BaseModel):
    __tablename__ = "search_runs"
    __table_args__ = (
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'partial', 'failed')",
            name="ck_search_runs_status",
        ),
        CheckConstraint("max_tools >= 1", name="ck_search_runs_max_tools"),
        CheckConstraint(
            "profile IN ('auto', 'passive', 'footprint', 'investigate', 'all')",
            name="ck_search_runs_profile",
        ),
        CheckConstraint(
            "discovery_max_depth >= 1 AND discovery_max_depth <= 3",
            name="ck_search_runs_discovery_max_depth",
        ),
        CheckConstraint(
            "discovery_max_events >= 1 AND discovery_max_events <= 100",
            name="ck_search_runs_discovery_max_events",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    targets: Mapped[list] = mapped_column(JSON, nullable=False)
    profile: Mapped[str] = mapped_column(
        String(20), nullable=False, default="auto", index=True
    )
    max_tools: Mapped[int] = mapped_column(Integer, nullable=False)
    allow_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    follow_discoveries: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    discovery_max_depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1
    )
    discovery_max_events: Mapped[int] = mapped_column(
        Integer, nullable=False, default=25
    )
    policy: Mapped[dict] = mapped_column(JSON, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", index=True
    )
    planner: Mapped[str | None] = mapped_column(String(50), nullable=True)
    plan: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result_summary: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation = relationship("Investigation")
    requested_by = relationship("User")
    collection_jobs = relationship("CollectionJob", back_populates="search_run")
    discoveries = relationship(
        "SearchDiscovery",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class SearchDiscovery(BaseModel):
    __tablename__ = "search_discoveries"
    __table_args__ = (
        UniqueConstraint(
            "search_run_id",
            "target_type",
            "value_hash",
            name="uq_search_discoveries_identity",
        ),
        CheckConstraint(
            "target_type IN ('domain', 'hostname', 'ip', 'asn', 'url', "
            "'username', 'email', 'hash', 'cve', 'keyword')",
            name="ck_search_discoveries_target_type",
        ),
        CheckConstraint(
            "min_depth >= 0 AND min_depth <= 4",
            name="ck_search_discoveries_min_depth",
        ),
    )

    search_run_id: Mapped[int] = mapped_column(
        ForeignKey("search_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    target_value: Mapped[str] = mapped_column(Text, nullable=False)
    value_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    min_depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )


class SearchDiscoveryEdge(BaseModel):
    __tablename__ = "search_discovery_edges"
    __table_args__ = (
        UniqueConstraint(
            "search_run_id",
            "edge_hash",
            name="uq_search_discovery_edges_identity",
        ),
        CheckConstraint(
            "depth >= 0 AND depth <= 4",
            name="ck_search_discovery_edges_depth",
        ),
    )

    search_run_id: Mapped[int] = mapped_column(
        ForeignKey("search_runs.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    parent_discovery_id: Mapped[int | None] = mapped_column(
        ForeignKey("search_discoveries.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    child_discovery_id: Mapped[int] = mapped_column(
        ForeignKey("search_discoveries.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    collection_job_id: Mapped[int | None] = mapped_column(
        ForeignKey("collection_jobs.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    evidence_id: Mapped[int | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    relation: Mapped[str] = mapped_column(String(100), nullable=False)
    depth: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, index=True
    )
    edge_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )


class AnalysisJob(BaseModel):
    __tablename__ = "analysis_jobs"
    __table_args__ = (
        CheckConstraint(
            "analysis_type IN ('summary', 'entities', 'relations', 'sentiment')",
            name="ck_analysis_jobs_type",
        ),
        CheckConstraint(
            "status IN ('queued', 'running', 'succeeded', 'failed')",
            name="ck_analysis_jobs_status",
        ),
    )

    investigation_id: Mapped[int] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requested_by_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    analysis_type: Mapped[str] = mapped_column(String(30), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    prompt_version: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="queued", index=True
    )
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    completed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    investigation = relationship("Investigation")
    requested_by = relationship("User")
