from alembic.config import Config
from alembic.script import ScriptDirectory

import app.models  # noqa: F401
from app.core.application import create_app
from app.core.constants import ALEMBIC_HEAD
from app.database.base import Base


def test_model_metadata_contains_identity_tables() -> None:
    assert {
        "users",
        "user_sessions",
        "roles",
        "permissions",
        "user_roles",
        "role_permissions",
        "projects",
        "project_members",
        "investigations",
        "investigation_tasks",
        "evidence_sources",
        "evidence",
        "entities",
        "entity_relations",
        "collection_jobs",
        "search_runs",
        "analysis_jobs",
        "audit_events",
        "knowledge_documents",
        "knowledge_chunks",
    } <= set(Base.metadata.tables)


def test_alembic_has_single_repair_head() -> None:
    scripts = ScriptDirectory.from_config(Config("alembic.ini"))
    assert scripts.get_heads() == [ALEMBIC_HEAD]


def test_lifecycle_routes_are_registered() -> None:
    paths = set(create_app().openapi()["paths"])

    assert "/api/v1/users/me/password" in paths
    assert "/api/v1/users/{user_id}/password/reset" in paths
    assert "/api/v1/users/{user_id}/activate" in paths
    assert "/api/v1/users/{user_id}/deactivate" in paths
    assert "/api/v1/users/{user_id}/restore" in paths
    assert "/api/v1/health/ready" in paths
    assert "/api/v1/projects" in paths
    assert "/api/v1/projects/{project_id}/investigations" in paths
    assert "/api/v1/investigations/{investigation_id}/evidence" in paths
    assert (
        "/api/v1/investigations/{investigation_id}/collection-jobs"
        in paths
    )
    assert "/api/v1/investigations/{investigation_id}/analysis-jobs" in paths
    assert "/api/v1/investigations/{investigation_id}/search-runs" in paths
    assert "/api/v1/search-runs/{run_id}" in paths
    assert "/api/v1/investigations/{investigation_id}/report" in paths
    assert "/api/v1/projects/{project_id}/soc-knowledge/documents" in paths
    assert "/api/v1/projects/{project_id}/soc-knowledge/query" in paths
