from pathlib import Path

import yaml
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
        "search_discoveries",
        "search_discovery_edges",
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
        "/api/v1/investigations/{investigation_id}/evidence/"
        "{evidence_id}/integrity"
        in paths
    )
    assert (
        "/api/v1/investigations/{investigation_id}/collection-jobs"
        in paths
    )
    assert "/api/v1/investigations/{investigation_id}/analysis-jobs" in paths
    assert "/api/v1/investigations/{investigation_id}/search-runs" in paths
    assert "/api/v1/investigations/{investigation_id}/chat" in paths
    assert "/api/v1/search-profiles" in paths
    assert "/api/v1/collectors/benchmark" in paths
    assert "/api/v1/search-runs/{run_id}" in paths
    assert "/api/v1/search-runs/{run_id}/discoveries" in paths
    assert "/api/v1/investigations/{investigation_id}/report" in paths
    assert "/api/v1/projects/{project_id}/soc-knowledge/documents" in paths
    assert "/api/v1/projects/{project_id}/soc-knowledge/query" in paths


def test_standalone_release_matches_documented_local_http_transport() -> None:
    release = yaml.safe_load(
        Path("docker-compose.release.yml").read_text(encoding="utf-8")
    )
    environment = release["services"]["api"]["environment"]

    assert environment["AUTH_COOKIE_SECURE"] == "false"
    assert environment["TRUST_PROXY_HEADERS"] == "false"
