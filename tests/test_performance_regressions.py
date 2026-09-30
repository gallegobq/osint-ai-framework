import json
import urllib.error
from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql

from app.repositories.evidence_repository import EvidenceRepository
from app.repositories.user_repository import UserRepository
from app.services.authorization_service import AuthorizationService
from scripts import load_test


def _postgres_sql(statement) -> str:
    return str(
        statement.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


def test_permission_check_uses_one_exists_query() -> None:
    db = Mock()
    db.scalar.return_value = True
    repository = UserRepository(db)

    assert repository.has_permission(12, "evidence:read") is True

    db.scalar.assert_called_once()
    sql = _postgres_sql(db.scalar.call_args.args[0])
    assert "EXISTS" in sql
    assert "user_roles" in sql
    assert "role_permissions" in sql
    assert "permissions" in sql


def test_authorization_service_does_not_load_the_rbac_graph() -> None:
    repository = Mock()
    repository.has_permission.return_value = True
    service = AuthorizationService(repository)

    assert service.has_permission(12, "evidence:read") is True

    repository.has_permission.assert_called_once_with(
        12,
        "evidence:read",
    )
    repository.get_by_id.assert_not_called()


def test_evidence_listing_eager_loads_source() -> None:
    db = Mock()
    db.scalars.return_value.all.return_value = []
    repository = EvidenceRepository(db)

    assert repository.list_by_investigation(7) == []

    db.scalars.assert_called_once()
    sql = _postgres_sql(db.scalars.call_args.args[0])
    assert "LEFT OUTER JOIN evidence_sources" in sql


def test_load_test_defaults_to_ipv4_loopback() -> None:
    args = load_test.build_parser().parse_args([])

    assert args.url == "http://127.0.0.1:8000/api/v1/health"


def test_load_test_preserves_http_error_status(monkeypatch) -> None:
    error = urllib.error.HTTPError(
        load_test.DEFAULT_URL,
        429,
        "Too Many Requests",
        {},
        None,
    )
    error.read = Mock(return_value=b"")
    monkeypatch.setattr(
        load_test.urllib.request,
        "urlopen",
        Mock(side_effect=error),
    )

    _, status = load_test.request_once(load_test.DEFAULT_URL, None)

    assert status == 429
    error.read.assert_called_once_with()


def test_percentile_uses_nearest_rank() -> None:
    assert load_test.percentile([1, 2, 3, 4, 100], 0.95) == 100
    with pytest.raises(ValueError):
        load_test.percentile([1], 0)


def test_load_test_writes_reproducible_json(monkeypatch, tmp_path) -> None:
    def fake_run_batch(url, token, requests, concurrency):
        assert url.startswith("http://127.0.0.1")
        assert token is None
        assert requests == 4
        assert concurrency == 2
        return [(0.01, 200)] * requests, 0.04

    monkeypatch.setattr(load_test, "run_batch", fake_run_batch)
    output = tmp_path / "benchmark.json"

    result = load_test.main(
        [
            "--requests",
            "4",
            "--concurrency",
            "2",
            "--warmup",
            "0",
            "--repetitions",
            "2",
            "--json-output",
            str(output),
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert result == 0
    assert payload["schema_version"] == 1
    assert payload["aggregate"]["requests"] == 8
    assert payload["aggregate"]["median_p95_ms"] == pytest.approx(10)
