from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.core.exceptions import ForbiddenException, NotFoundException
from app.core.permissions import Permissions
from app.schemas.project import ProjectMemberRole
from app.services.collection_executor import CollectionExecutor
from app.services.engagement_policy import active_target_scope_status, require_active_actor


def engagement(scope="Only example.com TCP/443."):
    now = datetime.now(timezone.utc)
    return SimpleNamespace(operation_mode="pentest", active_testing_authorized=True,
                           authorization_scope=scope,
                           engagement_start_at=now - timedelta(minutes=1),
                           engagement_end_at=now + timedelta(minutes=10))


@pytest.mark.parametrize("scope", ["notexample.com", "sub.example.com", "example.com.evil.test",
                                  "a-example.com", "example.com_ignored"])
def test_scope_does_not_authorize_substrings_or_related_hosts(scope):
    target = [{"type": "domain", "value": "example.com"}]
    assert not active_target_scope_status(engagement(scope), target, "Only example.com TLS.")[0]
    assert not active_target_scope_status(engagement(), target, f"Only {scope} TLS.")[0]


@pytest.mark.parametrize("scope", ["Only example.com TCP/443.", "https://example.com/",
                                  "Hosts: EXAMPLE.COM; approved."])
def test_scope_accepts_exact_host_tokens(scope):
    assert active_target_scope_status(engagement(scope), [{"type": "domain", "value": "example.com"}], scope)[0]


@pytest.mark.parametrize("permissions", [set(), {Permissions.Collection.EXECUTE},
                                        {Permissions.Collection.EXECUTE_ACTIVE}])
def test_active_actor_requires_both_current_permissions(permissions):
    users = Mock()
    users.has_permission.side_effect = lambda uid, permission: permission in permissions
    with pytest.raises(ForbiddenException):
        require_active_actor(SimpleNamespace(id=1, is_active=True, is_superuser=False), users)


def test_inactive_superuser_cannot_act():
    with pytest.raises(ForbiddenException):
        require_active_actor(SimpleNamespace(id=1, is_active=False, is_superuser=True), Mock())


@pytest.mark.parametrize("revocation", ["permission", "membership", "scope", "window", "inactive"])
def test_worker_revalidates_before_any_active_network_action(monkeypatch, revocation):
    import app.services.collection_executor as module

    current = engagement()
    users = Mock()
    users.get_by_id.return_value = SimpleNamespace(id=1, is_active=revocation != "inactive", is_superuser=False)
    users.has_permission.return_value = revocation != "permission"
    investigations = Mock()
    investigations.get_model.return_value = current
    if revocation == "membership":
        investigations.get_model.side_effect = NotFoundException("Investigation")
    elif revocation == "scope":
        current.authorization_scope = "Only notexample.com TCP/443."
    elif revocation == "window":
        current.engagement_end_at = datetime.now(timezone.utc) - timedelta(minutes=1)
    monkeypatch.setattr(module, "build_investigation_service", Mock(return_value=investigations))
    monkeypatch.setattr(module, "build_audit_service", Mock(return_value=Mock()))
    collector = Mock(passive=False)
    registry = Mock()
    registry.get.return_value = collector
    job = SimpleNamespace(id=7, requested_by_id=1, investigation_id=3, collector="test_active",
                          query={"hostname": "example.com"}, status="queued", investigation=current,
                          search_run=SimpleNamespace(allow_active=True,
                              targets=[{"type": "domain", "value": "example.com"}],
                              policy={"authorization_confirmed": True, "scope_note": "Only example.com TCP/443."}))
    repository = Mock()
    repository.get_by_id.return_value = job
    repository.claim.return_value = True
    with pytest.raises(RuntimeError, match="Collection job execution failed"):
        CollectionExecutor(repository, users, registry).execute(7)
    collector.collect.assert_not_called()
    repository.db.expire_all.assert_called_once()
    assert job.status == "failed"
    if revocation not in {"inactive", "permission"}:
        investigations.get_model.assert_called_once_with(
            users.get_by_id.return_value, 3, minimum_role=ProjectMemberRole.EDITOR,
        )
