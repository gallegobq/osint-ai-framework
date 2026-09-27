from datetime import datetime, timezone
from unittest.mock import Mock

import pytest

from app.core.exceptions import ConflictException
from app.models.permission import Permission
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.schemas.permission import PermissionCreate
from app.services.permission_service import PermissionService
from app.services.role_permission_service import RolePermissionService


def _permission() -> Permission:
    return Permission(
        id=8,
        code="evidence:read",
        resource="evidence",
        action="read",
        is_system=True,
    )


def _role(*, is_system: bool = False) -> Role:
    return Role(id=4, name="Reviewer", is_system=is_system)


def _role_permission_service(
    *,
    role: Role | None = None,
    permission: Permission | None = None,
) -> tuple[RolePermissionService, Mock, Mock]:
    roles = Mock()
    permissions = Mock()
    assignments = Mock()
    audit = Mock()
    roles.get_by_id.return_value = role or _role()
    permissions.get_by_id.return_value = permission or _permission()
    assignments.get_by_role_and_permission.return_value = None
    return (
        RolePermissionService(roles, permissions, assignments, audit),
        assignments,
        audit,
    )


@pytest.mark.parametrize("operation", ["assign", "remove"])
def test_system_role_permissions_cannot_be_changed(operation: str) -> None:
    service, assignments, audit = _role_permission_service(
        role=_role(is_system=True)
    )

    with pytest.raises(ConflictException):
        if operation == "assign":
            service.assign_permission(4, 8, actor_user_id=12)
        else:
            service.remove_permission(4, 8, actor_user_id=12)

    assignments.create.assert_not_called()
    assignments.delete.assert_not_called()
    assignments.commit.assert_not_called()
    audit.record.assert_not_called()


def test_role_permission_assignment_and_audit_commit_together() -> None:
    service, assignments, audit = _role_permission_service()

    service.assign_permission(4, 8, actor_user_id=12)

    audit.record.assert_called_once_with(
        actor_user_id=12,
        action="roles.permissions.assign",
        resource_type="role",
        resource_id=4,
        data={
            "role_name": "Reviewer",
            "permission_id": 8,
            "permission_code": "evidence:read",
        },
    )
    assignments.commit.assert_called_once()


def test_role_permission_removal_and_audit_commit_together() -> None:
    service, assignments, audit = _role_permission_service()
    assignment = RolePermission(role_id=4, permission_id=8)
    assignments.get_by_role_and_permission.return_value = assignment

    service.remove_permission(4, 8, actor_user_id=12)

    assignments.delete.assert_called_once_with(assignment)
    audit.record.assert_called_once()
    assignments.commit.assert_called_once()


def test_role_permission_rolls_back_when_audit_fails() -> None:
    service, assignments, audit = _role_permission_service()
    audit.record.side_effect = RuntimeError("audit unavailable")

    with pytest.raises(RuntimeError):
        service.assign_permission(4, 8, actor_user_id=12)

    assignments.rollback.assert_called_once()
    assignments.commit.assert_not_called()


def test_custom_permission_creation_is_audited() -> None:
    repository = Mock()
    audit = Mock()
    repository.get_by_code.return_value = None
    repository.get_by_resource_and_action.return_value = None

    def create(permission: Permission) -> Permission:
        now = datetime.now(timezone.utc)
        permission.id = 21
        permission.created_at = now
        permission.updated_at = now
        return permission

    repository.create.side_effect = create
    service = PermissionService(repository, audit)

    service.create_permission(
        PermissionCreate(
            code="reports:approve",
            resource="reports",
            action="approve",
        ),
        actor_user_id=12,
    )

    audit.record.assert_called_once_with(
        actor_user_id=12,
        action="permissions.create",
        resource_type="permission",
        resource_id=21,
        data={"code": "reports:approve"},
    )
    repository.commit.assert_called_once()
