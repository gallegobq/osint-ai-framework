from datetime import datetime, timezone
from unittest.mock import Mock

from app.models.role import Role
from app.models.user import User
from app.schemas.role import RoleCreate
from app.services.role_service import RoleService
from app.services.user_role_service import UserRoleService


def test_role_creation_and_audit_are_committed_together() -> None:
    roles = Mock()
    assignments = Mock()
    audit = Mock()
    roles.get_by_name.return_value = None
    def create(role: Role) -> Role:
        role.id = 3
        role.created_at = datetime.now(timezone.utc)
        role.updated_at = role.created_at
        return role

    roles.create.side_effect = create
    service = RoleService(roles, assignments, audit)

    service.create_role(
        RoleCreate(name="Reviewer", description="Reviews findings"),
        actor_user_id=1,
    )

    audit.record.assert_called_once()
    roles.commit.assert_called_once()


def test_user_role_assignment_and_audit_are_committed_together() -> None:
    users = Mock()
    roles = Mock()
    assignments = Mock()
    audit = Mock()
    users.get_by_id.return_value = User(id=7, username="user", email="u@e.test")
    roles.get_by_id.return_value = Role(id=4, name="Reviewer")
    assignments.get_by_user_and_role.return_value = None
    service = UserRoleService(users, roles, assignments, audit)

    service.assign_role(user_id=7, role_id=4, actor_user_id=1)

    audit.record.assert_called_once()
    assignments.commit.assert_called_once()
