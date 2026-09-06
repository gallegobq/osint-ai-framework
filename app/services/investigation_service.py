from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.exceptions import ConflictException, NotFoundException
from app.models.investigation import Investigation, InvestigationTask
from app.models.user import User
from app.repositories.investigation_repository import InvestigationRepository
from app.repositories.task_repository import TaskRepository
from app.repositories.user_repository import UserRepository
from app.schemas.investigation import (
    InvestigationCreate,
    InvestigationRead,
    InvestigationStatus,
    InvestigationTaskCreate,
    InvestigationTaskRead,
    InvestigationTaskUpdate,
    InvestigationUpdate,
    RetentionPolicyUpdate,
    TaskStatus,
)
from app.schemas.project import ProjectMemberRole
from app.services.audit_service import AuditService
from app.services.project_service import ProjectService
from app.core.exceptions import BadRequestException
from app.core.settings import settings


STATUS_TRANSITIONS = {
    "draft": {"active", "archived"},
    "active": {"paused", "completed", "archived"},
    "paused": {"active", "completed", "archived"},
    "completed": {"active", "archived"},
    "archived": set(),
}


class InvestigationService:
    def __init__(
        self,
        repository: InvestigationRepository,
        task_repository: TaskRepository,
        user_repository: UserRepository,
        project_service: ProjectService,
        audit_service: AuditService,
    ):
        self.repository = repository
        self.tasks = task_repository
        self.users = user_repository
        self.projects = project_service
        self.audit = audit_service

    def create(
        self,
        actor: User,
        project_id: int,
        data: InvestigationCreate,
    ) -> InvestigationRead:
        self.projects.get(
            actor,
            project_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        if settings.require_legal_metadata and (
            not (data.jurisdiction or "").strip()
            or not (data.legal_basis or "").strip()
        ):
            raise BadRequestException(
                "Jurisdiction and legal basis are required by deployment policy."
            )
        retention_until = data.retention_until or (
            datetime.now(timezone.utc)
            + timedelta(days=settings.default_retention_days)
        )
        investigation = Investigation(
            project_id=project_id,
            created_by_id=actor.id,
            title=data.title,
            description=data.description,
            kind=data.kind.value,
            priority=data.priority.value,
            operation_mode=data.operation_mode.value,
            authorization_scope=data.authorization_scope,
            active_testing_authorized=data.active_testing_authorized,
            engagement_start_at=data.engagement_start_at,
            engagement_end_at=data.engagement_end_at,
            jurisdiction=(data.jurisdiction or "").strip() or None,
            legal_basis=(data.legal_basis or "").strip() or None,
            data_classification=data.data_classification.value,
            retention_until=retention_until,
            legal_hold=False,
            status=InvestigationStatus.DRAFT.value,
        )
        self.repository.create(investigation)
        self.audit.record(
            actor_user_id=actor.id,
            action="investigations.create",
            resource_type="investigation",
            resource_id=investigation.id,
            data={
                "project_id": project_id,
                "operation_mode": data.operation_mode.value,
                "active_testing_authorized": data.active_testing_authorized,
            },
        )
        self.repository.commit()
        return InvestigationRead.model_validate(investigation)

    def list(
        self,
        actor: User,
        project_id: int,
    ) -> list[InvestigationRead]:
        self.projects.get(actor, project_id)
        return [
            InvestigationRead.model_validate(item)
            for item in self.repository.list_by_project(project_id)
        ]

    def get_model(
        self,
        actor: User,
        investigation_id: int,
        *,
        minimum_role: ProjectMemberRole = ProjectMemberRole.VIEWER,
    ) -> Investigation:
        investigation = self.repository.get_by_id(investigation_id)
        if investigation is None:
            raise NotFoundException("Investigation")
        self.projects.get(
            actor,
            investigation.project_id,
            minimum_role=minimum_role,
        )
        return investigation

    def get(self, actor: User, investigation_id: int) -> InvestigationRead:
        return InvestigationRead.model_validate(
            self.get_model(actor, investigation_id)
        )

    def update(
        self,
        actor: User,
        investigation_id: int,
        data: InvestigationUpdate,
    ) -> InvestigationRead:
        investigation = self.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        values = data.model_dump(exclude_unset=True)
        new_status = values.get("status")

        if new_status is not None:
            new_status = new_status.value
            if new_status != investigation.status and new_status not in (
                STATUS_TRANSITIONS[investigation.status]
            ):
                raise ConflictException(
                    "Invalid investigation status transition."
                )
            values["status"] = new_status

        if values.get("priority") is not None:
            values["priority"] = values["priority"].value
        if values.get("data_classification") is not None:
            values["data_classification"] = values["data_classification"].value
        for text_field in ("jurisdiction", "legal_basis"):
            if values.get(text_field) is not None:
                values[text_field] = values[text_field].strip() or None
        if settings.require_legal_metadata:
            jurisdiction = values.get("jurisdiction", investigation.jurisdiction)
            legal_basis = values.get("legal_basis", investigation.legal_basis)
            if not jurisdiction or not legal_basis:
                raise BadRequestException(
                    "Jurisdiction and legal basis are required by deployment policy."
                )

        for field, value in values.items():
            setattr(investigation, field, value)

        self.audit.record(
            actor_user_id=actor.id,
            action="investigations.update",
            resource_type="investigation",
            resource_id=investigation.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.repository.commit()
        return InvestigationRead.model_validate(investigation)

    def create_task(
        self,
        actor: User,
        investigation_id: int,
        data: InvestigationTaskCreate,
    ) -> InvestigationTaskRead:
        investigation = self.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        self._validate_assignee(investigation.project, data.assignee_id)
        task = InvestigationTask(
            investigation_id=investigation.id,
            title=data.title,
            description=data.description,
            priority=data.priority.value,
            assignee_id=data.assignee_id,
            due_at=data.due_at,
            status=TaskStatus.TODO.value,
        )
        self.tasks.create(task)
        self.audit.record(
            actor_user_id=actor.id,
            action="investigations.tasks.create",
            resource_type="investigation_task",
            resource_id=task.id,
            data={"investigation_id": investigation.id},
        )
        self.repository.commit()
        return InvestigationTaskRead.model_validate(task)

    def update_retention(
        self,
        actor: User,
        investigation_id: int,
        data: RetentionPolicyUpdate,
    ) -> InvestigationRead:
        investigation = self.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.OWNER,
        )
        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(investigation, field, value)
        self.audit.record(
            actor_user_id=actor.id,
            action="investigations.retention.update",
            resource_type="investigation",
            resource_id=investigation.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.repository.commit()
        return InvestigationRead.model_validate(investigation)

    def list_tasks(
        self,
        actor: User,
        investigation_id: int,
    ) -> list[InvestigationTaskRead]:
        self.get_model(actor, investigation_id)
        return [
            InvestigationTaskRead.model_validate(task)
            for task in self.tasks.list_by_investigation(investigation_id)
        ]

    def update_task(
        self,
        actor: User,
        investigation_id: int,
        task_id: int,
        data: InvestigationTaskUpdate,
    ) -> InvestigationTaskRead:
        investigation = self.get_model(
            actor,
            investigation_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )
        task = self.tasks.get_by_id(task_id)
        if task is None or task.investigation_id != investigation.id:
            raise NotFoundException("Investigation task")

        values = data.model_dump(exclude_unset=True)
        if "assignee_id" in values:
            self._validate_assignee(investigation.project, values["assignee_id"])
        if values.get("priority") is not None:
            values["priority"] = values["priority"].value
        if values.get("status") is not None:
            values["status"] = values["status"].value

        for field, value in values.items():
            setattr(task, field, value)

        if task.status == TaskStatus.DONE.value and task.completed_at is None:
            task.completed_at = datetime.now(timezone.utc)
        elif task.status != TaskStatus.DONE.value:
            task.completed_at = None

        self.audit.record(
            actor_user_id=actor.id,
            action="investigations.tasks.update",
            resource_type="investigation_task",
            resource_id=task.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.repository.commit()
        return InvestigationTaskRead.model_validate(task)

    def _validate_assignee(self, project, user_id: int | None) -> None:
        if user_id is None:
            return
        user = self.users.get_by_id(user_id)
        if (
            user is None
            or not user.is_active
            or not self.projects.is_member(project, user.id)
        ):
            raise ConflictException(
                "Task assignee must be an active project member."
            )
