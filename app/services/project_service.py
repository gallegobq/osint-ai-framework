from sqlalchemy.exc import IntegrityError

from app.core.exceptions import ConflictException, ForbiddenException
from app.core.exceptions import NotFoundException
from app.models.project import Project, ProjectMember
from app.models.user import User
from app.repositories.project_repository import (
    ProjectMemberRepository,
    ProjectRepository,
)
from app.repositories.user_repository import UserRepository
from app.schemas.project import (
    ProjectCreate,
    ProjectMemberAssign,
    ProjectMemberRead,
    ProjectMemberRole,
    ProjectRead,
    ProjectUpdate,
)
from app.services.audit_service import AuditService


ACCESS_LEVEL = {
    ProjectMemberRole.VIEWER.value: 1,
    ProjectMemberRole.EDITOR.value: 2,
    ProjectMemberRole.OWNER.value: 3,
}


class ProjectService:
    def __init__(
        self,
        project_repository: ProjectRepository,
        member_repository: ProjectMemberRepository,
        user_repository: UserRepository,
        audit_service: AuditService,
    ):
        self.projects = project_repository
        self.members = member_repository
        self.users = user_repository
        self.audit = audit_service

    def create(self, actor: User, data: ProjectCreate) -> ProjectRead:
        if self.projects.get_by_slug(data.slug) is not None:
            raise ConflictException("Project slug already exists.")

        project = Project(
            name=data.name,
            slug=data.slug,
            description=data.description,
            status="active",
            owner_id=actor.id,
        )

        try:
            self.projects.create(project)
            self.members.create(
                ProjectMember(
                    project_id=project.id,
                    user_id=actor.id,
                    role=ProjectMemberRole.OWNER.value,
                )
            )
            self.audit.record(
                actor_user_id=actor.id,
                action="projects.create",
                resource_type="project",
                resource_id=project.id,
            )
            self.projects.commit()
        except IntegrityError as exc:
            self.projects.rollback()
            raise ConflictException("Could not create project.") from exc

        return ProjectRead.model_validate(project)

    def list_for_user(self, actor: User) -> list[ProjectRead]:
        projects = (
            self.projects.get_all()
            if actor.is_superuser
            else self.projects.list_for_user(actor.id)
        )
        return [ProjectRead.model_validate(item) for item in projects]

    def get(
        self,
        actor: User,
        project_id: int,
        *,
        minimum_role: ProjectMemberRole = ProjectMemberRole.VIEWER,
    ) -> Project:
        project = self.projects.get_by_id(project_id)
        if project is None:
            raise NotFoundException("Project")

        self.require_access(actor, project, minimum_role)
        return project

    def update(
        self,
        actor: User,
        project_id: int,
        data: ProjectUpdate,
    ) -> ProjectRead:
        project = self.get(
            actor,
            project_id,
            minimum_role=ProjectMemberRole.EDITOR,
        )

        for field, value in data.model_dump(exclude_unset=True).items():
            setattr(project, field, value)

        self.audit.record(
            actor_user_id=actor.id,
            action="projects.update",
            resource_type="project",
            resource_id=project.id,
            data={"fields": sorted(data.model_fields_set)},
        )
        self.projects.commit()
        return ProjectRead.model_validate(project)

    def list_members(
        self,
        actor: User,
        project_id: int,
    ) -> list[ProjectMemberRead]:
        self.get(actor, project_id)
        return [
            ProjectMemberRead.model_validate(member)
            for member in self.members.list_by_project(project_id)
        ]

    def add_member(
        self,
        actor: User,
        project_id: int,
        data: ProjectMemberAssign,
    ) -> ProjectMemberRead:
        project = self.get(
            actor,
            project_id,
            minimum_role=ProjectMemberRole.OWNER,
        )

        if data.role == ProjectMemberRole.OWNER:
            raise ConflictException(
                "Ownership transfer is not supported by this operation."
            )

        user = self.users.get_by_id(data.user_id)
        if user is None or not user.is_active:
            raise NotFoundException("Active user")

        if self.members.get_assignment(project.id, user.id) is not None:
            raise ConflictException("User is already a project member.")

        member = self.members.create(
            ProjectMember(
                project_id=project.id,
                user_id=user.id,
                role=data.role.value,
            )
        )
        self.audit.record(
            actor_user_id=actor.id,
            action="projects.members.add",
            resource_type="project",
            resource_id=project.id,
            data={"user_id": user.id, "role": data.role.value},
        )
        self.projects.commit()
        return ProjectMemberRead.model_validate(member)

    def remove_member(
        self,
        actor: User,
        project_id: int,
        user_id: int,
    ) -> None:
        project = self.get(
            actor,
            project_id,
            minimum_role=ProjectMemberRole.OWNER,
        )
        if project.owner_id == user_id:
            raise ConflictException("The project owner cannot be removed.")

        member = self.members.get_assignment(project.id, user_id)
        if member is None:
            raise NotFoundException("Project member")

        self.members.delete(member)
        self.audit.record(
            actor_user_id=actor.id,
            action="projects.members.remove",
            resource_type="project",
            resource_id=project.id,
            data={"user_id": user_id},
        )
        self.projects.commit()

    def require_access(
        self,
        actor: User,
        project: Project,
        minimum_role: ProjectMemberRole,
    ) -> None:
        if actor.is_superuser or project.owner_id == actor.id:
            return

        member = self.members.get_assignment(project.id, actor.id)
        current_level = ACCESS_LEVEL.get(member.role, 0) if member else 0
        required_level = ACCESS_LEVEL[minimum_role.value]

        if current_level < required_level:
            raise ForbiddenException()

    def is_member(self, project: Project, user_id: int) -> bool:
        return (
            project.owner_id == user_id
            or self.members.get_assignment(project.id, user_id) is not None
        )
