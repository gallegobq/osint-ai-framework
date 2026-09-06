from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.project import Project, ProjectMember
from app.repositories.base_repository import BaseRepository


class ProjectRepository(BaseRepository[Project]):
    def __init__(self, db: Session):
        super().__init__(Project, db)

    def get_by_slug(self, slug: str) -> Project | None:
        return self.db.scalar(select(Project).where(Project.slug == slug))

    def list_for_user(self, user_id: int) -> list[Project]:
        statement = (
            select(Project)
            .outerjoin(
                ProjectMember,
                ProjectMember.project_id == Project.id,
            )
            .where(
                or_(
                    Project.owner_id == user_id,
                    ProjectMember.user_id == user_id,
                )
            )
            .order_by(Project.updated_at.desc(), Project.id.desc())
            .distinct()
        )
        return list(self.db.scalars(statement).all())

    def get_member(
        self,
        project_id: int,
        user_id: int,
    ) -> ProjectMember | None:
        return self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id,
            )
        )

    def list_members(self, project_id: int) -> list[ProjectMember]:
        statement = (
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id)
            .order_by(ProjectMember.created_at.asc())
        )
        return list(self.db.scalars(statement).all())


class ProjectMemberRepository(BaseRepository[ProjectMember]):
    def __init__(self, db: Session):
        super().__init__(ProjectMember, db)

    def get_assignment(
        self,
        project_id: int,
        user_id: int,
    ) -> ProjectMember | None:
        return self.db.scalar(
            select(ProjectMember).where(
                ProjectMember.project_id == project_id,
                ProjectMember.user_id == user_id,
            )
        )

    def list_by_project(self, project_id: int) -> list[ProjectMember]:
        statement = (
            select(ProjectMember)
            .where(ProjectMember.project_id == project_id)
            .order_by(ProjectMember.created_at.asc())
        )
        return list(self.db.scalars(statement).all())
