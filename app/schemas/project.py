from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ProjectStatus(StrEnum):
    ACTIVE = "active"
    ARCHIVED = "archived"


class ProjectMemberRole(StrEnum):
    VIEWER = "viewer"
    EDITOR = "editor"
    OWNER = "owner"


class ProjectCreate(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    slug: str = Field(
        min_length=2,
        max_length=120,
        pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$",
    )
    description: str | None = Field(default=None, max_length=5000)


class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=120)
    description: str | None = Field(default=None, max_length=5000)
    status: ProjectStatus | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_non_nullable_nulls(cls, data: object) -> object:
        if isinstance(data, dict):
            invalid = {
                field
                for field in ("name", "status")
                if field in data and data[field] is None
            }
            if invalid:
                raise ValueError(
                    "The following fields cannot be null: "
                    + ", ".join(sorted(invalid))
                    + "."
                )
        return data

    @model_validator(mode="after")
    def require_change(self) -> "ProjectUpdate":
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided.")
        return self


class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    slug: str
    description: str | None
    status: ProjectStatus
    owner_id: int
    created_at: datetime
    updated_at: datetime


class ProjectMemberAssign(BaseModel):
    user_id: int = Field(gt=0)
    role: ProjectMemberRole = ProjectMemberRole.VIEWER


class ProjectMemberRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    project_id: int
    user_id: int
    role: ProjectMemberRole
    created_at: datetime
