from sqlalchemy.exc import IntegrityError

from app.core.exceptions import (
    ConflictException,
    NotFoundException,
)

from app.models.role import Role

from app.repositories.role_repository import RoleRepository

from app.schemas.role import (
    RoleCreate,
    RoleRead,
    RoleUpdate,
)

from app.services.base_service import BaseService
from app.repositories.user_role_repository import UserRoleRepository

class RoleService(BaseService[RoleRead]):
    """
    Lógica de negocio para la administración de roles.
    """

    def __init__(
            self,
            repository: RoleRepository,
            user_role_repository: UserRoleRepository,
        ):
            self.repository = repository
            self.user_role_repository = user_role_repository

    def create_role(
        self,
        data: RoleCreate,
    ) -> RoleRead:

        if self.repository.get_by_name(data.name):
            raise ConflictException(
                "Role already exists."
            )

        role = Role(
            name=data.name,
            description=data.description,
            is_system=False,
        )

        try:

            self.repository.create(role)
            self.repository.commit()

            return self.to_schema(
                RoleRead,
                role,
            )

        except IntegrityError:

            self.repository.rollback()

            raise ConflictException(
                "Database integrity error."
            )

    def get_role(
        self,
        role_id: int,
    ) -> RoleRead:

        role = self.repository.get_by_id(role_id)

        if role is None:
            raise NotFoundException("Role")

        return self.to_schema(
            RoleRead,
            role,
        )

    def list_roles(
        self,
    ) -> list[RoleRead]:

        roles = self.repository.get_all()

        return self.to_schema_list(
            RoleRead,
            roles,
        )

    def update_role(
        self,
        role_id: int,
        data: RoleUpdate,
    ) -> RoleRead:
    
        role = self.repository.get_by_id(role_id)
    
        if role is None:
            raise NotFoundException("Role")
    
        if role.is_system:
            raise ConflictException(
                "System roles cannot be modified."
            )
    
        if (
            data.name is not None
            and data.name != role.name
        ):
            existing = self.repository.get_by_name(
                data.name,
            )
    
            if existing is not None:
                raise ConflictException(
                    "Role already exists."
                )
    
            role.name = data.name
    
        if data.description is not None:
            role.description = data.description
    
        try:
            self.repository.commit()
    
            return self.to_schema(
                RoleRead,
                role,
            )
    
        except IntegrityError:
            self.repository.rollback()
    
            raise ConflictException(
                "Database integrity error."
            )

    def delete_role(
                    self,
                    role_id: int,
                ) -> None:
                
                    role = self.repository.get_by_id(role_id)
                
                    if role is None:
                        raise NotFoundException("Role")
                
                    if role.is_system:
                        raise ConflictException(
                            "System roles cannot be deleted."
                        )
                
                    assignments = self.user_role_repository.get_by_role_id(
                        role_id,
                    )
                
                    if assignments:
                        raise ConflictException(
                            "Role cannot be deleted because it is assigned to users."
                        )
                
                    try:
                        self.repository.delete(role)
                        self.repository.commit()
                
                    except IntegrityError:
                        self.repository.rollback()
                
                        raise ConflictException(
                            "Role cannot be deleted because it is in use."
                        )
