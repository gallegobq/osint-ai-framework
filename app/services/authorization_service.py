from app.repositories.user_repository import UserRepository


class AuthorizationService:
    """
    Servicio responsable de resolver permisos efectivos
    de un usuario.
    """

    def __init__(
        self,
        user_repository: UserRepository,
    ):
        self.user_repository = user_repository

    def get_permissions(
        self,
        user_id: int,
    ) -> set[str]:

        user = self.user_repository.get_by_id(
            user_id
        )

        if user is None:
            return set()

        permissions: set[str] = set()

        for user_role in user.role_assignments:

            role = user_role.role

            for role_permission in role.permission_assignments:

                permissions.add(
                    role_permission.permission.code
                )

        return permissions

    def has_permission(
        self,
        user_id: int,
        permission_code: str,
    ) -> bool:

        permissions = self.get_permissions(
            user_id
        )

        return permission_code in permissions

    def has_any_permission(
        self,
        user_id: int,
        permission_codes: list[str],
    ) -> bool:

        permissions = self.get_permissions(
            user_id
        )

        return any(
            permission in permissions
            for permission in permission_codes
        )

    def has_all_permissions(
        self,
        user_id: int,
        permission_codes: list[str],
    ) -> bool:

        permissions = self.get_permissions(
            user_id
        )

        return all(
            permission in permissions
            for permission in permission_codes
        )
