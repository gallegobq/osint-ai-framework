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
        return self.user_repository.get_permission_codes(user_id)

    def has_permission(
        self,
        user_id: int,
        permission_code: str,
    ) -> bool:
        return self.user_repository.has_permission(
            user_id,
            permission_code,
        )

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
