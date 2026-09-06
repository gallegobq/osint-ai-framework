from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.user_role import UserRole
from app.repositories.base_repository import BaseRepository
from app.schemas.user_query import SortOrder
from app.schemas.user_query import UserListQuery
from app.schemas.user_query import UserSortField


class UserRepository(BaseRepository[User]):
    """
    Acceso persistente a usuarios.

    Las reglas de negocio no pertenecen a este repositorio. Esta clase
    construye y ejecuta consultas, mientras que UserService decidirá cuándo
    una operación está permitida.
    """

    def __init__(self, db: Session):
        super().__init__(User, db)

    def get_by_email(
        self,
        email: str,
    ) -> User | None:
        """
        Return a user by exact email, including soft-deleted users.

        Deleted users remain relevant for uniqueness validation because their
        email values continue protected by the database unique constraint.
        """
        statement = select(User).where(
            User.email == email
        )

        return self.db.scalar(statement)

    def get_by_username(
        self,
        username: str,
    ) -> User | None:
        """
        Return a user by exact username, including soft-deleted users.

        Deleted users remain relevant for uniqueness validation because their
        usernames continue protected by the database unique constraint.
        """
        statement = select(User).where(
            User.username == username
        )

        return self.db.scalar(statement)

    def get_first_active_superuser(self) -> User | None:
        """Return the oldest active, non-deleted superuser, if one exists."""
        statement = (
            select(User)
            .where(
                User.is_superuser.is_(True),
                User.is_active.is_(True),
                User.deleted_at.is_(None),
            )
            .order_by(User.id.asc())
            .limit(1)
        )

        return self.db.scalar(statement)

    def get_by_id(
        self,
        user_id: int,
    ) -> User | None:
        """
        Return a non-deleted user by identifier.

        This is the safe default lookup for normal application operations.
        """
        statement = select(User).where(
            User.id == user_id,
            User.deleted_at.is_(None),
        )

        return self.db.scalar(statement)

    def get_by_id_including_deleted(
        self,
        user_id: int,
    ) -> User | None:
        """
        Return a user regardless of soft-deletion status.

        This method must only be used by explicit administrative use cases,
        such as restoration or authorized retrieval of deleted users.
        """
        statement = select(User).where(
            User.id == user_id
        )

        return self.db.scalar(statement)

    def list_users(
        self,
        query: UserListQuery,
    ) -> tuple[list[User], int]:
        """
        Return a filtered and paginated user collection and its total count.

        The count is calculated before applying offset and limit, allowing the
        service layer to build pagination metadata.
        """
        filters = self._build_list_filters(query)

        count_statement = (
            select(func.count(User.id))
            .select_from(User)
            .where(*filters)
        )

        total_items = self.db.scalar(count_statement) or 0

        sort_column = self._get_sort_column(query.sort_by)

        if query.sort_order == SortOrder.DESC:
            ordering = sort_column.desc()
        else:
            ordering = sort_column.asc()

        statement = (
            select(User)
            .where(*filters)
            .order_by(
                ordering,
                User.id.asc(),
            )
            .offset(query.offset)
            .limit(query.page_size)
        )

        users = list(
            self.db.scalars(statement).all()
        )

        return users, total_items

    @staticmethod
    def _build_list_filters(
        query: UserListQuery,
    ) -> list:
        """
        Build SQLAlchemy predicates from validated query parameters.

        Returning predicates separately ensures that the data query and count
        query always use exactly the same filters.
        """
        filters = []

        if query.is_deleted:
            filters.append(
                User.deleted_at.is_not(None)
            )
        else:
            filters.append(
                User.deleted_at.is_(None)
            )

        if query.is_active is not None:
            filters.append(
                User.is_active.is_(query.is_active)
            )

        if query.search is not None:
            search_pattern = (
                f"%{UserRepository._escape_like(query.search)}%"
            )

            filters.append(
                or_(
                    User.username.ilike(
                        search_pattern,
                        escape="\\",
                    ),
                    User.email.ilike(
                        search_pattern,
                        escape="\\",
                    ),
                )
            )

        if query.role_id is not None:
            role_exists = (
                select(UserRole.id)
                .where(
                    UserRole.user_id == User.id,
                    UserRole.role_id == query.role_id,
                )
                .exists()
            )

            filters.append(role_exists)

        if query.created_from is not None:
            filters.append(
                User.created_at >= query.created_from
            )

        if query.created_to is not None:
            filters.append(
                User.created_at <= query.created_to
            )

        return filters

    @staticmethod
    def _get_sort_column(
        sort_field: UserSortField,
    ):
        """
        Resolve an allowed sorting field to its mapped SQLAlchemy column.

        This explicit mapping prevents clients from selecting arbitrary model
        attributes or database expressions.
        """
        sort_columns = {
            UserSortField.ID: User.id,
            UserSortField.USERNAME: User.username,
            UserSortField.EMAIL: User.email,
            UserSortField.IS_ACTIVE: User.is_active,
            UserSortField.CREATED_AT: User.created_at,
            UserSortField.UPDATED_AT: User.updated_at,
            UserSortField.PASSWORD_CHANGED_AT: (
                User.password_changed_at
            ),
            UserSortField.DELETED_AT: User.deleted_at,
        }

        return sort_columns[sort_field]

    @staticmethod
    def _escape_like(value: str) -> str:
        """
        Escape SQL LIKE wildcard characters.

        User-provided '%' and '_' are treated as literal characters rather
        than search wildcards. SQLAlchemy still binds the value as a query
        parameter, so this is semantic escaping rather than SQL-injection
        protection.
        """
        return (
            value
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )
