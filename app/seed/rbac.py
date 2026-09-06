from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.permissions import Permissions
from app.core.settings import settings
from app.database.session import SessionLocal
from app.models.permission import Permission
from app.models.role import Role
from app.models.role_permission import RolePermission
from app.models.user import User
from app.models.user_role import UserRole
from app.repositories.permission_repository import PermissionRepository
from app.repositories.role_permission_repository import (
    RolePermissionRepository,
)
from app.repositories.role_repository import RoleRepository
from app.repositories.user_role_repository import UserRoleRepository


ADMIN_ROLE_NAME = "Administrator"


DEFAULT_PERMISSIONS = [
    {
        "code": Permissions.Users.CREATE,
        "resource": "users",
        "action": "create",
        "description": "Crear usuarios.",
    },
    {
        "code": Permissions.Users.LIST,
        "resource": "users",
        "action": "list",
        "description": "Listar usuarios con paginación, filtros y búsqueda.",
    },
    {
        "code": Permissions.Users.READ,
        "resource": "users",
        "action": "read",
        "description": "Consultar un usuario.",
    },
    {
        "code": Permissions.Users.READ_DELETED,
        "resource": "users",
        "action": "read_deleted",
        "description": "Consultar usuarios eliminados lógicamente.",
    },
    {
        "code": Permissions.Users.UPDATE,
        "resource": "users",
        "action": "update",
        "description": "Modificar los datos permitidos de un usuario.",
    },
    {
        "code": Permissions.Users.CHANGE_OWN_PASSWORD,
        "resource": "users",
        "action": "change_own_password",
        "description": "Cambiar la contraseña de la cuenta propia.",
    },
    {
        "code": Permissions.Users.RESET_PASSWORD,
        "resource": "users",
        "action": "reset_password",
        "description": "Restablecer administrativamente la contraseña de un usuario.",
    },
    {
        "code": Permissions.Users.ACTIVATE,
        "resource": "users",
        "action": "activate",
        "description": "Activar un usuario desactivado.",
    },
    {
        "code": Permissions.Users.DEACTIVATE,
        "resource": "users",
        "action": "deactivate",
        "description": "Desactivar un usuario activo.",
    },
    {
        "code": Permissions.Users.DELETE,
        "resource": "users",
        "action": "delete",
        "description": "Eliminar lógicamente un usuario.",
    },
    {
        "code": Permissions.Users.RESTORE,
        "resource": "users",
        "action": "restore",
        "description": "Restaurar un usuario eliminado lógicamente.",
    },
    {
        "code": Permissions.Roles.CREATE,
        "resource": "roles",
        "action": "create",
        "description": "Crear roles.",
    },
    {
        "code": Permissions.Roles.READ,
        "resource": "roles",
        "action": "read",
        "description": "Consultar roles.",
    },
    {
        "code": Permissions.Roles.UPDATE,
        "resource": "roles",
        "action": "update",
        "description": "Modificar roles.",
    },
    {
        "code": Permissions.Roles.DELETE,
        "resource": "roles",
        "action": "delete",
        "description": "Eliminar roles.",
    },
    {
        "code": Permissions.Permissions.CREATE,
        "resource": "permissions",
        "action": "create",
        "description": "Crear permisos.",
    },
    {
        "code": Permissions.Permissions.READ,
        "resource": "permissions",
        "action": "read",
        "description": "Consultar permisos.",
    },
    {
        "code": Permissions.Permissions.UPDATE,
        "resource": "permissions",
        "action": "update",
        "description": "Modificar permisos.",
    },
    {
        "code": Permissions.Permissions.DELETE,
        "resource": "permissions",
        "action": "delete",
        "description": "Eliminar permisos.",
    },
    {
        "code": Permissions.Projects.CREATE,
        "resource": "projects",
        "action": "create",
        "description": "Crear proyectos.",
    },
    {
        "code": Permissions.Projects.LIST,
        "resource": "projects",
        "action": "list",
        "description": "Listar proyectos accesibles.",
    },
    {
        "code": Permissions.Projects.READ,
        "resource": "projects",
        "action": "read",
        "description": "Consultar proyectos accesibles.",
    },
    {
        "code": Permissions.Projects.UPDATE,
        "resource": "projects",
        "action": "update",
        "description": "Modificar proyectos accesibles.",
    },
    {
        "code": Permissions.Projects.MANAGE_MEMBERS,
        "resource": "projects",
        "action": "manage_members",
        "description": "Administrar miembros de proyectos.",
    },
    {
        "code": Permissions.Investigations.CREATE,
        "resource": "investigations",
        "action": "create",
        "description": "Crear investigaciones.",
    },
    {
        "code": Permissions.Investigations.READ,
        "resource": "investigations",
        "action": "read",
        "description": "Consultar investigaciones y tareas.",
    },
    {
        "code": Permissions.Investigations.UPDATE,
        "resource": "investigations",
        "action": "update",
        "description": "Modificar investigaciones y tareas.",
    },
    {
        "code": Permissions.Evidence.CREATE,
        "resource": "evidence",
        "action": "create",
        "description": "Incorporar evidencia con procedencia.",
    },
    {
        "code": Permissions.Evidence.READ,
        "resource": "evidence",
        "action": "read",
        "description": "Consultar evidencia, entidades y relaciones.",
    },
    {
        "code": Permissions.Evidence.UPDATE,
        "resource": "evidence",
        "action": "update",
        "description": "Gestionar entidades y relaciones.",
    },
    {
        "code": Permissions.Collection.EXECUTE,
        "resource": "collection",
        "action": "execute",
        "description": "Ejecutar colectores OSINT aprobados.",
    },
    {
        "code": Permissions.Collection.EXECUTE_ACTIVE,
        "resource": "collection",
        "action": "execute_active",
        "description": "Ejecutar validaciones activas aprobadas en el sandbox SOC.",
    },
    {
        "code": Permissions.Collection.READ,
        "resource": "collection",
        "action": "read",
        "description": "Consultar trabajos de recolección.",
    },
    {
        "code": Permissions.Analysis.EXECUTE,
        "resource": "analysis",
        "action": "execute",
        "description": "Ejecutar análisis sobre evidencia.",
    },
    {
        "code": Permissions.Analysis.READ,
        "resource": "analysis",
        "action": "read",
        "description": "Consultar resultados de análisis.",
    },
    {
        "code": Permissions.Knowledge.INGEST,
        "resource": "knowledge",
        "action": "ingest",
        "description": "Incorporar conocimiento SOC trazable al RAG de Linterna.",
    },
    {
        "code": Permissions.Knowledge.READ,
        "resource": "knowledge",
        "action": "read",
        "description": "Consultar el catálogo de conocimiento SOC del proyecto.",
    },
    {
        "code": Permissions.Knowledge.QUERY,
        "resource": "knowledge",
        "action": "query",
        "description": "Consultar Linterna con recuperación y citas SOC.",
    },
    {
        "code": Permissions.Reports.READ,
        "resource": "reports",
        "action": "read",
        "description": "Generar y consultar reportes de investigación.",
    },
    {
        "code": Permissions.Findings.CREATE,
        "resource": "findings",
        "action": "create",
        "description": "Crear hallazgos SOC trazables.",
    },
    {
        "code": Permissions.Findings.READ,
        "resource": "findings",
        "action": "read",
        "description": "Consultar hallazgos SOC.",
    },
    {
        "code": Permissions.Findings.UPDATE,
        "resource": "findings",
        "action": "update",
        "description": "Gestionar severidad y ciclo de vida de hallazgos.",
    },
    {
        "code": Permissions.Schedules.CREATE,
        "resource": "schedules",
        "action": "create",
        "description": "Crear búsquedas pasivas programadas.",
    },
    {
        "code": Permissions.Schedules.READ,
        "resource": "schedules",
        "action": "read",
        "description": "Consultar búsquedas programadas.",
    },
    {
        "code": Permissions.Schedules.UPDATE,
        "resource": "schedules",
        "action": "update",
        "description": "Modificar o deshabilitar búsquedas programadas.",
    },
    {
        "code": Permissions.Governance.MANAGE_RETENTION,
        "resource": "governance",
        "action": "manage_retention",
        "description": "Gestionar retención y legal hold como owner del proyecto.",
    },
]


def get_bootstrap_user(
    db: Session,
    username: str,
) -> User | None:
    """
    Return the explicitly configured active bootstrap administrator.
    """
    statement = (
        select(User)
        .where(
            User.username == username,
            User.deleted_at.is_(None),
            User.is_active.is_(True),
        )
        .limit(1)
    )

    return db.scalar(statement)


def seed_rbac() -> None:
    """
    Create the system RBAC catalog and administrator assignments.

    The operation is idempotent: existing roles, permissions and assignments
    are reused instead of duplicated.
    """
    db = SessionLocal()

    try:
        role_repository = RoleRepository(db)
        permission_repository = PermissionRepository(db)
        user_role_repository = UserRoleRepository(db)
        role_permission_repository = RolePermissionRepository(db)

        administrator_role = role_repository.get_by_name(
            ADMIN_ROLE_NAME
        )

        if administrator_role is None:
            administrator_role = Role(
                name=ADMIN_ROLE_NAME,
                description="Rol administrativo principal del sistema.",
                is_system=True,
            )
            db.add(administrator_role)
            db.flush()

            print(
                f"Rol creado: {administrator_role.name}"
            )
        else:
            print(
                f"Rol existente: {administrator_role.name}"
            )

        permissions: list[Permission] = []

        for permission_data in DEFAULT_PERMISSIONS:
            permission = permission_repository.get_by_code(
                permission_data["code"]
            )

            if permission is None:
                permission = Permission(
                    code=permission_data["code"],
                    resource=permission_data["resource"],
                    action=permission_data["action"],
                    description=permission_data["description"],
                    is_system=True,
                )

                db.add(permission)
                db.flush()

                print(
                    f"Permiso creado: {permission.code}"
                )
            else:
                print(
                    f"Permiso existente: {permission.code}"
                )

            permissions.append(permission)

        for permission in permissions:
            role_permission = (
                role_permission_repository
                .get_by_role_and_permission(
                    role_id=administrator_role.id,
                    permission_id=permission.id,
                )
            )

            if role_permission is None:
                db.add(
                    RolePermission(
                        role_id=administrator_role.id,
                        permission_id=permission.id,
                    )
                )

                print(
                    "Permiso asignado: "
                    f"{administrator_role.name} "
                    f"-> {permission.code}"
                )
            else:
                print(
                    "Asignación existente: "
                    f"{administrator_role.name} "
                    f"-> {permission.code}"
                )

        bootstrap_username = settings.initial_admin_username
        bootstrap_user = (
            get_bootstrap_user(db, bootstrap_username)
            if bootstrap_username
            else None
        )

        if bootstrap_user is None:
            print(
                "No active INITIAL_ADMIN_USERNAME was configured. "
                "Administrator was not assigned."
            )
        else:
            user_role = user_role_repository.get_by_user_and_role(
                user_id=bootstrap_user.id,
                role_id=administrator_role.id,
            )

            if user_role is None:
                db.add(
                    UserRole(
                        user_id=bootstrap_user.id,
                        role_id=administrator_role.id,
                    )
                )

                print(
                    "Rol asignado: "
                    f"{bootstrap_user.username} "
                    f"-> {administrator_role.name}"
                )
            else:
                print(
                    "Asignación existente: "
                    f"{bootstrap_user.username} "
                    f"-> {administrator_role.name}"
                )

        db.commit()

        print("Seeder RBAC completado correctamente.")

    except Exception:
        db.rollback()
        print("Error ejecutando el seeder RBAC.")
        raise

    finally:
        db.close()


if __name__ == "__main__":
    seed_rbac()
