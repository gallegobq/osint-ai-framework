class Permissions:
    """
    Catálogo central de permisos del framework.

    Evita cadenas duplicadas y errores tipográficos en routers,
    servicios, dependencias, pruebas y procesos de inicialización.

    Los códigos son contratos persistentes del sistema. Una vez utilizados
    en la base de datos, no deben renombrarse sin una migración explícita.
    """

    class Users:
        """
        Permisos relacionados con la gestión del ciclo de vida de usuarios.
        """

        CREATE = "users:create"

        LIST = "users:list"
        READ = "users:read"
        READ_DELETED = "users:read_deleted"

        UPDATE = "users:update"

        CHANGE_OWN_PASSWORD = "users:change_own_password"
        RESET_PASSWORD = "users:reset_password"

        ACTIVATE = "users:activate"
        DEACTIVATE = "users:deactivate"

        DELETE = "users:delete"
        RESTORE = "users:restore"

    class Roles:
        """
        Permisos relacionados con la administración de roles.
        """

        CREATE = "roles:create"
        READ = "roles:read"
        UPDATE = "roles:update"
        DELETE = "roles:delete"

    class Permissions:
        """
        Permisos relacionados con la administración del catálogo de permisos.
        """

        CREATE = "permissions:create"
        READ = "permissions:read"
        UPDATE = "permissions:update"
        DELETE = "permissions:delete"

    class Projects:
        CREATE = "projects:create"
        LIST = "projects:list"
        READ = "projects:read"
        UPDATE = "projects:update"
        MANAGE_MEMBERS = "projects:manage_members"

    class Investigations:
        CREATE = "investigations:create"
        READ = "investigations:read"
        UPDATE = "investigations:update"

    class Evidence:
        CREATE = "evidence:create"
        READ = "evidence:read"
        UPDATE = "evidence:update"

    class Collection:
        EXECUTE = "collection:execute"
        EXECUTE_ACTIVE = "collection:execute_active"
        READ = "collection:read"

    class Analysis:
        EXECUTE = "analysis:execute"
        READ = "analysis:read"

    class Knowledge:
        INGEST = "knowledge:ingest"
        READ = "knowledge:read"
        QUERY = "knowledge:query"

    class Reports:
        READ = "reports:read"

    class Findings:
        CREATE = "findings:create"
        READ = "findings:read"
        UPDATE = "findings:update"

    class Schedules:
        CREATE = "schedules:create"
        READ = "schedules:read"
        UPDATE = "schedules:update"

    class Governance:
        MANAGE_RETENTION = "governance:manage_retention"
