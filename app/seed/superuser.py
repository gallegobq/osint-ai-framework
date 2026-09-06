import argparse
import getpass

from app.database.session import SessionLocal
from app.repositories.audit_repository import AuditRepository
from app.repositories.role_repository import RoleRepository
from app.repositories.user_repository import UserRepository
from app.repositories.user_role_repository import UserRoleRepository
from app.repositories.user_session_repository import UserSessionRepository
from app.schemas.user import UserCreate
from app.services.audit_service import AuditService
from app.services.session_service import SessionService
from app.services.superuser_service import SuperuserService


def create_superuser(username: str, email: str) -> None:
    password = getpass.getpass("New administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise RuntimeError("Passwords do not match.")

    data = UserCreate(username=username, email=email, password=password)
    db = SessionLocal()
    try:
        result = SuperuserService(
            users=UserRepository(db),
            roles=RoleRepository(db),
            user_roles=UserRoleRepository(db),
            sessions=SessionService(UserSessionRepository(db)),
            audit=AuditService(AuditRepository(db)),
        ).ensure(data)
        print(
            f"Administrator ready: {result.username} "
            f"(user_id={result.id}, superuser={result.is_superuser})"
        )
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Create or promote one exact account to full administrator."
    )
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    arguments = parser.parse_args()
    create_superuser(arguments.username, arguments.email)

