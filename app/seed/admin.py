import argparse

from app.core.settings import settings
from app.database.session import SessionLocal
from app.repositories.user_repository import UserRepository
from app.repositories.user_session_repository import UserSessionRepository
from app.schemas.user import UserCreate
from app.services.bootstrap_service import BootstrapService
from app.services.session_service import SessionService


def seed_initial_admin(*, reconcile_existing: bool = False) -> None:
    username = settings.initial_admin_username
    email = settings.initial_admin_email
    password = settings.initial_admin_password

    if username is None or email is None or password is None:
        raise RuntimeError(
            "INITIAL_ADMIN_USERNAME, INITIAL_ADMIN_EMAIL and "
            "INITIAL_ADMIN_PASSWORD are required."
        )

    data = UserCreate(
        username=username,
        email=email,
        password=password.get_secret_value(),
    )

    db = SessionLocal()

    try:
        service = BootstrapService(
            UserRepository(db),
            SessionService(UserSessionRepository(db)),
        )
        if reconcile_existing:
            admin = service.reconcile_initial_admin(data)
        else:
            admin = service.create_initial_admin(data)
        print(f"Initial administrator ready: {admin.username}")
    finally:
        db.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--reconcile-existing",
        action="store_true",
        help=(
            "Adopt INITIAL_ADMIN credentials for the existing active "
            "superuser and revoke its sessions."
        ),
    )
    arguments = parser.parse_args()
    seed_initial_admin(
        reconcile_existing=arguments.reconcile_existing,
    )
