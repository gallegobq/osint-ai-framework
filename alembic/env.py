from logging.config import fileConfig

from sqlalchemy import create_engine
from sqlalchemy import pool

from alembic import context

from app.core.config import config
from app.database.base import Base

import app.models  # noqa: F401
# por ahora no hay ninguno
# después importaremos:
#
# from app.models.user import User


config_alembic = context.config

if config_alembic.config_file_name is not None:
    fileConfig(config_alembic.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline():

    url = config.DATABASE_URL.render_as_string(hide_password=False)

    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():

    connectable = create_engine(
        config.DATABASE_URL,
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:

        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():

    run_migrations_offline()

else:

    run_migrations_online()
