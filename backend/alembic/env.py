# backend/alembic/env.py
"""
Alembic migration environment.

Uses a synchronous psycopg2 connection (stripped of +asyncpg prefix) so that
Alembic's CLI tools (upgrade, stamp, current, etc.) work reliably.
The FastAPI app continues to use asyncpg at runtime — that's unrelated to this.
"""
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from backend.db.models.models import Base

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Convert asyncpg URL → psycopg2 URL for sync Alembic operations
database_url = os.environ.get("DATABASE_URL", "").replace(
    "postgresql+asyncpg://", "postgresql://"
)
config.set_main_option("sqlalchemy.url", database_url)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
