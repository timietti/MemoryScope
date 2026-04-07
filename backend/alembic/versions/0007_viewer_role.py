"""Add viewer user role.

Revision ID: 0007
Revises: 0006
Create Date: 2026-04-07
"""
from __future__ import annotations

from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'viewer'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values directly.
    # Downgrade requires recreating the type without 'viewer'.
    op.execute("""
        ALTER TABLE users ALTER COLUMN role TYPE TEXT;
        UPDATE users SET role = 'analyst' WHERE role = 'viewer';
        DROP TYPE user_role;
        CREATE TYPE user_role AS ENUM ('analyst', 'admin');
        ALTER TABLE users ALTER COLUMN role TYPE user_role USING role::user_role;
    """)
