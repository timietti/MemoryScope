"""Add system_settings table for DB-backed runtime configuration.

Revision ID: 0002
Revises: 0001
Create Date: 2026-03-27
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_settings",
        sa.Column("key",       sa.String(128), primary_key=True),
        sa.Column("value",     sa.Text, nullable=False),
        sa.Column("is_secret", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("category",  sa.String(64), nullable=False, server_default="'general'"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_system_settings_category", "system_settings", ["category"])


def downgrade() -> None:
    op.drop_table("system_settings")
