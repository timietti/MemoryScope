"""Add 'enriching' value to case_status enum.

Revision ID: 0005
Revises: 0004
Create Date: 2026-04-03
"""
from __future__ import annotations

from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE case_status ADD VALUE IF NOT EXISTS 'enriching' AFTER 'analyzing'")


def downgrade() -> None:
    # PostgreSQL does not support removing enum values; downgrade is a no-op.
    pass
