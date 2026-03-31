"""Add chat_messages table for persisted case chat history.

Revision ID: 0003
Revises: 0002
Create Date: 2026-03-31
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_messages",
        sa.Column("id",         sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("case_id",    postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role",       sa.String(16),  nullable=False),
        sa.Column("content",    sa.Text,        nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_chat_messages_case_id", "chat_messages", ["case_id"])


def downgrade() -> None:
    op.drop_index("ix_chat_messages_case_id", table_name="chat_messages")
    op.drop_table("chat_messages")
