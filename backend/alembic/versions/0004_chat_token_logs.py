"""Add chat_token_logs table for tracking chat AI token usage.

Revision ID: 0004
Revises: 0003
Create Date: 2026-04-01
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "chat_token_logs",
        sa.Column("id",            sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("case_id",       postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("input_tokens",  sa.Integer, nullable=False, default=0),
        sa.Column("output_tokens", sa.Integer, nullable=False, default=0),
        sa.Column("model_used",    sa.String(64), nullable=False, default=""),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["case_id"], ["cases.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_chat_token_logs_case_id",    "chat_token_logs", ["case_id"])
    op.create_index("ix_chat_token_logs_created_at", "chat_token_logs", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_chat_token_logs_created_at", table_name="chat_token_logs")
    op.drop_index("ix_chat_token_logs_case_id",    table_name="chat_token_logs")
    op.drop_table("chat_token_logs")
