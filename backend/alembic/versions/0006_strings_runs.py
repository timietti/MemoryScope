"""Add strings_runs table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-06
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "strings_runs",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("case_id",         postgresql.UUID(as_uuid=True), sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status",          postgresql.ENUM(name="plugin_status", create_type=False), nullable=False, server_default="pending"),
        sa.Column("storage_key",     sa.Text,         nullable=True),
        sa.Column("line_count",      sa.Integer,      nullable=True),
        sa.Column("compressed_size", sa.Integer,      nullable=True),
        sa.Column("started_at",      sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at",    sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message",   sa.Text,         nullable=True),
        sa.Column("created_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
        sa.Column("updated_at",      sa.DateTime(timezone=True), nullable=False, server_default=sa.text("NOW()")),
    )
    op.create_index("idx_strings_runs_case_id", "strings_runs", ["case_id"])
    op.execute("""
        CREATE TRIGGER trg_strings_runs_updated_at
        BEFORE UPDATE ON strings_runs
        FOR EACH ROW EXECUTE FUNCTION update_updated_at()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_strings_runs_updated_at ON strings_runs")
    op.drop_index("idx_strings_runs_case_id", table_name="strings_runs")
    op.drop_table("strings_runs")
