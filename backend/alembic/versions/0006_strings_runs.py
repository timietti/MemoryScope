"""Add strings_runs table.

Revision ID: 0006
Revises: 0005
Create Date: 2026-04-06
"""
from __future__ import annotations

from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE strings_runs (
            id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
            status          plugin_status NOT NULL DEFAULT 'pending',
            storage_key     TEXT,
            line_count      INTEGER,
            compressed_size INTEGER,
            started_at      TIMESTAMPTZ,
            completed_at    TIMESTAMPTZ,
            error_message   TEXT,
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    """)
    op.execute("CREATE INDEX idx_strings_runs_case_id ON strings_runs (case_id)")
    op.execute("""
        CREATE TRIGGER trg_strings_runs_updated_at
        BEFORE UPDATE ON strings_runs
        FOR EACH ROW EXECUTE FUNCTION update_updated_at()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_strings_runs_updated_at ON strings_runs")
    op.execute("DROP INDEX IF EXISTS idx_strings_runs_case_id")
    op.execute("DROP TABLE IF EXISTS strings_runs")
