"""Initial schema — baseline migration representing the full current database state.

For existing installations: run `alembic stamp head` to mark the DB as current
without re-running this migration (the tables already exist).

For fresh installations: run `alembic upgrade head` to create the full schema.

Revision ID: 0001
Revises:
Create Date: 2026-03-27
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


# ── Enum definitions ───────────────────────────────────────────────────────────

_ENUMS = [
    ("os_type",      ["windows", "linux", "macos", "unknown"]),
    ("case_status",  ["pending", "queued", "detecting", "building_symbols",
                      "triage_complete", "analyzing", "ai_analysis",
                      "complete", "failed", "cancelled"]),
    ("plugin_status",["pending", "running", "complete", "failed", "skipped", "timeout"]),
    ("verdict",      ["clean", "suspicious", "compromised", "inconclusive"]),
    ("ioc_type",     ["ip", "domain", "url", "md5", "sha1", "sha256",
                      "file_path", "registry_key", "mutex", "process_name", "email"]),
    ("severity",     ["info", "low", "medium", "high", "critical"]),
    ("user_role",    ["analyst", "admin"]),
]


def upgrade() -> None:
    conn = op.get_bind()

    # ── 1. Create enum types ───────────────────────────────────────────────────
    for name, values in _ENUMS:
        quoted = ", ".join(f"'{v}'" for v in values)
        conn.execute(sa.text(
            f"DO $$ BEGIN CREATE TYPE {name} AS ENUM ({quoted}); "
            f"EXCEPTION WHEN duplicate_object THEN NULL; END $$;"
        ))

    # ── 2. users ───────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email",         sa.String(255), nullable=False, unique=True),
        sa.Column("display_name",  sa.String(128), nullable=False),
        sa.Column("password_hash", sa.Text),
        sa.Column("sso_provider",  sa.String(64)),
        sa.Column("role",          sa.Enum(name="user_role", create_type=False), nullable=False),
        sa.Column("mfa_secret",    sa.Text),
        sa.Column("is_active",     sa.Boolean, nullable=False, server_default="true"),
        sa.Column("last_login_at", sa.DateTime(timezone=True)),
        sa.Column("created_at",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False),
    )

    # ── 3. cases ───────────────────────────────────────────────────────────────
    op.create_table(
        "cases",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("short_id",     sa.String(8),  nullable=False, unique=True),
        sa.Column("name",         sa.String(255), nullable=False),
        sa.Column("description",  sa.Text),
        sa.Column("priority",     sa.SmallInteger, nullable=False, server_default="2"),
        sa.Column("submitted_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("assigned_to",  postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id")),
        sa.Column("tags",         postgresql.ARRAY(sa.Text), nullable=False,
                  server_default="'{}'"),

        sa.Column("original_filename", sa.String(512), nullable=False),
        sa.Column("file_size_bytes",   sa.BigInteger, nullable=False),
        sa.Column("sha256",            sa.String(64),  nullable=False),
        sa.Column("storage_key",       sa.Text, nullable=False),
        sa.Column("storage_bucket",    sa.String(128), nullable=False,
                  server_default="'dumps'"),

        sa.Column("detected_os",        sa.Enum(name="os_type", create_type=False),
                  nullable=False),
        sa.Column("detected_os_detail", sa.String(512)),
        sa.Column("volatility_profile", sa.String(256)),
        sa.Column("os_hint",            sa.Enum(name="os_type", create_type=False)),

        sa.Column("status",         sa.Enum(name="case_status", create_type=False),
                  nullable=False),
        sa.Column("error_message",  sa.Text),
        sa.Column("celery_task_id", sa.String(255)),

        sa.Column("queued_at",             sa.DateTime(timezone=True)),
        sa.Column("detection_started_at",  sa.DateTime(timezone=True)),
        sa.Column("analysis_started_at",   sa.DateTime(timezone=True)),
        sa.Column("ai_started_at",         sa.DateTime(timezone=True)),
        sa.Column("vt_enriched_at",        sa.DateTime(timezone=True)),
        sa.Column("completed_at",          sa.DateTime(timezone=True)),
        sa.Column("deleted_at",            sa.DateTime(timezone=True)),
        sa.Column("dump_purged_at",        sa.DateTime(timezone=True)),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_cases_status",    "cases", ["status"])
    op.create_index("ix_cases_sha256",    "cases", ["sha256"])
    op.create_index("ix_cases_submitted_by", "cases", ["submitted_by"])

    # ── 4. plugin_runs ────────────────────────────────────────────────────────
    op.create_table(
        "plugin_runs",
        sa.Column("id",             postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",        postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("plugin_name",    sa.String(128), nullable=False),
        sa.Column("plugin_domain",  sa.String(64),  nullable=False),
        sa.Column("plugin_version", sa.String(32)),

        sa.Column("status",    sa.Enum(name="plugin_status", create_type=False),
                  nullable=False),
        sa.Column("exit_code", sa.SmallInteger),
        sa.Column("started_at",   sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),

        sa.Column("raw_output",    sa.Text),
        sa.Column("stderr_output", sa.Text),
        sa.Column("parsed_output", postgresql.JSONB),
        sa.Column("row_count",     sa.Integer),
        sa.Column("error_message", sa.Text),

        sa.Column("ai_flagged", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("ai_summary", sa.Text),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),

        sa.UniqueConstraint("case_id", "plugin_name", name="uq_plugin_runs_case_plugin"),
    )
    op.create_index("ix_plugin_runs_case_id", "plugin_runs", ["case_id"])

    # ── 5. reports ────────────────────────────────────────────────────────────
    op.create_table(
        "reports",
        sa.Column("id",      postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),

        sa.Column("verdict",             sa.Enum(name="verdict", create_type=False),
                  nullable=False),
        sa.Column("confidence",          sa.SmallInteger, nullable=False),
        sa.Column("verdict_reasoning",   sa.Text, nullable=False),
        sa.Column("mitre_ttps",          postgresql.JSONB, nullable=False,
                  server_default="'[]'"),
        sa.Column("executive_summary",   sa.Text, nullable=False),
        sa.Column("technical_narrative", sa.Text, nullable=False),
        sa.Column("recommendations",     postgresql.JSONB, nullable=False,
                  server_default="'[]'"),
        sa.Column("timeline",            postgresql.JSONB, nullable=False,
                  server_default="'[]'"),

        sa.Column("model_used",      sa.String(128), nullable=False),
        sa.Column("agent_version",   sa.String(32),  nullable=False),
        sa.Column("token_usage",     postgresql.JSONB),
        sa.Column("pdf_storage_key", sa.Text),

        sa.Column("generated_at",  sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at",    sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_reports_case_id", "reports", ["case_id"])

    # ── 6. iocs ───────────────────────────────────────────────────────────────
    op.create_table(
        "iocs",
        sa.Column("id",        postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("case_id",   postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id",   ondelete="CASCADE"),  nullable=False),
        sa.Column("report_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reports.id", ondelete="SET NULL")),

        sa.Column("ioc_type",     sa.Enum(name="ioc_type", create_type=False),
                  nullable=False),
        sa.Column("value",        sa.Text, nullable=False),
        sa.Column("severity",     sa.Enum(name="severity", create_type=False),
                  nullable=False),
        sa.Column("description",  sa.Text),
        sa.Column("source_plugin", sa.String(128)),
        sa.Column("source_pid",    sa.Integer),

        sa.Column("vt_positives",  sa.SmallInteger),
        sa.Column("vt_total",      sa.SmallInteger),
        sa.Column("vt_permalink",  sa.Text),
        sa.Column("vt_checked_at", sa.DateTime(timezone=True)),
        sa.Column("threat_names",  postgresql.ARRAY(sa.Text)),
        sa.Column("ai_context",    sa.Text),

        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),

        sa.UniqueConstraint("case_id", "ioc_type", "value", name="uq_iocs_case_type_value"),
    )
    op.create_index("ix_iocs_case_id",  "iocs", ["case_id"])
    op.create_index("ix_iocs_severity", "iocs", ["severity"])

    # ── 7. case_events ────────────────────────────────────────────────────────
    op.create_table(
        "case_events",
        sa.Column("id",         sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("case_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("event_type", sa.String(64), nullable=False),
        sa.Column("payload",    postgresql.JSONB, nullable=False, server_default="'{}'"),
        sa.Column("actor_id",   postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_case_events_case_id", "case_events", ["case_id"])

    # ── 8. audit_log ──────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id",             sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("event_type",     sa.String(64), nullable=False),
        sa.Column("actor_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("target_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("payload",        postgresql.JSONB, nullable=False,
                  server_default="'{}'"),
        sa.Column("created_at",     sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_audit_log_event_type", "audit_log", ["event_type"])
    op.create_index("ix_audit_log_actor_id",   "audit_log", ["actor_id"])
    op.create_index("ix_audit_log_created_at", "audit_log", ["created_at"])

    # ── 9. kb_articles ────────────────────────────────────────────────────────
    op.create_table(
        "kb_articles",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("title",      sa.String(512), nullable=False),
        sa.Column("content",    sa.Text, nullable=False),
        sa.Column("tags",       postgresql.ARRAY(sa.Text), nullable=False,
                  server_default="'{}'"),
        sa.Column("created_by", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    # ── 10. case_kb_articles ──────────────────────────────────────────────────
    op.create_table(
        "case_kb_articles",
        sa.Column("case_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("cases.id",       ondelete="CASCADE"), primary_key=True),
        sa.Column("article_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("kb_articles.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("attached_at", sa.DateTime(timezone=True), nullable=False),
    )

    # ── 11. api_keys ──────────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key_hash",     sa.String(64), nullable=False, unique=True),
        sa.Column("name",         sa.String(128), nullable=False),
        sa.Column("last_used_at", sa.DateTime(timezone=True)),
        sa.Column("expires_at",   sa.DateTime(timezone=True)),
        sa.Column("is_active",    sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at",   sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])

    # ── 12. refresh_tokens ────────────────────────────────────────────────────
    op.create_table(
        "refresh_tokens",
        sa.Column("id",         postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])


def downgrade() -> None:
    # Drop tables in reverse dependency order
    op.drop_table("refresh_tokens")
    op.drop_table("api_keys")
    op.drop_table("case_kb_articles")
    op.drop_table("kb_articles")
    op.drop_table("audit_log")
    op.drop_table("case_events")
    op.drop_table("iocs")
    op.drop_table("reports")
    op.drop_table("plugin_runs")
    op.drop_table("cases")
    op.drop_table("users")

    # Drop enum types
    conn = op.get_bind()
    for name, _ in reversed(_ENUMS):
        conn.execute(sa.text(f"DROP TYPE IF EXISTS {name};"))
