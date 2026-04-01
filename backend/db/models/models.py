# backend/db/models/models.py
"""
All SQLAlchemy ORM models. Mirrors docs/schema.sql exactly.
"""
from __future__ import annotations
import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Boolean, BigInteger, Integer, SmallInteger, String, Text,
    DateTime, ForeignKey, Enum as PgEnum, ARRAY, Column,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class OSType(str, enum.Enum):
    windows = "windows"; linux = "linux"; macos = "macos"; unknown = "unknown"

class CaseStatus(str, enum.Enum):
    pending = "pending"; queued = "queued"; detecting = "detecting"
    building_symbols = "building_symbols"
    triage_complete = "triage_complete"
    analyzing = "analyzing"; ai_analysis = "ai_analysis"
    complete = "complete"; failed = "failed"; cancelled = "cancelled"

class PluginStatus(str, enum.Enum):
    pending = "pending"; running = "running"; complete = "complete"
    failed = "failed"; skipped = "skipped"; timeout = "timeout"

class Verdict(str, enum.Enum):
    clean = "clean"; suspicious = "suspicious"
    compromised = "compromised"; inconclusive = "inconclusive"

class IOCType(str, enum.Enum):
    ip = "ip"; domain = "domain"; url = "url"
    md5 = "md5"; sha1 = "sha1"; sha256 = "sha256"
    file_path = "file_path"; registry_key = "registry_key"
    mutex = "mutex"; process_name = "process_name"; email = "email"

class Severity(str, enum.Enum):
    info = "info"; low = "low"; medium = "medium"; high = "high"; critical = "critical"

class UserRole(str, enum.Enum):
    analyst = "analyst"; admin = "admin"


# SQLAlchemy enum types with explicit names matching schema.sql
_os_type      = PgEnum(OSType,      name="os_type",      create_type=False)
_case_status  = PgEnum(CaseStatus,  name="case_status",  create_type=False)
_plugin_status= PgEnum(PluginStatus,name="plugin_status", create_type=False)
_verdict      = PgEnum(Verdict,     name="verdict",      create_type=False)
_ioc_type     = PgEnum(IOCType,     name="ioc_type",     create_type=False)
_severity     = PgEnum(Severity,    name="severity",     create_type=False)
_user_role    = PgEnum(UserRole,    name="user_role",    create_type=False)


# ── User ──────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email         = Column(String(255), nullable=False, unique=True)
    display_name  = Column(String(128), nullable=False)
    password_hash = Column(Text)                        # NULL for SSO-only users
    sso_provider  = Column(String(64))                  # e.g. "authentik"; NULL for local users
    role          = Column(_user_role, nullable=False, default=UserRole.analyst)
    mfa_secret    = Column(Text)
    is_active     = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True))
    created_at    = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    submitted_cases = relationship("Case", foreign_keys="Case.submitted_by", back_populates="submitter")
    api_keys        = relationship("APIKey",         back_populates="user", cascade="all, delete-orphan")
    refresh_tokens  = relationship("RefreshToken",   back_populates="user", cascade="all, delete-orphan")


# ── Case ──────────────────────────────────────────────────────────────────────

class Case(Base):
    __tablename__ = "cases"

    id            = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    short_id      = Column(String(8),   nullable=False, unique=True)
    name          = Column(String(255), nullable=False)
    description   = Column(Text)
    priority      = Column(SmallInteger, nullable=False, default=2)
    submitted_by  = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    assigned_to   = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    tags          = Column(ARRAY(Text), nullable=False, default=list)

    original_filename  = Column(String(512), nullable=False)
    file_size_bytes    = Column(BigInteger, nullable=False)
    sha256             = Column(String(64), nullable=False)
    storage_key        = Column(Text, nullable=False)
    storage_bucket     = Column(String(128), nullable=False, default="dumps")

    detected_os        = Column(_os_type, nullable=False, default=OSType.unknown)
    detected_os_detail = Column(String(512))
    volatility_profile = Column(String(256))
    os_hint            = Column(_os_type)

    status         = Column(_case_status, nullable=False, default=CaseStatus.pending)
    error_message  = Column(Text)
    celery_task_id = Column(String(255))

    queued_at            = Column(DateTime(timezone=True))
    detection_started_at = Column(DateTime(timezone=True))
    analysis_started_at  = Column(DateTime(timezone=True))
    ai_started_at        = Column(DateTime(timezone=True))
    vt_enriched_at       = Column(DateTime(timezone=True))
    completed_at         = Column(DateTime(timezone=True))
    deleted_at           = Column(DateTime(timezone=True))
    dump_purged_at       = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    submitter     = relationship("User",          foreign_keys=[submitted_by], back_populates="submitted_cases")
    plugin_runs   = relationship("PluginRun",     back_populates="case", cascade="all, delete-orphan")
    reports       = relationship("Report",        back_populates="case", cascade="all, delete-orphan")
    iocs          = relationship("IOC",           back_populates="case", cascade="all, delete-orphan")
    events        = relationship("CaseEvent",     back_populates="case", cascade="all, delete-orphan")
    kb_links      = relationship("CaseKBArticle", back_populates="case", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage",   back_populates="case", cascade="all, delete-orphan", order_by="ChatMessage.id")


# ── Plugin Run ─────────────────────────────────────────────────────────────────

class PluginRun(Base):
    __tablename__ = "plugin_runs"
    __table_args__ = (UniqueConstraint("case_id", "plugin_name"),)

    id             = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id        = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    plugin_name    = Column(String(128), nullable=False)
    plugin_domain  = Column(String(64),  nullable=False)
    plugin_version = Column(String(32))

    status       = Column(_plugin_status, nullable=False, default=PluginStatus.pending)
    exit_code    = Column(SmallInteger)
    started_at   = Column(DateTime(timezone=True))
    completed_at = Column(DateTime(timezone=True))

    raw_output    = Column(Text)
    stderr_output = Column(Text)
    parsed_output = Column(JSONB)
    row_count     = Column(Integer)
    error_message = Column(Text)

    ai_flagged = Column(Boolean, nullable=False, default=False)
    ai_summary = Column(Text)

    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    case = relationship("Case", back_populates="plugin_runs")


# ── Report ─────────────────────────────────────────────────────────────────────

class Report(Base):
    __tablename__ = "reports"

    id      = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)

    verdict            = Column(_verdict, nullable=False)
    confidence         = Column(SmallInteger, nullable=False)
    verdict_reasoning  = Column(Text, nullable=False)
    mitre_ttps         = Column(JSONB, nullable=False, default=list)
    executive_summary  = Column(Text, nullable=False)
    technical_narrative = Column(Text, nullable=False)
    recommendations    = Column(JSONB, nullable=False, default=list)
    timeline           = Column(JSONB, nullable=False, default=list)

    model_used      = Column(String(128), nullable=False)
    agent_version   = Column(String(32),  nullable=False)
    token_usage     = Column(JSONB)
    pdf_storage_key = Column(Text)

    generated_at  = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at    = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    superseded_at = Column(DateTime(timezone=True), nullable=True)

    case = relationship("Case",   back_populates="reports")
    iocs = relationship("IOC",    back_populates="report")


# ── IOC ───────────────────────────────────────────────────────────────────────

class IOC(Base):
    __tablename__ = "iocs"
    __table_args__ = (UniqueConstraint("case_id", "ioc_type", "value"),)

    id        = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id   = Column(UUID(as_uuid=True), ForeignKey("cases.id",   ondelete="CASCADE"),  nullable=False)
    report_id = Column(UUID(as_uuid=True), ForeignKey("reports.id", ondelete="SET NULL"))

    ioc_type    = Column(_ioc_type, nullable=False)
    value       = Column(Text, nullable=False)
    severity    = Column(_severity, nullable=False, default=Severity.medium)
    description = Column(Text)
    source_plugin = Column(String(128))
    source_pid    = Column(Integer)

    vt_positives  = Column(SmallInteger)
    vt_total      = Column(SmallInteger)
    vt_permalink  = Column(Text)
    vt_checked_at = Column(DateTime(timezone=True))
    threat_names  = Column(ARRAY(Text))
    ai_context    = Column(Text)

    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    case   = relationship("Case",   back_populates="iocs")
    report = relationship("Report", back_populates="iocs")


# ── Case Event ────────────────────────────────────────────────────────────────

class CaseEvent(Base):
    __tablename__ = "case_events"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    case_id    = Column(UUID(as_uuid=True), ForeignKey("cases.id",  ondelete="CASCADE"),  nullable=False)
    event_type = Column(String(64), nullable=False)
    payload    = Column(JSONB, nullable=False, default=dict)
    actor_id   = Column(UUID(as_uuid=True), ForeignKey("users.id",  ondelete="SET NULL"))
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    case = relationship("Case", back_populates="events")


# ── Audit Log (system-level events: login, user CRUD, etc.) ──────────────────

class AuditLog(Base):
    __tablename__ = "audit_log"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    event_type     = Column(String(64), nullable=False)   # e.g. user.login, user.created
    actor_id       = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    target_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    payload        = Column(JSONB, nullable=False, default=dict)
    created_at     = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


# ── KB Article ────────────────────────────────────────────────────────────────

class KBArticle(Base):
    __tablename__ = "kb_articles"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title      = Column(String(512), nullable=False)
    content    = Column(Text, nullable=False)
    tags       = Column(ARRAY(Text), nullable=False, default=list)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    author   = relationship("User", foreign_keys=[created_by])
    case_links = relationship("CaseKBArticle", back_populates="article", cascade="all, delete-orphan")


class CaseKBArticle(Base):
    __tablename__ = "case_kb_articles"

    case_id    = Column(UUID(as_uuid=True), ForeignKey("cases.id",       ondelete="CASCADE"), primary_key=True)
    article_id = Column(UUID(as_uuid=True), ForeignKey("kb_articles.id", ondelete="CASCADE"), primary_key=True)
    attached_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    case    = relationship("Case",      back_populates="kb_links")
    article = relationship("KBArticle", back_populates="case_links")


# ── API Key ───────────────────────────────────────────────────────────────────

class APIKey(Base):
    __tablename__ = "api_keys"

    id           = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id      = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    key_hash     = Column(String(64), nullable=False, unique=True)
    name         = Column(String(128), nullable=False)
    last_used_at = Column(DateTime(timezone=True))
    expires_at   = Column(DateTime(timezone=True))
    is_active    = Column(Boolean, nullable=False, default=True)
    created_at   = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="api_keys")


# ── System Settings ───────────────────────────────────────────────────────────

class SystemSetting(Base):
    """Key-value store for runtime-configurable settings managed from the Admin UI."""
    __tablename__ = "system_settings"

    key        = Column(String(128), primary_key=True)
    value      = Column(Text, nullable=False)
    is_secret  = Column(Boolean, nullable=False, default=False)
    category   = Column(String(64), nullable=False, default="general")
    updated_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)


# ── Chat Message ──────────────────────────────────────────────────────────────

class ChatMessage(Base):
    __tablename__ = "chat_messages"

    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    case_id    = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    role       = Column(String(16),  nullable=False)   # 'user' | 'assistant'
    content    = Column(Text,        nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    case = relationship("Case", back_populates="chat_messages")


class ChatTokenLog(Base):
    __tablename__ = "chat_token_logs"

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    case_id       = Column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    input_tokens  = Column(Integer, nullable=False, default=0)
    output_tokens = Column(Integer, nullable=False, default=0)
    model_used    = Column(String(64), nullable=False, default="")
    created_at    = Column(DateTime(timezone=True), nullable=False)


# ── Refresh Token ─────────────────────────────────────────────────────────────

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id         = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id    = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)   # SHA-256 hex of the raw token
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), nullable=False, default=datetime.utcnow)

    user = relationship("User", back_populates="refresh_tokens")
