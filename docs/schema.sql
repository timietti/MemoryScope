-- ============================================================
-- MemoryScope Database Schema
-- PostgreSQL 16  |  UUID primary keys  |  JSONB for outputs
-- ============================================================

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- trigram search on strings

-- ============================================================
-- ENUM TYPES
-- ============================================================

CREATE TYPE os_type AS ENUM ('windows', 'linux', 'macos', 'unknown');

CREATE TYPE case_status AS ENUM (
    'pending',          -- uploaded, not yet queued
    'queued',           -- in Celery queue
    'detecting',         -- OS/profile detection running
    'building_symbols',  -- Linux ISF symbol table being generated (blocks plugin run)
    'triage_complete',   -- OS detected; waiting for analyst to select plugins
    'analyzing',        -- Volatility3 plugins running
    'ai_analysis',      -- LLM agent running
    'complete',         -- done, report available
    'failed',           -- terminal error
    'cancelled'
);

CREATE TYPE plugin_status AS ENUM (
    'pending',
    'running',
    'complete',
    'failed',
    'skipped',       -- not applicable for detected OS
    'timeout'
);

CREATE TYPE verdict AS ENUM ('clean', 'suspicious', 'compromised', 'inconclusive');

CREATE TYPE ioc_type AS ENUM (
    'ip', 'domain', 'url', 'md5', 'sha1', 'sha256',
    'file_path', 'registry_key', 'mutex', 'process_name', 'email'
);

CREATE TYPE severity AS ENUM ('info', 'low', 'medium', 'high', 'critical');

CREATE TYPE user_role AS ENUM ('analyst', 'admin');

-- ============================================================
-- USERS
-- ============================================================

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    display_name    VARCHAR(128) NOT NULL,
    password_hash   TEXT,                    -- null for SSO users
    sso_provider    VARCHAR(64),             -- e.g. "authentik"; NULL for local users
    role            user_role NOT NULL DEFAULT 'analyst',
    mfa_secret      TEXT,                    -- TOTP secret, encrypted at app layer
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users (email);

-- ============================================================
-- CASES  (one per submitted memory dump)
-- ============================================================

CREATE TABLE cases (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    short_id        VARCHAR(8) NOT NULL UNIQUE,  -- human-readable, e.g. "A3F9B2C1"

    -- Metadata
    name            VARCHAR(255) NOT NULL,        -- analyst-supplied label
    description     TEXT,
    priority        SMALLINT NOT NULL DEFAULT 2,  -- 1=low 2=med 3=high 4=critical
    submitted_by    UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    assigned_to     UUID REFERENCES users(id) ON DELETE SET NULL,
    tags            TEXT[] NOT NULL DEFAULT '{}',

    -- File info
    original_filename   VARCHAR(512) NOT NULL,
    file_size_bytes     BIGINT NOT NULL,
    sha256              CHAR(64) NOT NULL,
    storage_key         TEXT NOT NULL,           -- object store path
    storage_bucket      VARCHAR(128) NOT NULL DEFAULT 'dumps',

    -- OS detection results
    detected_os         os_type NOT NULL DEFAULT 'unknown',
    detected_os_detail  VARCHAR(256),            -- e.g. "Windows 10 19041 x64"
    volatility_profile  VARCHAR(256),            -- resolved symbol profile
    os_hint             os_type,                 -- analyst override

    -- Status tracking
    status              case_status NOT NULL DEFAULT 'pending',
    error_message       TEXT,                    -- populated on failure
    celery_task_id      VARCHAR(255),

    -- Timing
    queued_at           TIMESTAMPTZ,
    detection_started_at TIMESTAMPTZ,
    analysis_started_at  TIMESTAMPTZ,
    ai_started_at        TIMESTAMPTZ,
    vt_enriched_at       TIMESTAMPTZ,
    completed_at         TIMESTAMPTZ,

    -- Soft delete
    deleted_at          TIMESTAMPTZ,
    dump_purged_at      TIMESTAMPTZ,             -- when the raw dump was deleted from object store

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cases_status         ON cases (status) WHERE deleted_at IS NULL;
CREATE INDEX idx_cases_submitted_by   ON cases (submitted_by);
CREATE INDEX idx_cases_sha256         ON cases (sha256);
CREATE INDEX idx_cases_created_at     ON cases (created_at DESC);
CREATE INDEX idx_cases_tags           ON cases USING GIN (tags);

-- ============================================================
-- PLUGIN RUNS  (one row per plugin per case)
-- ============================================================

CREATE TABLE plugin_runs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,

    -- Identity
    plugin_name     VARCHAR(128) NOT NULL,        -- e.g. "windows.malfind"
    plugin_domain   VARCHAR(64) NOT NULL,         -- e.g. "code_injection"
    plugin_version  VARCHAR(32),

    -- Execution
    status          plugin_status NOT NULL DEFAULT 'pending',
    exit_code       SMALLINT,
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    duration_ms     INTEGER GENERATED ALWAYS AS (
                        EXTRACT(EPOCH FROM (completed_at - started_at)) * 1000
                    ) STORED,

    -- Outputs
    raw_output      TEXT,                         -- verbatim Volatility3 stdout
    stderr_output   TEXT,                         -- stderr for debugging
    parsed_output   JSONB,                        -- normalised typed schema
    row_count       INTEGER,                      -- number of records in parsed_output
    error_message   TEXT,

    -- AI analysis flags
    ai_flagged      BOOLEAN NOT NULL DEFAULT FALSE,
    ai_summary      TEXT,                         -- short AI-generated summary of this plugin

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (case_id, plugin_name)
);

CREATE INDEX idx_plugin_runs_case_id       ON plugin_runs (case_id);
CREATE INDEX idx_plugin_runs_status        ON plugin_runs (status);
CREATE INDEX idx_plugin_runs_ai_flagged    ON plugin_runs (case_id, ai_flagged) WHERE ai_flagged = TRUE;
CREATE INDEX idx_plugin_runs_parsed        ON plugin_runs USING GIN (parsed_output);

-- ============================================================
-- REPORTS  (one per case, produced by AI agent)
-- ============================================================

CREATE TABLE reports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,

    -- Verdict
    verdict         verdict NOT NULL,
    confidence      SMALLINT NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    verdict_reasoning TEXT NOT NULL,

    -- Structured findings
    mitre_ttps      JSONB NOT NULL DEFAULT '[]',
    -- [{ "tactic": "TA0002", "tactic_name": "Execution",
    --    "technique": "T1059.001", "technique_name": "PowerShell",
    --    "evidence": "...", "severity": "high" }]

    executive_summary   TEXT NOT NULL,
    technical_narrative TEXT NOT NULL,
    recommendations     JSONB NOT NULL DEFAULT '[]',
    -- [{ "priority": 1, "action": "...", "rationale": "..." }]

    timeline        JSONB NOT NULL DEFAULT '[]',
    -- [{ "timestamp_estimate": "...", "event": "...", "evidence_plugin": "..." }]

    -- Model provenance
    model_used      VARCHAR(128) NOT NULL,        -- e.g. "claude-opus-4-5"
    agent_version   VARCHAR(32) NOT NULL,
    token_usage     JSONB,                        -- input/output tokens per sub-agent

    -- Export
    pdf_storage_key TEXT,                         -- object store path for PDF

    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    superseded_at   TIMESTAMPTZ                           -- set when re-analysis produces a new report; NULL = active
);

CREATE INDEX idx_reports_verdict      ON reports (verdict);
CREATE INDEX idx_reports_active       ON reports (case_id) WHERE superseded_at IS NULL;

-- ============================================================
-- IOCs  (extracted indicators of compromise)
-- ============================================================

CREATE TABLE iocs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    report_id       UUID REFERENCES reports(id) ON DELETE SET NULL,

    ioc_type        ioc_type NOT NULL,
    value           TEXT NOT NULL,
    severity        severity NOT NULL DEFAULT 'medium',
    description     TEXT,

    -- Source tracking
    source_plugin   VARCHAR(128),                 -- which plugin surfaced it
    source_pid      INTEGER,                      -- associated process if applicable

    -- Enrichment
    vt_positives    SMALLINT,                     -- VT detection count
    vt_total        SMALLINT,                     -- VT total engines
    vt_permalink    TEXT,
    vt_checked_at   TIMESTAMPTZ,
    threat_names    TEXT[],                       -- malware family names from VT

    ai_context      TEXT,                         -- why the AI flagged this

    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (case_id, ioc_type, value)
);

CREATE INDEX idx_iocs_case_id   ON iocs (case_id);
CREATE INDEX idx_iocs_type      ON iocs (ioc_type);
CREATE INDEX idx_iocs_value     ON iocs USING GIN (value gin_trgm_ops);  -- fuzzy search
CREATE INDEX idx_iocs_severity  ON iocs (severity);

-- ============================================================
-- CASE EVENTS  (audit + real-time notification log)
-- ============================================================

CREATE TABLE case_events (
    id              BIGSERIAL PRIMARY KEY,
    case_id         UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    event_type      VARCHAR(64) NOT NULL,
    -- e.g. status_change | plugin_complete | plugin_failed | report_ready | error
    payload         JSONB NOT NULL DEFAULT '{}',
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_case_events_case_id    ON case_events (case_id, created_at DESC);
CREATE INDEX idx_case_events_type       ON case_events (event_type);

-- ============================================================
-- AUDIT LOG  (admin-visible security event log)
-- ============================================================

CREATE TABLE audit_log (
    id              BIGSERIAL PRIMARY KEY,
    event_type      VARCHAR(64) NOT NULL,
    actor_id        UUID REFERENCES users(id) ON DELETE SET NULL,
    target_user_id  UUID REFERENCES users(id) ON DELETE SET NULL,
    payload         JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_log_event_type ON audit_log (event_type);
CREATE INDEX idx_audit_log_actor_id   ON audit_log (actor_id);
CREATE INDEX idx_audit_log_created_at ON audit_log (created_at DESC);

-- ============================================================
-- API KEYS  (for programmatic access)
-- ============================================================

CREATE TABLE api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_hash        CHAR(64) NOT NULL UNIQUE,     -- SHA-256 of the raw key
    name            VARCHAR(128) NOT NULL,
    last_used_at    TIMESTAMPTZ,
    expires_at      TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user_id  ON api_keys (user_id);
CREATE INDEX idx_api_keys_hash     ON api_keys (key_hash);

-- ============================================================
-- REFRESH TOKENS  (JWT refresh token rotation)
-- ============================================================

CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  VARCHAR(64) NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens (user_id);

-- ============================================================
-- KB ARTICLES  (analyst knowledge base notes)
-- ============================================================

CREATE TABLE kb_articles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       VARCHAR(512) NOT NULL,
    content     TEXT NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_kb_articles_tags        ON kb_articles USING GIN (tags);
CREATE INDEX idx_kb_articles_created_by  ON kb_articles (created_by);

CREATE TABLE case_kb_articles (
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    article_id  UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    attached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, article_id)
);

CREATE INDEX idx_case_kb_articles_article ON case_kb_articles (article_id);

-- ============================================================
-- SYSTEM SETTINGS  (DB-backed runtime configuration)
-- ============================================================

CREATE TABLE system_settings (
    key         VARCHAR(128) NOT NULL PRIMARY KEY,
    value       TEXT NOT NULL,
    is_secret   BOOLEAN NOT NULL DEFAULT FALSE,
    category    VARCHAR(64) NOT NULL DEFAULT 'general',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_system_settings_category ON system_settings (category);

-- ============================================================
-- CHAT MESSAGES  (persisted case chat history)
-- ============================================================

CREATE TABLE chat_messages (
    id          BIGSERIAL PRIMARY KEY,
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    role        VARCHAR(16) NOT NULL,
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_chat_messages_case_id ON chat_messages (case_id);

-- ============================================================
-- HELPER: auto-update updated_at
-- ============================================================

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

CREATE TRIGGER trg_users_updated_at         BEFORE UPDATE ON users         FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_cases_updated_at         BEFORE UPDATE ON cases         FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_plugin_runs_updated_at   BEFORE UPDATE ON plugin_runs   FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_reports_updated_at       BEFORE UPDATE ON reports       FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_kb_articles_updated_at   BEFORE UPDATE ON kb_articles   FOR EACH ROW EXECUTE FUNCTION update_updated_at();

