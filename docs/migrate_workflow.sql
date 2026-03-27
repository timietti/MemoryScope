-- DEPRECATED: This file is superseded by Alembic migrations.
-- All future schema changes must be done via Alembic migration files in backend/alembic/versions/.
-- See: make migrate (new DB) or make db-stamp (existing DB).
--
-- Migration: implement manual workflow (triage_complete status + KB tables)
-- Run this against an existing MemoryScope database BEFORE restarting the backend.

-- 1. Add the new enum value to case_status
--    PostgreSQL requires ALTER TYPE to add enum values.
ALTER TYPE case_status ADD VALUE IF NOT EXISTS 'triage_complete' AFTER 'detecting';

-- 2. Create KB articles table
CREATE TABLE IF NOT EXISTS kb_articles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title       VARCHAR(512) NOT NULL,
    content     TEXT NOT NULL,
    tags        TEXT[] NOT NULL DEFAULT '{}',
    created_by  UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_kb_articles_tags       ON kb_articles USING GIN (tags);
CREATE INDEX IF NOT EXISTS idx_kb_articles_created_by ON kb_articles (created_by);

-- 3. Create case <-> KB article join table
CREATE TABLE IF NOT EXISTS case_kb_articles (
    case_id     UUID NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
    article_id  UUID NOT NULL REFERENCES kb_articles(id) ON DELETE CASCADE,
    attached_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (case_id, article_id)
);

CREATE INDEX IF NOT EXISTS idx_case_kb_articles_article ON case_kb_articles (article_id);

-- 4. updated_at trigger for kb_articles
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER LANGUAGE plpgsql AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_kb_articles_updated_at') THEN
        CREATE TRIGGER trg_kb_articles_updated_at
            BEFORE UPDATE ON kb_articles
            FOR EACH ROW EXECUTE FUNCTION update_updated_at();
    END IF;
END $$;
