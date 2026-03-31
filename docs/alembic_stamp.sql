-- Stamp the Alembic version table so that alembic upgrade head
-- recognises the schema (created by schema.sql) as already at head.
-- This must run AFTER schema.sql in docker-entrypoint-initdb.d.
CREATE TABLE IF NOT EXISTS alembic_version (
    version_num VARCHAR(32) NOT NULL,
    CONSTRAINT alembic_version_pkc PRIMARY KEY (version_num)
);
INSERT INTO alembic_version (version_num) VALUES ('0003')
ON CONFLICT DO NOTHING;
