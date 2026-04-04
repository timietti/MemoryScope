#!/bin/sh
# Run Alembic migrations then start the API server.
# Migrations are idempotent — safe to run on every startup.
set -e

# Alembic requires the sync psycopg2 driver; strip +asyncpg if present.
ALEMBIC_URL=$(echo "$DATABASE_URL" | sed 's/+asyncpg//')

echo "[entrypoint] Running database migrations..."
PYTHONPATH=/app DATABASE_URL="$ALEMBIC_URL" alembic -c /app/backend/alembic.ini upgrade head

echo "[entrypoint] Starting API server..."
exec uvicorn backend.main:app --host 0.0.0.0 --port 8000 --workers 1
