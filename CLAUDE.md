# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Dev commands

All commands run from the repo root.

```bash
make infra           # start Postgres, Redis, MinIO in Docker (required first)
make seed            # create admin@memoryscope.local / changeme123!
make backend         # FastAPI on :8000  (PYTHONPATH=. backend/.venv/bin/uvicorn backend.main:app --reload)
make worker          # Celery analysis worker
make frontend        # Vite dev server on :3000 (binds 0.0.0.0 for remote access)
make lint            # ruff + mypy
make test            # pytest
make infra-down      # stop infrastructure containers
```

Install dependencies:
```bash
make install         # creates backend/.venv + pip install + npm install
```

Run a single test:
```bash
PYTHONPATH=. backend/.venv/bin/pytest backend/tests/path/to/test.py::test_name -v
```

## Environment variables

Copy `.env.example` to `.env`. Key variables:

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | JWT signing — must be stable across restarts or all tokens invalidate |
| `DATABASE_URL` | Full async connection string: `postgresql+asyncpg://memoryscope:<DB_PASSWORD>@localhost:5432/memoryscope` |
| `S3_ENDPOINT` | MinIO S3 API: `http://localhost:9000` for local dev |
| `S3_ACCESS_KEY` / `S3_SECRET_KEY` | MinIO credentials (used by both the app and `docker-compose.yml` to init MinIO) |
| `ANTHROPIC_API_KEY` | Required for AI analysis phase |

`DB_PASSWORD`, `DOMAIN`, `VITE_API_BASE_URL` are used by Docker Compose only and ignored by the backend (pydantic-settings is configured with `extra="ignore"`).

## Architecture

**Request flow:**
```
Browser → FastAPI (:8000) → PostgreSQL (cases/results)
                          → MinIO/S3 (dump files)
                          → Celery → Redis (task queue)
                               └→ Volatility3 (forensic plugins)
                               └→ Anthropic API (AI agent)
```

**Analysis pipeline** (`backend/workers/analysis.py`):
1. `triage_task` — downloads dump from MinIO, runs OS detection via Volatility3
2. `_plugin_phase` — runs 30+ Volatility3 plugins sequentially (parallelism via Celery worker concurrency)
3. `enrichment_task` — extracts IOCs (IPs, hashes) from plugin output, optionally enriches via VirusTotal
4. `ai_analysis_task` — runs the multi-agent AI pipeline, persists `Report` + `IOC` rows

Celery workers use the **sync** psycopg2 driver (`postgresql://`). The FastAPI app uses the **async** asyncpg driver (`postgresql+asyncpg://`). The seed script strips the `+asyncpg` prefix for this reason.

**AI agent** (`backend/core/agent/`):
- `orchestrator.py` calls domain sub-agents (process, network, injection, rootkit, persistence)
- Sub-agents use tool calls (`tools.py`) to fetch specific plugin outputs from the DB
- Orchestrator synthesises findings into a `FinalReport` (defined in `report_schema.py`)

**Plugin system** (`backend/core/plugins/`):
- `registry.py` — maps OS → list of `PluginSpec` (name, domain, priority, parser class)
- `runner.py` — runs Volatility3 as a subprocess, captures JSON output
- `parsers/base.py` — contains all parser implementations; individual files in `parsers/` re-export from here

## Known quirks

**PostgreSQL enum type names** — `docs/schema.sql` defines enum types as `os_type`, `case_status`, `user_role` etc. SQLAlchemy ORM models must use `PgEnum(..., name="os_type", create_type=False)` explicitly; without `create_type=False` SQLAlchemy tries to recreate the type and without the explicit name it generates `ostype` (no underscore), causing `DatatypeMismatchError`.

**Pydantic v2 + ORM enums** — SQLAlchemy enum columns return Python `enum.Enum` instances. Pydantic v2 response models that type a field as `str` will reject them. Use `@field_validator('field', mode='before') def coerce(cls, v): return str(v)` for enum and UUID fields that need to be serialised as strings.

**MinIO buckets** — `ensure_buckets()` in `storage.py` is called from FastAPI's lifespan on startup. Buckets (`dumps`, `reports`) are created automatically on first backend start. MinIO port 9000 (S3 API) must be exposed to the host; port 9001 is the web console only.

**Docker networking** — infrastructure services (postgres, redis, minio) must be on both `internal` and `external` networks to accept connections from the host (i.e. from `make backend`/`make worker`). `internal: true` on a Docker network prevents host port publishing without the `external` network also attached.

**`make backend` / `make worker`** — run from the repo root with `PYTHONPATH=.` so that `backend` is a top-level package. Do not `cd backend` before running uvicorn/celery; the module path `backend.main:app` requires the root on the Python path.

**Parser files** — `backend/core/plugins/parsers/` contains individual stub files (e.g. `pslist.py`) that simply re-export their class from `base.py`. All parser logic lives in `base.py`.
