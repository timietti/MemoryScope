# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Dev commands

All commands run from the repo root.

```bash
make infra           # start Postgres, Redis, MinIO in Docker (required first)
make seed            # create admin@memoryscope.local / changeme123!
make backend         # FastAPI on :8000  (PYTHONPATH=. backend/.venv/bin/uvicorn backend.main:app --reload)
make worker          # Celery analysis worker
make beat            # Celery beat scheduler — required for watch folder and scheduled purges
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
| `DWARF2JSON_PATH` | Path/name of `dwarf2json` binary (default: `dwarf2json`); required for Linux symbol auto-build |
| `SYMBOL_CACHE_PATH` | Where Volatility3 ISF symbol tables are stored (default: `/opt/volatility3/volatility3/symbols` — the package's own symbols dir); subdirs `linux/` and `mac/` are used automatically |

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
1. `triage_task` — downloads dump from MinIO, runs OS detection via Volatility3. **Skipped** when the submit form provides both an OS hint and a custom symbol file — the case transitions directly to `triage_complete` in the API layer.
2. `build_linux_symbols_task` — (async, after triage) downloads the matching Ubuntu dbgsym package via the Launchpad API, runs `dwarf2json`, and places the ISF at `SYMBOL_CACHE_PATH/linux/`. Skipped if a custom symbol file was uploaded at submit time.
3. Plugin runs — analyst selects plugins manually via the UI; `run_selected_plugins_task` executes them
4. `manual_enrich_task` — extracts IOCs (IPs, hashes) from plugin output, optionally enriches via VirusTotal; sets `vt_enriched_at` on the case
5. `ai_analysis_task` — runs the multi-agent AI pipeline, persists `Report` + `IOC` rows. KB articles attached to the case (including the auto-created Description note) are passed as analyst context.

Celery workers use the **sync** psycopg2 driver (`postgresql://`). The FastAPI app uses the **async** asyncpg driver (`postgresql+asyncpg://`). The seed script strips the `+asyncpg` prefix for this reason.

**AI agent** (`backend/core/agent/`):
- `orchestrator.py` calls domain sub-agents (process, network, injection, rootkit, persistence)
- Sub-agents use tool calls (`tools.py`) to fetch specific plugin outputs from the DB
- Orchestrator synthesises findings into a `FinalReport` (defined in `report_schema.py`)

**Plugin system** (`backend/core/plugins/`):
- `registry.py` — maps OS → list of `PluginSpec` (name, domain, priority, parser class)
- `runner.py` — runs Volatility3 as a subprocess, captures JSON output; passes `--symbol-dirs SYMBOL_CACHE_PATH` so all subdirs (`linux/`, `mac/`, `windows/`) are searched
- `parsers/base.py` — contains all parser implementations; individual files in `parsers/` re-export from here

**Symbol table builder** (`backend/core/symbols/`, `backend/workers/analysis.py`):

`build_linux_symbols_task` runs a 4-step waterfall after triage detects Linux (or macOS). It stops at the first success and always advances the case to `triage_complete`:

1. **Local probe** — runs `vol.py -f <dump> linux.pslist` (or `mac.pslist`). Success = exit 0 + no symbol-error strings in stderr. If a cached ISF already works, done.
2. **Remote ISF #1** — same probe with `--remote-isf-url` pointing at the Abyss-W4tcher banners index. Volatility downloads and caches the matching ISF automatically.
3. **Remote ISF #2** — same with the leludo84 index.
4. **Build from source** (`linux_builder.py`) — Ubuntu only; uses the Launchpad API to find and download the matching `linux-image-*-dbgsym` `.ddeb`, extracts `vmlinux`, runs `dwarf2json linux --elf <vmlinux> | xz`.

After `dwarf2json` writes the ISF, `_patch_linux_banner()` fixes `symbols.linux_banner.constant_data`. `dwarf2json` leaves this field wrong (includes trailing `\n\x00`); the correct value is `base64(plain_banner_utf8)` with nothing appended. If `linux_banner` is absent from the ISF, the file is deleted and the build fails.

`build_linux_symbols_task` receives `storage_key` so it can re-download the dump if the triage work_dir was already cleaned up.

Remote ISF URLs are configured in `settings.REMOTE_ISF_URLS` (overridable via `.env`).

Custom symbol tables uploaded at submit time are stored directly to `SYMBOL_CACHE_PATH/linux/` or `SYMBOL_CACHE_PATH/mac/` by the API, bypassing the task entirely.

## Known quirks

**PostgreSQL enum type names** — `docs/schema.sql` defines enum types as `os_type`, `case_status`, `user_role` etc. SQLAlchemy ORM models must use `PgEnum(..., name="os_type", create_type=False)` explicitly; without `create_type=False` SQLAlchemy tries to recreate the type and without the explicit name it generates `ostype` (no underscore), causing `DatatypeMismatchError`.

**Pydantic v2 + ORM enums** — SQLAlchemy enum columns return Python `enum.Enum` instances. Pydantic v2 response models that type a field as `str` will reject them. Use `@field_validator('field', mode='before') def coerce(cls, v): return str(v)` for enum and UUID fields that need to be serialised as strings.

**MinIO buckets** — `ensure_buckets()` in `storage.py` is called from FastAPI's lifespan on startup. Buckets (`dumps`, `reports`) are created automatically on first backend start. MinIO port 9000 (S3 API) must be exposed to the host; port 9001 is the web console only.

**Docker networking** — infrastructure services (postgres, redis, minio) must be on both `internal` and `external` networks to accept connections from the host (i.e. from `make backend`/`make worker`). `internal: true` on a Docker network prevents host port publishing without the `external` network also attached.

**`make backend` / `make worker`** — run from the repo root with `PYTHONPATH=.` so that `backend` is a top-level package. Do not `cd backend` before running uvicorn/celery; the module path `backend.main:app` requires the root on the Python path.

**Parser files** — `backend/core/plugins/parsers/` contains individual stub files (e.g. `pslist.py`) that simply re-export their class from `base.py`. All parser logic lives in `base.py`.

**Python 3.11+ enum `str()` change** — `str(StrEnum.member)` now returns `"ClassName.member"` instead of `"member"`. All Pydantic validators that coerce enum fields to strings must use `v.value if hasattr(v, 'value') else str(v)`, not plain `str(v)`. See `backend/schemas/case.py` `coerce_to_str`.

**Celery task priority (Redis)** — priority queues are enabled via `broker_transport_options` in `celery_app.py`. Case priority (1–4) maps to Celery priority (9, 6, 3, 0 respectively — lower number = higher priority). All `dispatch_*` functions in `analysis.py` accept a `priority` argument. Workers must be restarted after changing this config.

**Description → KB article** — when a case is submitted with a non-empty description, the API automatically creates a `KBArticle` (title: "Description") and attaches it to the case. This is the mechanism that makes the description available to the AI agent; the `description` column on the `cases` table is still populated but is not read by the pipeline.

**Triage skip** — if the submit form includes both `os_hint` and a `symbols_file`, the API sets the case directly to `triage_complete`, creates `PluginRun` records for the detected OS, and skips `triage_task` entirely. The symbol file is written to `SYMBOL_CACHE_PATH/{linux|mac}/` before the case row is created.

**JWT refresh tokens** — `POST /auth/token` now returns both `access_token` and `refresh_token`. The refresh token is stored as a SHA-256 hash in the `refresh_tokens` table. `POST /auth/refresh` rotates the token pair; `POST /auth/logout` revokes the refresh token server-side. The `refresh_tokens` table must exist — see `docs/schema.sql` for the DDL.
