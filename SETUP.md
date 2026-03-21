# MemoryScope — Developer Setup Guide

## 1. Repository structure

After cloning, your repository should look exactly like this.
Run `python scripts/create_inits.py` once to add the `__init__.py` files
that Python needs (they are not listed here for brevity).

```
MemoryScope/                          ← git root
│
├── .env.example                      ← copy to .env, fill secrets
├── .gitignore
├── docker-compose.yml                ← full dev stack
│
├── backend/                          ← Python / FastAPI
│   ├── alembic.ini
│   ├── main.py                       ← FastAPI app entry point
│   ├── config.py                     ← pydantic-settings (reads .env)
│   ├── requirements.txt
│   │
│   ├── api/
│   │   ├── dependencies.py           ← JWT auth FastAPI deps
│   │   ├── middleware/               ← (add rate_limit.py here)
│   │   └── routers/
│   │       ├── auth.py               ← /auth/token, /auth/me
│   │       ├── cases.py              ← main CRUD + upload
│   │       └── ws.py                 ← WebSocket /ws/cases/{id}
│   │
│   ├── core/
│   │   ├── storage.py                ← MinIO/S3 client
│   │   ├── agent/
│   │   │   ├── orchestrator.py       ← AI agent main loop
│   │   │   ├── tools.py              ← 6 agent tool functions
│   │   │   ├── prompts.py            ← all LLM prompt templates
│   │   │   └── report_schema.py      ← Pydantic report models
│   │   └── plugins/
│   │       ├── registry.py           ← 30+ plugin specs by OS
│   │       ├── runner.py             ← Volatility3 subprocess runner
│   │       └── parsers/
│   │           └── base.py           ← all parsers in one file
│   │
│   ├── db/
│   │   ├── session.py                ← async SQLAlchemy engine + get_db()
│   │   ├── models/
│   │   │   └── models.py             ← all ORM models
│   │   └── migrations/               ← Alembic auto-generated
│   │
│   ├── workers/
│   │   ├── celery_app.py             ← Celery config
│   │   └── analysis.py               ← full task pipeline
│   │
│   ├── schemas/                      ← Pydantic API schemas (add here)
│   │   ├── case.py                   ← CaseCreate, CaseResponse, etc.
│   │   ├── plugin.py
│   │   └── report.py
│   │
│   └── utils/
│       ├── enrichment.py             ← VirusTotal client
│       ├── notifications.py          ← Redis pub/sub publish helper
│       └── pdf_export.py             ← WeasyPrint (stub, add later)
│
├── frontend/                         ← React + TypeScript (Vite)
│   ├── index.html
│   ├── package.json
│   ├── vite.config.ts
│   ├── tsconfig.json
│   ├── tsconfig.node.json
│   └── src/
│       ├── main.tsx                  ← React entry point
│       ├── App.tsx                   ← Router + routes
│       ├── index.css                 ← CSS variables + base styles
│       ├── api/
│       │   ├── client.ts             ← axios instance + all API helpers
│       │   └── queryClient.ts        ← React Query client
│       ├── components/
│       │   └── shared/
│       │       └── Layout.tsx        ← sidebar + nav shell
│       ├── hooks/
│       │   └── useCaseWebSocket.ts   ← WS hook + React Query hooks
│       ├── pages/
│       │   ├── Login.tsx
│       │   ├── Dashboard.tsx
│       │   ├── Submit.tsx
│       │   └── CaseDetail.tsx        ← 4-tab case viewer
│       └── types/
│           └── index.ts              ← all shared TypeScript types
│
├── infra/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.worker         ← includes Volatility3
│   │   └── Dockerfile.frontend
│   └── nginx/
│       └── nginx.conf
│
├── docs/
│   └── schema.sql                    ← full PostgreSQL schema
│
└── scripts/
    └── create_inits.py               ← creates Python __init__.py files
```

---

## 2. Files still needed (stubs to create)

These files are referenced by the existing code but not yet written.
Create them as empty stubs first so nothing crashes at import time.

### backend/schemas/case.py
```python
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class CaseCreate(BaseModel):
    name: str
    description: Optional[str] = None
    priority: int = 2

class CaseResponse(BaseModel):
    id: str
    short_id: str
    name: str
    description: Optional[str]
    priority: int
    original_filename: str
    file_size_bytes: int
    sha256: str
    detected_os: str
    detected_os_detail: Optional[str]
    status: str
    error_message: Optional[str]
    created_at: datetime
    queued_at: Optional[datetime]
    completed_at: Optional[datetime]
    submitted_by: str

    class Config:
        from_attributes = True

class CaseListResponse(BaseModel):
    items: List[CaseResponse]
    total: int
    page: int
    page_size: int

class PluginRunResponse(BaseModel):
    id: str
    case_id: str
    plugin_name: str
    plugin_domain: str
    status: str
    exit_code: Optional[int]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_ms: Optional[int]
    row_count: Optional[int]
    parsed_output: Optional[object]
    raw_output: Optional[str]
    error_message: Optional[str]
    ai_flagged: bool
    ai_summary: Optional[str]

    class Config:
        from_attributes = True

class ReportResponse(BaseModel):
    id: str
    case_id: str
    verdict: str
    confidence: int
    verdict_reasoning: str
    executive_summary: str
    technical_narrative: str
    mitre_ttps: list
    timeline: list
    recommendations: list
    model_used: str
    agent_version: str
    token_usage: Optional[object]
    generated_at: datetime

    class Config:
        from_attributes = True
```

### backend/utils/notifications.py
(already written inside ws.py — move to its own file)
```python
# Copy the publish_case_event() and _persist_event() functions
# from backend/api/routers/ws.py to this file,
# then import from here in both ws.py and analysis.py
```

### backend/utils/pdf_export.py
```python
# Stub — implement in Phase 3
async def generate_pdf(report) -> bytes:
    raise NotImplementedError("PDF export not yet implemented")
```

### backend/core/agent/report_schema.py
```python
# The FinalReport, Verdict, MitreTTP, etc. classes are currently
# defined at the bottom of backend/core/agent/prompts.py.
# Either leave them there or move to this dedicated file and
# update the import in orchestrator.py.
```

---

## 3. First-time local setup

### Prerequisites
- Python 3.12+
- Node.js 20+
- Docker Desktop (for Postgres, Redis, MinIO)
- Volatility3 (for actual analysis; skip for UI dev)

### Step 1 — Clone and configure
```bash
git clone https://github.com/YOUR_USERNAME/MemoryScope.git
cd MemoryScope

cp .env.example .env
# Edit .env — minimum required:
#   SECRET_KEY=<any long random string>
#   DB_PASSWORD=localdev
#   MINIO_ACCESS_KEY=memoryscope
#   MINIO_SECRET_KEY=memoryscope123
#   ANTHROPIC_API_KEY=sk-ant-...
```

### Step 2 — Start infrastructure only
```bash
# Start just Postgres, Redis, MinIO (not the app services)
docker compose up postgres redis minio -d

# Wait ~10s, then verify:
docker compose ps
```

### Step 3 — Backend (runs locally, not in Docker)
```bash
cd backend

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt

# Create __init__.py files
python ../scripts/create_inits.py

# Apply schema to Postgres
# Option A — direct SQL (quickest for dev):
psql postgresql://memoryscope:localdev@localhost:5432/memoryscope < ../docs/schema.sql

# Option B — init Alembic migrations (for production workflow):
# alembic init alembic
# alembic revision --autogenerate -m "initial"
# alembic upgrade head

# Start FastAPI dev server
uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000
```

Open http://localhost:8000/api/docs — you should see the Swagger UI.

### Step 4 — Celery worker (separate terminal)
```bash
cd backend
source .venv/bin/activate

celery -A backend.workers.celery_app worker \
  --loglevel=info --concurrency=2 --queues=analysis,plugins,default
```

### Step 5 — Frontend
```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 — login with the seeded admin account.

> **Seed the admin password** — the schema creates the admin user but without
> a password hash. Run this once:
> ```python
> from passlib.context import CryptContext
> print(CryptContext(schemes=["bcrypt"]).hash("changeme"))
> # Copy the hash, then:
> # UPDATE users SET password_hash = '<hash>' WHERE email = 'admin@memoryscope.local';
> ```

---

## 4. Running the full stack with Docker Compose

```bash
# Build and start everything
docker compose up --build

# Scale workers
docker compose up --scale worker=4

# View logs
docker compose logs -f worker
docker compose logs -f api
```

---

## 5. VSCode recommended extensions

Add `.vscode/extensions.json`:
```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.vscode-pylance",
    "ms-python.black-formatter",
    "bradlc.vscode-tailwindcss",
    "dbaeumer.vscode-eslint",
    "esbenp.prettier-vscode",
    "ms-azuretools.vscode-docker",
    "mtxr.sqltools",
    "mtxr.sqltools-driver-pg",
    "humao.rest-client"
  ]
}
```

Add `.vscode/settings.json`:
```json
{
  "python.defaultInterpreterPath": "./backend/.venv/bin/python",
  "editor.formatOnSave": true,
  "[python]": {
    "editor.defaultFormatter": "ms-python.black-formatter"
  },
  "[typescript]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  },
  "[typescriptreact]": {
    "editor.defaultFormatter": "esbenp.prettier-vscode"
  }
}
```

---

## 6. .gitignore

```gitignore
# Python
__pycache__/
*.py[cod]
.venv/
*.egg-info/
.pytest_cache/
.mypy_cache/

# Environment
.env
*.env.local

# Frontend
frontend/node_modules/
frontend/dist/

# Docker volumes (if bind-mounted locally)
.docker-volumes/

# OS
.DS_Store
Thumbs.db

# IDE
.vscode/settings.json
.idea/

# Dumps (never commit memory dumps!)
*.raw
*.mem
*.dmp
*.vmem
*.lime
```

---

## 7. Git workflow — pushing files from your download

```bash
cd MemoryScope   # your cloned repo

# Copy downloaded files into the repo, preserving directory structure
# (Drag-drop from your Downloads folder into the VSCode Explorer,
#  maintaining the structure shown in Section 1)

# Run the init script
python scripts/create_inits.py

# Stage everything
git add .
git status          # review what's staged

git commit -m "feat: initial project scaffold from MemoryScope design session"
git push origin main
```

---

## 8. Phase 1 completion checklist

Before moving to AI integration (Phase 2), verify these work end-to-end:

- [ ] `docker compose up postgres redis minio -d` — services healthy
- [ ] `uvicorn backend.main:app --reload` — starts without import errors
- [ ] `GET /health` returns `{"status": "ok"}`
- [ ] `POST /api/v1/auth/token` returns a JWT
- [ ] `POST /api/v1/cases` (with a small test file) creates a case
- [ ] Celery worker picks up the job and runs OS detection
- [ ] Plugin runs appear in the DB after analysis
- [ ] Frontend loads at `localhost:3000` and shows the dashboard
- [ ] WebSocket connects and shows live plugin progress

Once all boxes are checked, move to Phase 2: AI agent integration.

---

## 9. Key implementation gaps to fill (in priority order)

| File | What to add |
|------|-------------|
| `backend/schemas/case.py` | Pydantic response schemas (see Section 2) |
| `backend/utils/notifications.py` | Extract from ws.py into standalone module |
| `backend/utils/pdf_export.py` | WeasyPrint report export |
| `backend/db/models/models.py` | Add `User` model (currently only imported) |
| `backend/core/agent/report_schema.py` | Extract from bottom of prompts.py |
| `backend/api/routers/ws.py` | Remove duplicate notifications.py code |
| `backend/core/plugins/parsers/` | Split base.py into individual parser files |
| `docs/` | OpenAPI spec export: `GET /api/openapi.json` |
