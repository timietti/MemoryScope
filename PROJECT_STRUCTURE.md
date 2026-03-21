# MemoryScope — Project Structure

```
memoryscope/
├── backend/
│   ├── api/
│   │   ├── routers/          # FastAPI route handlers
│   │   │   ├── cases.py      # Case CRUD + upload
│   │   │   ├── plugins.py    # Plugin output retrieval
│   │   │   ├── reports.py    # AI report retrieval + export
│   │   │   ├── ws.py         # WebSocket endpoint
│   │   │   └── auth.py       # Auth endpoints
│   │   ├── middleware/
│   │   │   ├── auth.py       # JWT validation
│   │   │   └── rate_limit.py # Upload/API rate limiting
│   │   └── dependencies.py   # Shared FastAPI deps
│   ├── core/
│   │   ├── agent/
│   │   │   ├── orchestrator.py    # Main AI agent loop
│   │   │   ├── sub_agents.py      # Domain sub-agents
│   │   │   ├── tools.py           # Agent tool definitions
│   │   │   ├── prompts.py         # System + domain prompts
│   │   │   └── report_schema.py   # Pydantic report models
│   │   ├── plugins/
│   │   │   ├── registry.py        # Plugin→OS mapping
│   │   │   ├── runner.py          # Volatility3 subprocess runner
│   │   │   └── parsers/           # Per-plugin output parsers
│   │   │       ├── base.py
│   │   │       ├── pslist.py
│   │   │       ├── malfind.py
│   │   │       ├── netstat.py
│   │   │       └── ...
│   │   └── storage.py             # MinIO/S3 client
│   ├── db/
│   │   ├── models/
│   │   │   ├── base.py
│   │   │   ├── case.py
│   │   │   ├── plugin_run.py
│   │   │   ├── report.py
│   │   │   ├── ioc.py
│   │   │   └── user.py
│   │   ├── migrations/            # Alembic migrations
│   │   └── session.py             # SQLAlchemy async session
│   ├── workers/
│   │   ├── celery_app.py          # Celery configuration
│   │   ├── triage.py              # OS detection task
│   │   ├── analysis.py            # Plugin execution tasks
│   │   └── ai_analysis.py         # AI agent task
│   ├── schemas/                   # Pydantic API schemas
│   │   ├── case.py
│   │   ├── plugin.py
│   │   └── report.py
│   ├── utils/
│   │   ├── enrichment.py          # VirusTotal integration
│   │   ├── pdf_export.py          # WeasyPrint report export
│   │   └── notifications.py       # WebSocket pub/sub
│   ├── main.py                    # FastAPI app entry
│   ├── config.py                  # Settings (pydantic-settings)
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── cases/             # Case list, submission form
│   │   │   ├── viewer/            # Plugin output tables
│   │   │   ├── report/            # AI report display
│   │   │   └── shared/            # Layout, nav, badges
│   │   ├── pages/
│   │   │   ├── Dashboard.tsx
│   │   │   ├── CaseDetail.tsx
│   │   │   ├── Submit.tsx
│   │   │   └── Login.tsx
│   │   ├── hooks/
│   │   │   ├── useCaseWebSocket.ts
│   │   │   └── useCase.ts
│   │   ├── stores/
│   │   │   └── authStore.ts
│   │   ├── api/
│   │   │   └── client.ts          # Axios + React Query config
│   │   └── types/
│   │       └── index.ts           # Shared TypeScript types
│   ├── package.json
│   └── vite.config.ts
├── infra/
│   ├── docker/
│   │   ├── Dockerfile.api
│   │   ├── Dockerfile.worker
│   │   └── Dockerfile.frontend
│   ├── docker-compose.yml
│   ├── docker-compose.prod.yml
│   ├── k8s/                       # Helm chart
│   └── nginx/nginx.conf
└── scripts/
    ├── seed_db.py
    └── test_analysis.py
```
