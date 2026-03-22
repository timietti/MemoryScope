# MemoryScope

**Automated memory forensics analysis platform.** Submit a raw memory dump, get back a structured threat assessment — powered by Volatility3 and an AI agent pipeline built on Claude.

![Python](https://img.shields.io/badge/Python-3.12-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=black)
![Volatility3](https://img.shields.io/badge/Volatility3-latest-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What it does

Upload a Windows, Linux, or macOS memory dump through the web UI. MemoryScope automatically:

1. **Detects the OS** and selects the relevant Volatility3 plugin set
2. **Runs 30+ forensic plugins** in parallel across 9 domains — processes, code injection, network, persistence, rootkits, credentials, filesystem, handles, and memory strings
3. **Enriches extracted IOCs** against VirusTotal (IPs, domains, file hashes)
4. **Runs a multi-step AI agent** that analyses each forensic domain through domain-specific sub-agents, then synthesises a cross-domain threat assessment
5. **Produces a structured report** with a CLEAN / SUSPICIOUS / COMPROMISED verdict, confidence score, MITRE ATT&CK technique mappings, IOC table, reconstructed event timeline, and analyst recommendations

All plugin outputs and the final report are viewable in the same web application with real-time progress updates via WebSocket.

---

## Screenshots

```
┌─────────────────────────────────────────────────────────────┐
│  MemoryScope                              [+ Submit Dump]    │
├─────────────────────────────────────────────────────────────┤
│  Cases                                                       │
│                                                              │
│  ID       Name                  OS       Status             │
│  A3F9B2C1 ACME-Workstation-01   WINDOWS  ● COMPLETE         │
│  D7E1C4F2 prod-server-linux-02  LINUX    ● AI ANALYSIS      │
│  B5K2M8N9 macbook-finance-03    MACOS    ● ANALYZING        │
└─────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│  COMPROMISED          Confidence: 91%                        │
│  ─────────────────────────────────────────────────────────── │
│  MITRE ATT&CK    T1059.001 PowerShell · T1055 Process Inject │
│  IOCs            192.168.45.201 · 8/72 VT detections        │
│  Timeline        T+0  Hollowed svchost.exe detected         │
│                  T+3m Encoded PS payload executed           │
│                  T+7m C2 beacon to 192.168.45.201:4444      │
└──────────────────────────────────────────────────────────────┘
```

---

## Architecture

```
Browser (React SPA)
      │ HTTPS / WebSocket
      ▼
FastAPI + Celery  ──→  PostgreSQL  (cases, plugin runs, reports, IOCs)
      │            ──→  MinIO/S3   (dump files, encrypted at rest)
      │            ──→  Redis      (task queue, pub/sub, cache)
      ▼
Worker (isolated Docker container)
  ├── Volatility3 runner      parallel plugin execution, per-OS
  ├── IOC enrichment          VirusTotal batch lookup
  └── AI Agent (Anthropic)
        ├── Domain sub-agents  process / network / injection / rootkit / ...
        └── Orchestrator       cross-domain synthesis → structured report
                    │
              External APIs
              Anthropic Claude  (primary model)
              OpenAI GPT-4o     (optional fallback)
              VirusTotal        (IOC enrichment)
```

Workers run in rootless Docker containers with read-only filesystems, no outbound internet access, and tmpfs analysis directories that are wiped after every job. Raw dump bytes never reach the AI API — only normalised, summarised text is sent.

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, React Query, Axios |
| API | FastAPI 0.115, Python 3.12, Pydantic v2, SQLAlchemy 2 async |
| Task queue | Celery 5, Redis 7 |
| Database | PostgreSQL 16, JSONB columns for plugin output |
| Object storage | MinIO (S3-compatible), AES-256 server-side encryption |
| Forensics | Volatility3 with symbol server integration |
| AI | Anthropic Claude (claude-opus-4-5 / claude-sonnet-4-5), tool-use agent loop |
| Real-time | WebSocket (FastAPI), Redis Pub/Sub fan-out |
| Containers | Docker, Docker Compose, Kubernetes Helm chart (roadmap) |

---

## Quick start

### Prerequisites

- Python 3.12+
- Node.js 20+
- Docker Desktop

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_USERNAME/MemoryScope.git
cd MemoryScope

cp .env.example .env
# Edit .env — minimum required values:
#   SECRET_KEY=<long random string>
#   ANTHROPIC_API_KEY=sk-ant-...
#   DB_PASSWORD=localdev
#   MINIO_ACCESS_KEY=memoryscope
#   MINIO_SECRET_KEY=memoryscope123
```

### 2. Install dependencies

```bash
make install          # creates backend .venv + pip install + npm install
python scripts/create_inits.py   # adds Python __init__.py files
```

### 3. Start infrastructure

```bash
make infra            # starts Postgres, Redis, MinIO in Docker
make seed             # creates admin@memoryscope.local / changeme123!
```

> **Note:** The database schema is applied automatically when the Postgres container first starts (via `docker-entrypoint-initdb.d`). You do not need to run `make schema` manually.

### 4. Run the application

Open three terminals (or use the VSCode compound launch config):

```bash
make backend          # FastAPI on :8000
make worker           # Celery analysis worker
make frontend         # React dev server on :3000
```

Open **http://localhost:3000** and log in.
API docs are at **http://localhost:8000/api/docs**.

### Full Docker stack

```bash
docker compose up --build
```

---

## Forensic plugin coverage

| Domain | Plugins | What the AI looks for |
|---|---|---|
| Process Analysis | pslist, pstree, cmdline, dlllist, envars | Orphaned processes, unusual parent chains, obfuscated command lines, DLL injection |
| Code Injection | malfind, vadinfo, vadyarascan | RWX memory regions with PE headers, process hollowing, shellcode |
| Network | netstat, netscan | C2 beacons, unusual listening ports, connections to known-bad IPs |
| Persistence | registry Run/RunOnce, services, scheduled tasks, bash history | Malicious autorun entries, unexpected services, attacker commands |
| Rootkits | modules, driverscan, ssdt, lsmod, check_modules, check_syscall | Hidden kernel modules, SSDT hooks, DKOM artefacts, hidden LKMs |
| Credentials | hashdump, lsadump | LSASS tampering, extracted NTLM hashes, LSA secrets |
| Filesystem | filescan, dumpfiles | Suspicious cached file objects, malware dropped to disk |
| Memory Artifacts | handles | Mutex names that fingerprint known malware families |
| Memory Strings | strings | Embedded C2 URLs, IPs, encoded payloads |

All plugins run for the detected OS (Windows, Linux, or macOS). Each output is normalised into a typed schema before the AI receives it.

---

## AI agent design

The agent is a multi-step reasoning pipeline, not a single prompt.

```
Orchestrator (claude-opus-4-5)
  │
  ├── Process Analyst sub-agent    (claude-sonnet-4-5)
  ├── Injection Detector sub-agent
  ├── Network Analyst sub-agent
  ├── Persistence Hunter sub-agent
  └── Rootkit Detector sub-agent
           │
           └── Tool calls (on demand)
                 get_plugin_output(plugin_name)
                 get_process_details(pid)
                 search_strings(pattern)
                 lookup_ioc(hash_or_ip)
                 list_network_connections()
                 get_registry_key(path)
```

Each sub-agent fetches only the plugin data it needs via tool calls, keeping context lean. Large outputs (e.g. `windows.strings` on a 32 GB dump) are pre-summarised before the agent sees them — the full raw output is always stored in the database and viewable in the UI.

The orchestrator synthesises sub-agent findings into a structured JSON report that includes:

- `verdict` — CLEAN / SUSPICIOUS / COMPROMISED / INCONCLUSIVE
- `confidence` — 0–100 with reasoning
- `mitre_ttps` — MITRE ATT&CK T-codes with evidence citations
- `iocs` — extracted indicators with severity and VirusTotal data
- `timeline` — reconstructed event sequence
- `executive_summary` — plain-English paragraph for stakeholders
- `technical_narrative` — full analyst-grade write-up
- `recommendations` — prioritised response actions

---

## Project structure

```
MemoryScope/
├── backend/
│   ├── main.py                  FastAPI application entry point
│   ├── config.py                Settings (pydantic-settings, reads .env)
│   ├── api/routers/             REST endpoints + WebSocket
│   ├── core/
│   │   ├── agent/               AI orchestrator, sub-agents, tools, prompts
│   │   ├── plugins/             Volatility3 runner + 30-plugin registry
│   │   └── storage.py           MinIO/S3 client
│   ├── db/                      SQLAlchemy models + Alembic migrations
│   ├── workers/                 Celery task pipeline
│   ├── schemas/                 Pydantic API response schemas
│   └── utils/                   VirusTotal enrichment, notifications, PDF export
├── frontend/
│   └── src/
│       ├── pages/               Dashboard, Submit, CaseDetail (4-tab), Login
│       ├── hooks/               useCaseWebSocket, useCase (React Query)
│       ├── api/                 Axios client + all API helpers
│       └── types/               Shared TypeScript types
├── infra/
│   ├── docker/                  Dockerfile.api / .worker / .frontend
│   └── nginx/                   Reverse proxy with WS upgrade + TLS
├── docs/
│   ├── schema.sql               Full PostgreSQL schema
│   └── api.http                 REST Client test file (VSCode)
├── scripts/
│   ├── create_inits.py          Generates Python __init__.py files
│   └── seed_db.py               Creates admin user
├── docker-compose.yml
├── Makefile                     Dev shortcuts (make help)
└── SETUP.md                     Detailed setup guide
```

---

## Configuration reference

All settings are read from the `.env` file via `pydantic-settings`.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — use a long random string |
| `DATABASE_URL` | ✅ | `postgresql+asyncpg://user:pass@host/db` |
| `ANTHROPIC_API_KEY` | ✅ | Claude API key for the AI agent |
| `DB_PASSWORD` | ✅ | PostgreSQL password (used in docker-compose) |
| `MINIO_ACCESS_KEY` | ✅ | MinIO access key |
| `MINIO_SECRET_KEY` | ✅ | MinIO secret key |
| `OPENAI_API_KEY` | — | Optional GPT-4o fallback |
| `VIRUSTOTAL_API_KEY` | — | Optional IOC enrichment (free tier: 4 req/min) |
| `PRIMARY_MODEL` | — | Default: `claude-opus-4-5` |
| `FAST_MODEL` | — | Default: `claude-sonnet-4-5` (sub-agents) |
| `PLUGIN_TIMEOUT_SECONDS` | — | Default: `600` (10 min per plugin) |
| `MAX_DUMP_SIZE_BYTES` | — | Default: `68719476736` (64 GB) |
| `DUMP_RETENTION_DAYS` | — | Default: `30` — dumps purged after this |

---

## Security notes

Memory dumps contain live credentials, encryption keys, PII, and active malware. Treat the platform accordingly.

- **Worker isolation** — analysis containers run rootless with seccomp profiles, read-only root filesystems, and tmpfs working directories wiped after every job
- **No dump data to AI** — only normalised, summarised text from plugin outputs is sent to the Anthropic API; raw dump bytes never leave the object store
- **Encryption at rest** — dumps are stored with AES-256 server-side encryption in MinIO/S3
- **Network isolation** — worker containers have no direct internet access; outbound calls go through an egress proxy to AI and symbol server endpoints only
- **Retention policies** — dump files are automatically purged after 30 days (configurable); reports are retained for 365 days

---

## Development

```bash
make help             # list all available commands
make lint             # ruff + mypy
make test             # pytest
make docker-up        # full stack via Docker Compose
make docker-logs      # tail api + worker logs
```

VSCode users: install the recommended extensions (`.vscode/extensions.json`) and use the **Full Backend** compound launch config to debug the API and Celery worker together.

---

## Roadmap

- **Phase 1** — Core pipeline: upload → Volatility3 → results in UI *(current)*
- **Phase 2** — AI agent integration: structured report with MITRE ATT&CK mapping
- **Phase 3** — Production hardening: auth/RBAC, PDF export, Kubernetes Helm chart, observability
- **Phase 4** — Advanced: YARA rule execution in workers, multi-dump correlation, SIEM/SOAR webhook integrations, custom plugin upload

---

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Make your changes and add tests
4. Run `make lint && make test`
5. Open a pull request

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

> **MemoryScope** is a forensics tool intended for legitimate incident response and security research. Only analyse memory dumps you have authorisation to examine.
