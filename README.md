# MemoryScope

**Automated memory forensics analysis platform.** Submit a raw memory dump, get back a structured threat assessment — powered by Volatility3 and a multi-agent AI pipeline built on Claude.

![Python](https://img.shields.io/badge/Python-3.12-3776ab?style=flat-square&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?style=flat-square&logo=fastapi&logoColor=white)
![React](https://img.shields.io/badge/React-18-61dafb?style=flat-square&logo=react&logoColor=black)
![Volatility3](https://img.shields.io/badge/Volatility3-latest-orange?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What it does

Upload a Windows, Linux, or macOS memory dump through the web UI. MemoryScope automatically:

1. **Detects the OS** and builds symbol tables if needed (Linux ISF auto-generated for Ubuntu, Debian, Fedora, and RHEL-family kernels; universal debuginfod fallback for any distro)
2. **Presents 140+ Volatility3 plugins** organised by domain and priority tier — you select which to run
3. **Enriches extracted IOCs** against VirusTotal (IPs, domains, file hashes)
4. **Runs a multi-agent AI pipeline** with domain-specific sub-agents for each forensic area, then synthesises a cross-domain threat assessment
5. **Produces a structured report** with a CLEAN / SUSPICIOUS / COMPROMISED / INCONCLUSIVE verdict, confidence score, MITRE ATT&CK mappings, IOC table, event timeline, and prioritised recommendations
6. **Supports incremental analysis** — run more plugins and re-run AI; the agent builds on the prior report rather than starting from scratch
7. **Exports to PDF** for sharing with stakeholders or filing in ticketing systems

All plugin outputs and the final report are viewable in the same web UI with real-time progress via WebSocket.

---

## Architecture

```
Browser (React SPA)
      │ HTTPS / WebSocket
      ▼
Nginx  ──→  FastAPI (:8000)  ──→  PostgreSQL  (cases, plugin runs, reports, IOCs, KB)
                  │           ──→  MinIO/S3    (dump files)
                  │           ──→  Redis       (Celery broker + pub/sub)
                  ▼
         Celery Workers (isolated containers)
           ├── Triage task          OS detection, symbol table build
           ├── Plugin runner        Volatility3 per-plugin, parallel
           ├── IOC enrichment       VirusTotal batch lookup
           ├── AI analysis          Multi-agent pipeline (Anthropic Claude)
           │     ├── Domain sub-agents   process / network / injection /
           │     │                       rootkit / persistence / credentials /
           │     │                       filesystem / memory / gui_artifacts
           │     └── Orchestrator        cross-domain synthesis → FinalReport
           └── Celery Beat          watch-folder scan, dump purge (scheduled)
```

Workers run in rootless Docker containers with read-only filesystems, seccomp profiles, and tmpfs analysis directories wiped after every job. Raw dump bytes never reach the AI API — only normalised, summarised plugin text is sent.

---

## Tech stack

| Layer | Technology |
|---|---|
| Frontend | React 18, TypeScript, Vite, TanStack Query, Axios |
| API | FastAPI 0.115, Python 3.12, Pydantic v2, SQLAlchemy 2 async |
| Task queue | Celery 5 + Beat, Redis 7 |
| Database | PostgreSQL 16, JSONB columns for plugin output |
| Object storage | MinIO (S3-compatible) |
| Forensics | Volatility3 with automatic Linux symbol table building (Ubuntu, Debian, Fedora, RHEL-family, debuginfod) |
| AI | Anthropic Claude (primary) or any OpenAI-compatible endpoint (Ollama, vLLM, LiteLLM, OpenAI, …) |
| Real-time | WebSocket (FastAPI), Redis Pub/Sub |
| Auth | JWT (access + refresh tokens), OIDC/SSO (Authentik, Okta, Azure AD, …), LDAP/LDAPS |
| Containers | Docker, Docker Compose |

---

## Quick start

### Option A — Automated installer (recommended)

```bash
git clone https://github.com/timietti/MemoryScope.git
cd MemoryScope
bash install.sh
```

`install.sh` asks a series of questions (environment, passwords, SSL), writes `.env`, checks prerequisites, starts the Docker stack, and prints the URL for the first-run setup wizard. Run `bash install.sh --help` for an overview of what it does.

### Option B — Manual setup

#### 1. Prerequisites

- Python 3.11+
- Node.js 18+
- Docker with Docker Compose v2
- `openssl` (for key generation)
- Volatility3 installed on the worker host (see below)

#### 2. Clone and configure

```bash
git clone https://github.com/timietti/MemoryScope.git
cd MemoryScope
cp .env.example .env
# Edit .env — required bootstrap values:
#   SECRET_KEY=<64-char random hex>      openssl rand -hex 32
#   DB_PASSWORD=<password>
#   S3_SECRET_KEY=<password>
```

All other settings (AI keys, Volatility paths, OIDC, retention policies, etc.) are configured from **Admin → Settings** after first login.

#### 3. Install Volatility3

Volatility3 must be installed on the host that runs `make worker` (or inside the worker Docker image for production):

```bash
git clone https://github.com/volatilityfoundation/volatility3.git /opt/volatility3
pip install -r /opt/volatility3/requirements.txt
```

Set the path in **Admin → Settings → Volatility** after first login. Default assumed path: `/opt/volatility3/vol.py`.

#### 4. Linux symbol build prerequisites

Required only when analysing **Linux memory dumps**. MemoryScope automatically tries multiple strategies in order:

1. **Local cache** — uses any matching ISF already in `SYMBOL_CACHE_PATH/linux/`
2. **Remote ISF** — downloads from community symbol index (no extra tools needed)
3. **Debuginfod** — extracts the kernel's GNU build-ID from the dump and fetches the debuginfo ELF from public debuginfod servers (elfutils.org aggregator, then Fedora, Debian, Ubuntu) — works for any distro
4. **Build from source** — downloads the distro debug package, extracts `vmlinux`, runs `dwarf2json`:
   - **Ubuntu** — Launchpad API → `linux-image-*-dbgsym` `.ddeb`
   - **Debian** — snapshot.debian.org JSON API → `.deb` via `dpkg-deb`
   - **Fedora** — Koji XML-RPC → `kernel-debuginfo` `.rpm` via `rpm2cpio`
   - **RHEL-family** (CentOS / Rocky Linux / AlmaLinux / RHEL) — HTTP debuginfo mirrors → `.rpm` via `rpm2cpio`

For strategy 4, install the tools for the distros you expect to analyse:

```bash
# dwarf2json  (required for all — needs Go 1.18+)
go install github.com/volatilityfoundation/dwarf2json@latest

# xz  (required for all)
sudo apt-get install xz-utils  # Debian/Ubuntu
sudo dnf install xz            # Fedora/RHEL

# dpkg-deb  (required for Ubuntu/Debian builds — pre-installed on Debian/Ubuntu)
sudo dnf install dpkg          # Fedora/RHEL host

# rpm2cpio + cpio  (required for Fedora/RHEL builds)
sudo apt-get install rpm2cpio cpio   # Debian/Ubuntu host
sudo dnf install rpm2cpio cpio       # Fedora/RHEL host

# eu-readelf  (optional — speeds up build-ID extraction for debuginfod)
sudo apt-get install elfutils        # Debian/Ubuntu
sudo dnf install elfutils            # Fedora/RHEL
```

> Disk space: ~2 GB free needed during a build. The generated `.json.xz` ISF (~30–80 MB) is cached and reused across all cases with the same kernel version.

You can also upload a pre-built symbol table at case submission time to skip auto-building entirely.

#### 5. Install dependencies

```bash
make install          # creates backend/.venv + pip install + npm install
```

#### 6. Start infrastructure

```bash
make infra            # Postgres, Redis, MinIO in Docker
```

The database schema is applied automatically when the Postgres container first starts.

#### 7. Run the application

Open four terminals:

```bash
make backend          # FastAPI on :8000
make worker           # Celery analysis worker
make beat             # Celery beat scheduler (watch folder, daily purges)
make frontend         # Vite dev server on :3000
```

Navigate to **http://localhost:3000/setup** to create your admin account and configure AI provider and Volatility paths through the first-run wizard.

API docs: **http://localhost:8000/api/docs**

#### Production — full Docker stack

```bash
# Copy SSL certs first (or let install.sh generate self-signed ones)
cp your.crt infra/nginx/certs/server.crt
cp your.key infra/nginx/certs/server.key

docker compose up --build -d
# Then open https://your-domain/setup
```

---

## First-run setup wizard

On first launch MemoryScope shows a setup wizard at `/setup`. It collects:

- Admin account (email, display name, password)
- AI provider — Anthropic API key and model names, or a fallback OpenAI-compatible endpoint
- Volatility3 path, symbol cache path, and dwarf2json path

All of these — and many more runtime settings — can be changed at any time from **Admin → Settings**.

---

## Forensic plugin coverage

MemoryScope ships with **142 plugins** (77 Windows · 41 Linux · 24 macOS) across 10 domains, organised into four priority tiers:

| Priority | Meaning |
|---|---|
| P1 | Always run — essential for any analysis |
| P2 | High-value — strongly recommended |
| P3 | Supplementary — targeted deep-dives |
| P4 | Informational / extended — situational |

| Domain | Example plugins | What the AI looks for |
|---|---|---|
| Process Analysis | pslist, pstree, psscan, cmdline, psxview | Orphaned processes, unusual parent chains, masquerading, obfuscated command lines |
| Code Injection | malfind, hollowprocesses, ldrmodules, processghosting | RWX regions with PE headers, hollowing, DLL injection, ghosting |
| Network | netscan, netstat, sockstat | C2 beacons, unusual listening ports, connections to malicious IPs |
| Persistence | registry Run keys, svcscan, bash history | Malicious autorun entries, unexpected services, attacker commands |
| Rootkits | ssdt, callbacks, driverscan, lsmod, check_syscall | SSDT hooks, hidden kernel modules, DKOM artefacts |
| Credentials | hashdump, cachedump, lsadump | LSASS tampering, extracted NTLM hashes, LSA secrets |
| Filesystem | filescan, dumpfiles | Suspicious file objects cached in memory, malware dropped to disk |
| Memory Artifacts | handles, mutantscan | Mutex names fingerprinting known malware families |
| Memory Strings | strings | Embedded C2 URLs, encoded payloads (Base64/hex) |
| GUI Artifacts | deskscan, desktops, windows, windowstations | Hidden desktop sessions, injected GUI processes (Windows only) |

The UI plugin selector lets you filter by priority tier and toggle domains — select only what you need and run as many batches as you like.

---

## AI agent design

The agent is a multi-step reasoning pipeline, not a single prompt.

```
Orchestrator  (primary model — default: claude-opus-4-6)
  │
  ├── Process Analyst sub-agent    (fast model — default: claude-sonnet-4-6)
  ├── Injection Detector sub-agent
  ├── Network Analyst sub-agent
  ├── Persistence Hunter sub-agent
  ├── Rootkit Detector sub-agent
  ├── Credentials sub-agent
  ├── Filesystem sub-agent
  ├── Memory Artifacts sub-agent
  └── Memory Strings sub-agent
           │
           └── Tool calls (on demand)
                 get_plugin_output(plugin_name)
                 get_process_details(pid)
                 lookup_ioc(hash_or_ip)
                 list_network_connections()
                 get_registry_key(path)
```

Each sub-agent fetches only the plugin data it needs via tool calls, keeping context lean. Plugins with high row counts are summarised before the agent sees them — the full output is always stored and viewable in the UI.

### Incremental analysis

When you run additional plugins after a first report exists, the AI pipeline operates incrementally: sub-agents receive the prior finding as context and only process new plugin outputs; the orchestrator produces a revised report that supersedes the old one without discarding previously confirmed evidence.

### Knowledge base notes

Analyst notes (KB articles) can be attached to any case and are automatically passed as authoritative context to the AI agent. Use them to:

- Describe known-good behaviour for the environment being analysed
- Share prior investigation findings across team members
- Ask the AI specific questions — it will address them in `technical_narrative`

### Report output

```json
{
  "verdict":            "compromised",
  "confidence":         91,
  "verdict_reasoning":  "...",
  "executive_summary":  "...",
  "technical_narrative":"...",
  "mitre_ttps":         [{ "technique": "T1059.001", "severity": "high", ... }],
  "iocs":               [{ "ioc_type": "ip", "value": "192.168.45.201", ... }],
  "timeline":           [{ "event": "svchost.exe hollowed", ... }],
  "recommendations":    [{ "priority": 1, "action": "...", ... }]
}
```

Reports are viewable in the UI, exportable as PDF, and stored with full history — re-running analysis adds a new version rather than overwriting.

---

## Watch folder

MemoryScope can automatically import dump files dropped into a directory. Configure in **Admin → Settings → Watch Folder**:

- Enable/disable the watcher
- Set the watch directory path
- Control poll interval and stable-age threshold (prevents reading files mid-write)

Requires `make beat` (or the `beat` Docker service) to be running — the scan is a Celery Beat periodic task.

---

## Configuration reference

`.env` holds only **bootstrap settings** — values the app needs before it can connect to the database. Everything else is managed from **Admin → Settings**.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | JWT signing key — use `openssl rand -hex 32` |
| `DATABASE_URL` | ✅ | `postgresql+asyncpg://user:pass@host:port/db` |
| `DB_PASSWORD` | ✅ | PostgreSQL password (used by docker-compose) |
| `REDIS_URL` | ✅ | `redis://localhost:6379/0` |
| `S3_ENDPOINT` | ✅ | MinIO/S3 URL, e.g. `http://localhost:9000` |
| `S3_ACCESS_KEY` | ✅ | MinIO access key |
| `S3_SECRET_KEY` | ✅ | MinIO secret key (min 16 chars) |
| `ENV` | — | `development` or `production` |
| `DOMAIN` | — | Hostname used by nginx (production) |
| `VITE_API_BASE_URL` | — | API base URL seen by the browser |

**Runtime settings** (set via Admin → Settings after first login):

| Setting | Default | Notes |
|---|---|---|
| `anthropic_api_key` | *(from setup wizard)* | Required if using Anthropic Claude |
| `primary_model` | `claude-opus-4-6` | Orchestrator model (Anthropic) |
| `fast_model` | `claude-sonnet-4-6` | Sub-agent model (Anthropic) |
| `fallback_api_url` | *(empty)* | Base URL of any OpenAI-compatible endpoint — e.g. `http://ollama:11434/v1`. Used when `anthropic_api_key` is empty. |
| `fallback_api_key` | *(empty)* | API key for the fallback endpoint. Use any non-empty string (e.g. `"ollama"`) for local models that don't require authentication. |
| `fallback_model` | *(empty)* | Model name to use with the fallback endpoint — e.g. `llama3.2`, `mistral`, `gpt-4o`. Both orchestrator and sub-agent calls use this model. |
| `ldap_enabled` | `false` | Master switch for LDAP authentication |
| `ldap_url` | *(empty)* | `ldap://host:389` or `ldaps://host:636` |
| `ldap_use_starttls` | `false` | Upgrade plain LDAP connection to TLS |
| `ldap_tls_verify` | `true` | Verify TLS certificate |
| `ldap_bind_dn` | *(empty)* | Service-account DN for directory search |
| `ldap_bind_password` | *(empty)* | Service-account password (stored encrypted) |
| `ldap_base_dn` | *(empty)* | Search base, e.g. `dc=example,dc=com` |
| `ldap_user_filter` | `(sAMAccountName={username})` | User lookup filter; `{username}` is substituted |
| `ldap_attr_email` | `mail` | LDAP attribute for email |
| `ldap_attr_display_name` | `displayName` | LDAP attribute for display name |
| `ldap_group_base_dn` | *(defaults to base DN)* | Base DN for group membership search |
| `ldap_admin_group` | *(empty)* | Full DN of group mapped to the `admin` role |
| `ldap_analyst_group` | *(empty)* | Full DN of group mapped to the `analyst` role |
| `ldap_viewer_group` | *(empty)* | Full DN of group mapped to the `viewer` role |
| `ldap_jit_provisioning` | `true` | Auto-create accounts on first LDAP login |
| `virustotal_api_key` | *(optional)* | |
| `volatility_path` | `/opt/volatility3/vol.py` | |
| `symbol_cache_path` | `/opt/volatility3/volatility3/symbols` | |
| `dwarf2json_path` | `dwarf2json` | |
| `plugin_timeout_seconds` | `600` | |
| `max_dump_size_bytes` | `68719476736` (64 GB) | |
| `dump_retention_days` | `30` | |
| `report_retention_days` | `365` | |

### AI provider selection

MemoryScope supports two AI backends:

**Anthropic Claude** (default):
Set `anthropic_api_key` in Admin → Settings. Choose models with `primary_model` (orchestrator) and `fast_model` (sub-agents).

**Any OpenAI-compatible endpoint** (fallback):
Leave `anthropic_api_key` empty and configure all three fallback fields. The same model is used for both orchestrator and sub-agent calls.

```
# Examples for common local / self-hosted setups

# Ollama
fallback_api_url   = http://ollama:11434/v1
fallback_api_key   = ollama
fallback_model     = llama3.2

# vLLM
fallback_api_url   = http://vllm-server:8000/v1
fallback_api_key   = <your-key>
fallback_model     = mistral-7b-instruct

# LiteLLM proxy (can route to many providers)
fallback_api_url   = http://litellm:4000
fallback_api_key   = <your-key>
fallback_model     = ollama/llama3.2

# OpenAI (direct)
fallback_api_url   = https://api.openai.com/v1
fallback_api_key   = sk-...
fallback_model     = gpt-4o
```

> Tool calling (function calling) must be supported by the model for the agent pipeline to work correctly. Verify this for your chosen model before running analysis.

---

## SSO / OIDC / LDAP

MemoryScope supports three authentication backends, all configured from **Admin → Settings** without any login-page changes:

**Local accounts** (default) — username/password with bcrypt, JWT access + refresh tokens, server-side revocation on logout.

**OIDC / SSO** — any standard OpenID Connect provider (Authentik, Okta, Azure AD, …). Set `oidc_client_id` to enable; leave blank to disable.

**LDAP / LDAPS** — enable `ldap_enabled` and point at your directory server. Supports plain LDAP, LDAPS, and StartTLS. The login endpoint tries LDAP first and falls back to local auth on failure, so mixed environments work without changes to the UI.

LDAP features:
- Configurable bind DN, base DN, and user search filter (`{username}` substitution)
- Group-based role mapping — map directory groups to **admin**, **analyst**, or **viewer** roles
- Just-in-time (JIT) provisioning — auto-creates accounts on first login; toggle with `ldap_jit_provisioning`
- **Test Connection** button in Admin → Settings → LDAP validates the service-account bind instantly

OIDC also supports JIT provisioning for users whose email is not yet registered.

### User roles

| Role | Access |
|---|---|
| `admin` | Full access including user management, settings, and audit logs |
| `analyst` | Submit cases, run plugins, trigger AI analysis, manage KB articles |
| `viewer` | Read-only — view cases, reports, and plugin output; no write actions |

---

## Security notes

Memory dumps contain live credentials, encryption keys, PII, and active malware. Treat the platform accordingly.

- **Worker isolation** — analysis containers run rootless with seccomp profiles, read-only root filesystems, dropped capabilities, and tmpfs working directories wiped after every job
- **No dump data to AI** — only normalised, summarised plugin text is sent to the AI provider; raw dump bytes never leave the object store
- **Network isolation** — worker containers are on an internal Docker network with no direct internet; outbound AI/VT calls go through the API container on the external network
- **Retention policies** — dump files are automatically purged after `dump_retention_days` (default 30); reports after `report_retention_days` (default 365)
- **JWT rotation** — refresh tokens are stored hashed in the database and rotated on every use; logout revokes server-side
- **Audit log** — all user actions and admin changes are recorded in Admin → Logs

---

## Development

```bash
make help             # list all available commands
make lint             # ruff + mypy
make test             # pytest
make infra            # start Postgres, Redis, MinIO
make backend          # FastAPI :8000 with --reload
make worker           # Celery worker
make beat             # Celery beat (watch folder, purges)
make frontend         # Vite :3000 with HMR
make infra-down       # stop infrastructure containers
make docker-up        # full production stack
make docker-logs      # tail api + worker logs
```

Run a single test:

```bash
PYTHONPATH=. backend/.venv/bin/pytest backend/tests/path/to/test.py::test_name -v
```

---

## Project structure

```
MemoryScope/
├── backend/
│   ├── main.py                  FastAPI application entry point
│   ├── config.py                Pydantic-settings (reads .env + DB overrides)
│   ├── api/routers/             REST endpoints + WebSocket
│   │   ├── cases.py             Case CRUD, plugin runs, report, IOCs, downloads
│   │   ├── kb.py                Knowledge base article management
│   │   ├── admin.py             Users, settings, system health, audit logs
│   │   └── auth.py              Login, refresh, logout, OIDC
│   ├── core/
│   │   ├── agent/               AI orchestrator, sub-agents, tools, prompts, schemas
│   │   ├── plugins/             Volatility3 runner + 142-plugin registry + parsers
│   │   ├── symbols/             Linux ISF auto-builder (dwarf2json pipeline)
│   │   └── storage.py           MinIO/S3 client
│   ├── db/                      SQLAlchemy ORM models + Alembic migrations
│   ├── workers/                 Celery tasks (triage, plugins, enrich, AI, watch, purge)
│   ├── schemas/                 Pydantic API response schemas
│   └── utils/                   PDF export, VirusTotal, notifications, DB settings
├── frontend/
│   └── src/
│       ├── pages/               Cases, Submit, CaseDetail, AIStats, Admin, Setup, Login
│       ├── hooks/               useCaseWebSocket, React Query hooks
│       ├── api/                 Axios client + all API method wrappers
│       └── types/               Shared TypeScript interfaces
├── infra/
│   ├── docker/                  Dockerfile.api / .worker / .frontend
│   └── nginx/                   Reverse proxy (TLS, WS upgrade, rate limiting)
│       └── certs/               SSL certificate location (server.crt / server.key)
├── docs/
│   ├── schema.sql               Full PostgreSQL schema (DDL)
│   └── api.http                 REST Client test file (VSCode)
├── scripts/
│   ├── create_inits.py          Generates Python __init__.py stubs
│   └── seed_db.py               Creates a dev admin user (alternative to wizard)
├── install.sh                   Interactive installer (recommended entry point)
├── docker-compose.yml           Full production stack definition
├── Makefile                     Dev shortcuts
└── CLAUDE.md                    AI coding assistant guidance
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

> **MemoryScope** is a forensics tool intended for legitimate incident response and security research. Only analyse memory dumps you have authorisation to examine.
