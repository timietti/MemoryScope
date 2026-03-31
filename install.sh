#!/usr/bin/env bash
# install.sh — MemoryScope interactive installer
# Usage: bash install.sh
set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'
CYAN='\033[0;36m'; BOLD='\033[1m'; DIM='\033[2m'; RESET='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}${BOLD}  [•]${RESET} $*"; }
ok()      { echo -e "${GREEN}${BOLD}  [✓]${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}  [!]${RESET} $*"; }
die()     { echo -e "${RED}${BOLD}  [✗]${RESET} $*" >&2; exit 1; }
section() { echo; echo -e "${BOLD}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

ask() {
  # ask "Prompt text" "default value"  →  echoes the answer
  local prompt="$1" default="${2:-}"
  local answer
  if [[ -n "$default" ]]; then
    read -rp "$(echo -e "  ${DIM}${prompt}${RESET} [${CYAN}${default}${RESET}]: ")" answer
    echo "${answer:-$default}"
  else
    read -rp "$(echo -e "  ${DIM}${prompt}${RESET}: ")" answer
    echo "$answer"
  fi
}

ask_secret() {
  # ask_secret "Prompt text" ["placeholder label"]  →  echoes the entered secret (hidden)
  local prompt="$1" placeholder="${2:-}"
  local answer
  if [[ -n "$placeholder" ]]; then
    read -rsp "$(echo -e "  ${DIM}${prompt}${RESET} [${CYAN}${placeholder}${RESET}]: ")" answer
  else
    read -rsp "$(echo -e "  ${DIM}${prompt}${RESET}: ")" answer
  fi
  echo
  echo "$answer"
}

ask_yn() {
  # ask_yn "Question?" "y|n (default)"  →  returns 0 for yes, 1 for no
  local prompt="$1" default="${2:-y}" answer hint
  hint="$([ "$default" = "y" ] && echo "Y/n" || echo "y/N")"
  read -rp "$(echo -e "  ${DIM}${prompt}${RESET} [${hint}]: ")" answer
  answer="${answer:-$default}"
  [[ "$answer" =~ ^[Yy] ]]
}

gen_secret() {
  # Generate a cryptographically random hex string (64 chars = 256 bits)
  openssl rand -hex 32
}

gen_password() {
  # Generate a random password (alphanumeric, 32 chars, safe for connection strings)
  openssl rand -base64 32 | tr -d '/+=' | head -c 32
}

# ── Banner ────────────────────────────────────────────────────────────────────
clear
echo
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
  ███╗   ███╗███████╗███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗███████╗ ██████╗ ██████╗ ██████╗ ███████╗
  ████╗ ████║██╔════╝████╗ ████║██╔═══██╗██╔══██╗╚██╗ ██╔╝██╔════╝██╔════╝██╔═══██╗██╔══██╗██╔════╝
  ██╔████╔██║█████╗  ██╔████╔██║██║   ██║██████╔╝ ╚████╔╝ ███████╗██║     ██║   ██║██████╔╝█████╗
  ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗  ╚██╔╝  ╚════██║██║     ██║   ██║██╔═══╝ ██╔══╝
  ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   ███████║╚██████╗╚██████╔╝██║     ███████╗
  ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚══════╝
BANNER
echo -e "${RESET}"
echo -e "  ${BOLD}Memory Forensics & Threat Intelligence Platform${RESET}  ${DIM}— Installer${RESET}"
echo -e "  ${DIM}$(date '+%Y-%m-%d %H:%M:%S')${RESET}"
echo

# ── 1. Environment mode ───────────────────────────────────────────────────────
section "1 / 11  Environment"
echo -e "  ${DIM}prod  — full Docker stack with nginx TLS termination (recommended)${RESET}"
echo -e "  ${DIM}dev   — infrastructure in Docker; API/worker/frontend run locally${RESET}"
echo
MODE=$(ask "Environment" "prod")
[[ "$MODE" == "prod" || "$MODE" == "dev" ]] || { warn "Unknown mode '${MODE}', defaulting to prod"; MODE="prod"; }
ok "Mode: ${MODE}"

# ── 2. SECRET_KEY ─────────────────────────────────────────────────────────────
section "2 / 11  Secret Key"
echo -e "  ${DIM}Used to sign JWT tokens. Changing this invalidates all active sessions.${RESET}"
echo
if ask_yn "Generate a random SECRET_KEY?" "y"; then
  SECRET_KEY=$(gen_secret)
  ok "SECRET_KEY generated (256-bit random)"
else
  while true; do
    SECRET_KEY=$(ask_secret "SECRET_KEY (minimum 32 characters)")
    [[ ${#SECRET_KEY} -ge 32 ]] && break
    warn "Must be at least 32 characters — try again"
  done
  ok "SECRET_KEY accepted"
fi

# ── 3. Database ───────────────────────────────────────────────────────────────
section "3–6 / 11  Database (PostgreSQL)"
echo -e "  ${DIM}Note: the bundled Docker PostgreSQL always uses username 'memoryscope'.${RESET}"
echo -e "  ${DIM}Set a different username only when connecting to an external database.${RESET}"
echo
DB_USER=$(ask "Database username" "memoryscope")
DB_NAME="memoryscope"   # database name is always memoryscope

echo
if ask_yn "Generate a random database password?" "y"; then
  DB_PASSWORD=$(gen_password)
  ok "Database password generated"
else
  while true; do
    DB_PASSWORD=$(ask_secret "Database password (minimum 12 characters)")
    [[ ${#DB_PASSWORD} -ge 12 ]] && break
    warn "Must be at least 12 characters — try again"
  done
  ok "Database password accepted"
fi

echo
DB_HOST=$(ask "Database host / IP" "localhost")
DB_PORT=$(ask "Database port"       "5432")
ok "Database: postgresql://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"

# ── 4–5. Object Storage ───────────────────────────────────────────────────────
section "7–10 / 11  Object Storage (MinIO / S3)"
S3_HOST=$(ask "MinIO / S3 host / IP" "localhost")
S3_PORT=$(ask "MinIO / S3 port"      "9000")
S3_ACCESS_KEY=$(ask "S3 access key"  "memoryscope")

echo
if ask_yn "Generate a random S3 secret key?" "y"; then
  S3_SECRET_KEY=$(gen_password)
  ok "S3 secret key generated"
else
  while true; do
    S3_SECRET_KEY=$(ask_secret "S3 secret key (minimum 16 characters)")
    [[ ${#S3_SECRET_KEY} -ge 16 ]] && break
    warn "Must be at least 16 characters — try again"
  done
  ok "S3 secret key accepted"
fi

# ── 5. SSL / Domain (prod only) ───────────────────────────────────────────────
DOMAIN="localhost"
VITE_API_BASE_URL="http://localhost:8000"
SELF_SIGNED=false
SSL_CERT_SRC=""
SSL_KEY_SRC=""

if [[ "$MODE" == "prod" ]]; then
  section "11 / 11  Domain & SSL"
  DOMAIN=$(ask "Domain name (e.g. memoryscope.example.com)" "localhost")
  VITE_API_BASE_URL="https://${DOMAIN}"

  echo
  echo -e "  SSL certificate options:"
  echo -e "  ${DIM}  1) Provide existing certificate files (CA-signed or Let's Encrypt)${RESET}"
  echo -e "  ${DIM}  2) Generate a self-signed certificate (default — fine for internal use)${RESET}"
  echo

  if ask_yn "Use existing SSL certificate files?" "n"; then
    while true; do
      SSL_CERT_SRC=$(ask "Path to certificate file (.crt / .pem)")
      [[ -f "$SSL_CERT_SRC" ]] && break
      warn "File not found: ${SSL_CERT_SRC}"
    done
    while true; do
      SSL_KEY_SRC=$(ask "Path to private key file (.key / .pem)")
      [[ -f "$SSL_KEY_SRC" ]] && break
      warn "File not found: ${SSL_KEY_SRC}"
    done
    ok "SSL files verified"
  else
    SELF_SIGNED=true
    ok "Will generate a self-signed certificate for '${DOMAIN}'"
  fi
else
  section "11 / 11  SSL"
  echo -e "  ${DIM}Skipped — dev mode uses plain HTTP.${RESET}"
fi

# ── Confirmation ──────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BOLD}  Configuration summary${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  Mode         : ${CYAN}${MODE}${RESET}"
echo -e "  Database     : postgresql://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
echo -e "  Redis        : redis://localhost:6379/0"
echo -e "  S3 endpoint  : http://${S3_HOST}:${S3_PORT}  (key: ${S3_ACCESS_KEY})"
if [[ "$MODE" == "prod" ]]; then
  echo -e "  Domain       : ${DOMAIN}"
  echo -e "  SSL          : $($SELF_SIGNED && echo 'self-signed (auto-generated)' || echo 'provided files')"
fi
echo -e "  SECRET_KEY   : ${DIM}(generated/set above)${RESET}"
echo -e "  DB password  : ${DIM}(generated/set above)${RESET}"
echo -e "  S3 secret    : ${DIM}(generated/set above)${RESET}"
echo
ask_yn "Proceed with installation?" "y" || { echo "  Aborted."; exit 0; }

# ═════════════════════════════════════════════════════════════════════════════
#  INSTALLATION BEGINS
# ═════════════════════════════════════════════════════════════════════════════

# ── Check prerequisites ────────────────────────────────────────────────────────
section "Checking prerequisites"

check_cmd() {
  # Returns 0 if found, 1 if not. Prints status.
  local cmd="$1" label="${2:-$1}"
  if command -v "$cmd" &>/dev/null; then
    ok "${label}: $(command -v "$cmd")"
    return 0
  fi
  return 1
}

# Docker
if ! check_cmd docker "Docker"; then
  if ask_yn "Docker not found. Install it automatically? (requires root/sudo)" "y"; then
    info "Installing Docker via get.docker.com..."
    curl -fsSL https://get.docker.com | sudo sh
    sudo systemctl enable --now docker 2>/dev/null || true
    # Add current user to docker group so they don't need sudo
    if ! groups "$USER" 2>/dev/null | grep -q docker; then
      sudo usermod -aG docker "$USER" 2>/dev/null || true
      warn "Added ${USER} to the docker group. Log out and back in for this to take effect,"
      warn "or run: newgrp docker"
    fi
    check_cmd docker "Docker" || die "Docker installation failed. Install manually: https://docs.docker.com/engine/install/"
  else
    die "Docker is required. Install from: https://docs.docker.com/engine/install/"
  fi
fi

# Docker Compose (v2 plugin preferred over v1 standalone)
COMPOSE=""
if docker compose version &>/dev/null 2>&1; then
  ok "Docker Compose v2 (plugin)"
  COMPOSE="docker compose"
elif command -v docker-compose &>/dev/null; then
  warn "Using docker-compose v1 — consider upgrading to Docker Compose v2"
  COMPOSE="docker-compose"
else
  info "Docker Compose plugin not found. Attempting install..."
  sudo apt-get install -y docker-compose-plugin 2>/dev/null || \
  sudo yum install -y docker-compose-plugin 2>/dev/null || \
  die "Could not install Docker Compose. Install manually: https://docs.docker.com/compose/install/"
  COMPOSE="docker compose"
  ok "Docker Compose installed"
fi

# OpenSSL — needed for key generation and self-signed certs
if ! check_cmd openssl "OpenSSL"; then
  info "Installing OpenSSL..."
  sudo apt-get install -y openssl 2>/dev/null || \
  sudo yum install -y openssl 2>/dev/null || \
  die "OpenSSL not found and could not be installed automatically"
  check_cmd openssl "OpenSSL"
fi

# curl — needed for public-IP detection
check_cmd curl "curl" || warn "curl not found — public IP detection will be skipped"

# Dev-mode extras
if [[ "$MODE" == "dev" ]]; then

  # Python 3.11+
  PY_CMD=""
  for cmd in python3.13 python3.12 python3.11 python3; do
    if command -v "$cmd" &>/dev/null; then
      if "$cmd" -c 'import sys; exit(0 if sys.version_info >= (3,11) else 1)' 2>/dev/null; then
        PY_VER=$("$cmd" --version 2>&1)
        ok "Python: $cmd ($PY_VER)"
        PY_CMD="$cmd"
        break
      fi
    fi
  done
  [[ -n "$PY_CMD" ]] || die "Python 3.11+ required for dev mode. Install from https://python.org"

  # Node.js 18+
  if command -v node &>/dev/null; then
    NODE_VER=$(node --version)
    NODE_MAJOR=$(echo "$NODE_VER" | tr -d 'v' | cut -d. -f1)
    if [[ "$NODE_MAJOR" -ge 18 ]]; then
      ok "Node.js: $NODE_VER"
    else
      die "Node.js 18+ required (found ${NODE_VER}). Install from https://nodejs.org"
    fi
  else
    die "Node.js not found. Install from https://nodejs.org"
  fi

  # make
  check_cmd make "make" || die "'make' is required for dev mode. Install build-essential (Debian/Ubuntu) or Development Tools (RHEL/CentOS)"

fi

# ── Write .env ────────────────────────────────────────────────────────────────
section "Writing .env"

ENV_FILE="${SCRIPT_DIR}/.env"

if [[ -f "$ENV_FILE" ]]; then
  BACKUP="${ENV_FILE}.bak.$(date +%Y%m%d%H%M%S)"
  cp "$ENV_FILE" "$BACKUP"
  warn "Existing .env backed up → ${BACKUP}"
fi

DATABASE_URL="postgresql+asyncpg://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
S3_ENDPOINT="http://${S3_HOST}:${S3_PORT}"

cat > "$ENV_FILE" << EOF
# .env — generated by install.sh on $(date '+%Y-%m-%d %H:%M:%S')
# ⚠️  Never commit this file to source control

# ── Security ──────────────────────────────────────────────────────────────────
SECRET_KEY=${SECRET_KEY}

# ── Database ──────────────────────────────────────────────────────────────────
DB_PASSWORD=${DB_PASSWORD}
DATABASE_URL=${DATABASE_URL}

# ── Redis (always localhost) ──────────────────────────────────────────────────
REDIS_URL=redis://localhost:6379/0

# ── Object Storage (MinIO / S3) ───────────────────────────────────────────────
S3_ENDPOINT=${S3_ENDPOINT}
S3_ACCESS_KEY=${S3_ACCESS_KEY}
S3_SECRET_KEY=${S3_SECRET_KEY}

# ── App ───────────────────────────────────────────────────────────────────────
ENV=${MODE}
DOMAIN=${DOMAIN}

# ── Frontend ──────────────────────────────────────────────────────────────────
VITE_API_BASE_URL=${VITE_API_BASE_URL}
EOF

chmod 600 "$ENV_FILE"
ok ".env written and locked to owner-only (chmod 600)"

# ── SSL setup (prod only) ─────────────────────────────────────────────────────
if [[ "$MODE" == "prod" ]]; then
  section "SSL certificates"
  CERT_DIR="${SCRIPT_DIR}/infra/nginx/certs"
  mkdir -p "$CERT_DIR"

  if [[ "$SELF_SIGNED" == true ]]; then
    info "Generating self-signed certificate for '${DOMAIN}' (valid 10 years)..."
    openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
      -nodes \
      -keyout "${CERT_DIR}/server.key" \
      -out    "${CERT_DIR}/server.crt" \
      -subj   "/CN=${DOMAIN}/O=MemoryScope/C=US" \
      -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1" \
      2>/dev/null
    ok "Self-signed certificate generated"
    warn "Browsers will warn about this certificate."
    warn "Replace with a CA-signed cert (e.g. Let's Encrypt) for public deployments:"
    warn "  Copy your cert to:  infra/nginx/certs/server.crt"
    warn "  Copy your key to:   infra/nginx/certs/server.key"
    warn "  Then run:           docker compose restart nginx"
  else
    cp "$SSL_CERT_SRC" "${CERT_DIR}/server.crt"
    cp "$SSL_KEY_SRC"  "${CERT_DIR}/server.key"
    ok "SSL certificates copied to ${CERT_DIR}"
  fi
  chmod 600 "${CERT_DIR}/server.key"
fi

# ── Install Python / Node dependencies (dev only) ─────────────────────────────
if [[ "$MODE" == "dev" ]]; then
  section "Installing dependencies"

  info "Creating Python virtual environment..."
  if [[ ! -d "${SCRIPT_DIR}/backend/.venv" ]]; then
    "$PY_CMD" -m venv "${SCRIPT_DIR}/backend/.venv"
  fi
  info "Installing Python packages (this may take a minute)..."
  "${SCRIPT_DIR}/backend/.venv/bin/pip" install -q --upgrade pip
  "${SCRIPT_DIR}/backend/.venv/bin/pip" install -q -r "${SCRIPT_DIR}/backend/requirements.txt"
  ok "Python dependencies installed"

  info "Installing Node.js packages (this may take a minute)..."
  npm --prefix "${SCRIPT_DIR}/frontend" install --silent
  ok "Node.js dependencies installed"
fi

# ── Start infrastructure ───────────────────────────────────────────────────────
section "Starting services"

# Load .env so compose can read variables
set -a; source "${SCRIPT_DIR}/.env"; set +a

if [[ "$MODE" == "prod" ]]; then
  # Generate package-lock.json if missing — required for npm ci in the Docker build.
  # Uses node:20-alpine via Docker so no host Node.js installation is needed.
  if [[ ! -f "${SCRIPT_DIR}/frontend/package-lock.json" ]]; then
    info "Generating frontend/package-lock.json..."
    docker run --rm \
      -v "${SCRIPT_DIR}/frontend:/app" \
      -w /app \
      node:20-alpine \
      npm install --package-lock-only --silent
    ok "package-lock.json generated"
  fi

  info "Building Docker images and starting full stack (this may take several minutes)..."
  $COMPOSE up -d --build
  ok "All services started"
else
  info "Starting infrastructure (PostgreSQL, Redis, MinIO)..."
  $COMPOSE up -d postgres redis minio

  info "Waiting for PostgreSQL to be ready..."
  TIMEOUT=60; ELAPSED=0
  until $COMPOSE exec -T postgres pg_isready -U memoryscope &>/dev/null; do
    sleep 2; ELAPSED=$((ELAPSED + 2))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "Timed out waiting for PostgreSQL after ${TIMEOUT}s"
  done
  ok "PostgreSQL ready"

  info "Waiting for Redis to be ready..."
  ELAPSED=0
  until $COMPOSE exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
    sleep 2; ELAPSED=$((ELAPSED + 2))
    [[ $ELAPSED -ge $TIMEOUT ]] && die "Timed out waiting for Redis after ${TIMEOUT}s"
  done
  ok "Redis ready"

  ok "MinIO available at http://localhost:${S3_PORT}"
fi

# ── Apply database schema (dev only) ──────────────────────────────────────────
if [[ "$MODE" == "dev" ]]; then
  section "Applying database schema"
  info "Running Alembic migrations..."
  (
    cd "$SCRIPT_DIR"
    PYTHONPATH=. \
      "${SCRIPT_DIR}/backend/.venv/bin/alembic" \
      -c backend/alembic.ini \
      upgrade head
  ) && ok "Database schema applied" || warn "Migration reported an issue — schema may already be up to date"
fi

# ── Detect public IP ──────────────────────────────────────────────────────────
PUBLIC_IP=""
if command -v curl &>/dev/null; then
  PUBLIC_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null || \
              curl -s --max-time 5 https://ifconfig.me  2>/dev/null || echo "")
fi

# ── Done ──────────────────────────────────────────────────────────────────────
echo
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${GREEN}${BOLD}  ✓  Installation complete!${RESET}"
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo

if [[ "$MODE" == "prod" ]]; then
  echo -e "  ${BOLD}Open the setup wizard in your browser to create the admin account:${RESET}"
  echo
  echo -e "    ${CYAN}${BOLD}https://localhost/setup${RESET}"
  [[ -n "$PUBLIC_IP"              ]] && echo -e "    ${CYAN}${BOLD}https://${PUBLIC_IP}/setup${RESET}   ${DIM}← public IP${RESET}"
  [[ "$DOMAIN" != "localhost"     ]] && echo -e "    ${CYAN}${BOLD}https://${DOMAIN}/setup${RESET}   ${DIM}← domain${RESET}"
  echo
  if [[ "$SELF_SIGNED" == true ]]; then
    echo -e "  ${YELLOW}  Self-signed cert:${RESET} click Advanced → Proceed to continue past the browser warning."
    echo
  fi
  echo -e "  ${DIM}Useful commands:${RESET}"
  echo -e "  ${DIM}  View logs          : docker compose logs -f api worker beat${RESET}"
  echo -e "  ${DIM}  Stop all services  : docker compose down${RESET}"
  echo -e "  ${DIM}  Restart a service  : docker compose restart <service>${RESET}"
  echo -e "  ${DIM}  Replace SSL cert   : copy new files to infra/nginx/certs/ then restart nginx${RESET}"
else
  echo -e "  ${BOLD}Start the application services in separate terminals:${RESET}"
  echo
  echo -e "    ${CYAN}make backend${RESET}   ${DIM}# FastAPI on :8000${RESET}"
  echo -e "    ${CYAN}make worker${RESET}    ${DIM}# Celery analysis worker${RESET}"
  echo -e "    ${CYAN}make beat${RESET}      ${DIM}# Celery beat scheduler (watch folder, purges)${RESET}"
  echo -e "    ${CYAN}make frontend${RESET}  ${DIM}# Vite dev server on :3000${RESET}"
  echo
  echo -e "  ${BOLD}Then open the setup wizard:${RESET}"
  echo
  echo -e "    ${CYAN}${BOLD}http://localhost:3000/setup${RESET}"
  [[ -n "$PUBLIC_IP" ]] && echo -e "    ${CYAN}${BOLD}http://${PUBLIC_IP}:3000/setup${RESET}   ${DIM}← public IP${RESET}"
  echo
  echo -e "  ${DIM}Infrastructure commands:${RESET}"
  echo -e "  ${DIM}  Stop infra     : docker compose down${RESET}"
  echo -e "  ${DIM}  Restart infra  : docker compose restart postgres redis minio${RESET}"
fi

echo
echo -e "  ${DIM}Credentials are saved in ${SCRIPT_DIR}/.env — keep this file private!${RESET}"
echo
echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo
