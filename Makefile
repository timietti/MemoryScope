# Makefile — MemoryScope development shortcuts
# Usage: make <target>

.PHONY: help infra infra-down backend worker frontend seed lint test clean migrate db-stamp

help:
	@echo "MemoryScope dev commands:"
	@echo "  make infra       Start Postgres, Redis, MinIO in Docker"
	@echo "  make infra-down  Stop infrastructure containers"
	@echo "  make backend     Run FastAPI dev server"
	@echo "  make worker      Run Celery worker"
	@echo "  make frontend    Run Vite dev server"
	@echo "  make seed        Seed database with admin user"
	@echo "  make init        Create Python __init__.py files"
	@echo "  make schema      Apply SQL schema to local Postgres (legacy — use migrate)"
	@echo "  make migrate     Run Alembic migrations (new installations)"
	@echo "  make db-stamp    Mark existing DB as current without running migrations"
	@echo "  make lint        Run ruff + mypy"
	@echo "  make test        Run pytest"
	@echo "  make docker-up   Start full stack with Docker Compose"
	@echo "  make clean       Remove __pycache__ and .pyc files"

# ── Infrastructure ────────────────────────────────────────────────────────────

infra:
	docker compose up postgres redis minio -d
	@echo "Waiting for services..."
	@sleep 5
	@docker compose ps

infra-down:
	docker compose stop postgres redis minio

# ── Backend ───────────────────────────────────────────────────────────────────

backend:
	PYTHONPATH=. backend/.venv/bin/uvicorn backend.main:app --reload --host 0.0.0.0 --port 8000

worker:
	PYTHONPATH=. backend/.venv/bin/celery -A backend.workers.celery_app worker \
	    --loglevel=info --concurrency=2 \
	    --queues=analysis,plugins,default

# ── Frontend ──────────────────────────────────────────────────────────────────

frontend:
	cd frontend && npm run dev -- --host 0.0.0.0

# ── Setup ─────────────────────────────────────────────────────────────────────

install-backend:
	cd backend && python -m venv .venv && \
	  .venv/bin/pip install --upgrade pip && \
	  .venv/bin/pip install -r requirements.txt

install-frontend:
	cd frontend && npm install

install: install-backend install-frontend

init:
	python scripts/create_inits.py

schema:
	psql $${DATABASE_URL:-postgresql://memoryscope:localdev@localhost:5432/memoryscope} \
	  < docs/schema.sql

seed:
	cd backend && .venv/bin/python ../scripts/seed_db.py

migrate:
	cd backend && PYTHONPATH=.. .venv/bin/alembic upgrade head

db-stamp:
	cd backend && PYTHONPATH=.. .venv/bin/alembic stamp head

# ── Quality ───────────────────────────────────────────────────────────────────

lint:
	PYTHONPATH=. backend/.venv/bin/ruff check backend/ && backend/.venv/bin/mypy backend/

test:
	PYTHONPATH=. backend/.venv/bin/pytest backend/tests/ -v

# ── Docker ────────────────────────────────────────────────────────────────────

docker-up:
	docker compose up --build

docker-down:
	docker compose down

docker-logs:
	docker compose logs -f api worker

# ── Misc ──────────────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete 2>/dev/null; true
	@echo "Cleaned."
