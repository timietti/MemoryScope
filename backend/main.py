# backend/main.py
import logging
import logging.handlers
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from backend.config import settings
from backend.api.limiter import limiter
from backend.api.routers import cases, ws, auth, stats, kb, admin, oidc, setup, chat
from backend.db.session import async_session_factory
from backend.core.storage import ensure_buckets
from backend.utils.db_settings import seed_db_settings, load_db_settings


def _configure_file_logging() -> None:
    if not settings.LOG_FILE:
        return
    log_path = Path(settings.LOG_FILE)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=settings.LOG_MAX_BYTES,
        backupCount=settings.LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    logging.getLogger().addHandler(handler)
    logging.getLogger().setLevel(logging.INFO)


_configure_file_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure MinIO buckets exist
    ensure_buckets()
    # Seed runtime settings from env (first boot) then load them into memory
    async with async_session_factory() as db:
        await seed_db_settings(db)
        await load_db_settings(db)
    yield


app = FastAPI(
    title="MemoryScope API",
    version="0.1.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

# Rate limiter (H-1)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS (H-7: no wildcard fallback; explicit method list)
_origins = [str(o) for o in settings.ALLOWED_ORIGINS]
if not _origins:
    if settings.ENV == "production":
        raise RuntimeError(
            "ALLOWED_ORIGINS must not be empty in production. "
            "Set it in your .env file."
        )
    # Development convenience: allow localhost variants
    _origins = ["http://localhost:3000", "http://127.0.0.1:3000"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(cases.router,  prefix=settings.API_PREFIX)
app.include_router(chat.router,   prefix=settings.API_PREFIX)
app.include_router(stats.router,  prefix=settings.API_PREFIX)
app.include_router(kb.router,     prefix=settings.API_PREFIX)
app.include_router(admin.router,  prefix=settings.API_PREFIX)
app.include_router(setup.router,  prefix=settings.API_PREFIX)
app.include_router(ws.router)
app.include_router(auth.router,   prefix=settings.API_PREFIX)
app.include_router(oidc.router,   prefix=settings.API_PREFIX)


@app.get("/health")
async def health():
    return {"status": "ok", "version": "0.1.0"}
