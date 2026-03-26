# backend/api/routers/admin.py
import collections
import platform
from datetime import datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_admin
from backend.db.session import get_db
from backend.config import settings
from backend.db.models.models import User, UserRole, Case, Report, CaseEvent, AuditLog
from backend.utils.audit import log_audit

router = APIRouter(prefix="/admin", tags=["admin"])
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ── Pydantic schemas ──────────────────────────────────────────────────────────

class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    is_active: bool
    last_login_at: str | None
    created_at: str

    class Config:
        from_attributes = True

    @field_validator("id", "role", mode="before")
    @classmethod
    def coerce_str(cls, v):
        return v.value if hasattr(v, 'value') else str(v)

    @field_validator("last_login_at", "created_at", mode="before")
    @classmethod
    def coerce_dt(cls, v):
        return v.isoformat() if v else None


class UserCreate(BaseModel):
    email: str
    display_name: str
    password: str
    role: Literal["analyst", "admin"] = "analyst"


class UserUpdate(BaseModel):
    display_name: str | None = None
    role: Literal["analyst", "admin"] | None = None
    is_active: bool | None = None
    password: str | None = None


def _secret_val(secret) -> str:
    """Return the actual secret value, or empty string if not set."""
    if secret is None:
        return ""
    return secret.get_secret_value() if hasattr(secret, 'get_secret_value') else str(secret)


class SettingsOut(BaseModel):
    # App
    env: str
    api_prefix: str
    secret_key: str          # masked

    # Database
    database_url: str        # read-only

    # Redis
    redis_url: str           # read-only

    # Storage
    s3_endpoint: str
    s3_bucket_dumps: str
    s3_bucket_reports: str
    s3_access_key: str       # masked
    s3_secret_key: str       # masked

    # Volatility
    volatility_path: str
    symbol_cache_path: str
    dwarf2json_path: str
    worker_tmp_dir: str
    plugin_timeout_seconds: int
    max_dump_size_bytes: int

    # AI
    primary_model: str
    fast_model: str
    ai_max_context_tokens: int
    summarise_threshold_chars: int
    anthropic_api_key: str   # masked
    openai_api_key: str      # masked

    # Enrichment
    vt_rate_limit_per_min: int
    virustotal_api_key: str  # masked

    # Auth
    jwt_algorithm: str
    jwt_access_expire_minutes: int
    jwt_refresh_expire_days: int

    # Celery
    celery_concurrency: int

    # Retention
    dump_retention_days: int
    report_retention_days: int


class SettingsPatch(BaseModel):
    # Volatility — editable
    plugin_timeout_seconds: int | None = None
    max_dump_size_bytes: int | None = None

    # AI — editable
    primary_model: str | None = None
    fast_model: str | None = None
    ai_max_context_tokens: int | None = None
    summarise_threshold_chars: int | None = None

    # AI — secrets
    anthropic_api_key: str | None = None
    openai_api_key: str | None = None

    # Enrichment — editable + secret
    vt_rate_limit_per_min: int | None = None
    virustotal_api_key: str | None = None

    # Auth — editable
    jwt_access_expire_minutes: int | None = None
    jwt_refresh_expire_days: int | None = None

    # Celery — editable
    celery_concurrency: int | None = None

    # Retention — editable
    dump_retention_days: int | None = None
    report_retention_days: int | None = None

    # App — secret
    secret_key: str | None = None

    # Storage — secrets
    s3_access_key: str | None = None
    s3_secret_key: str | None = None


class SystemHealth(BaseModel):
    api: str
    database: str
    worker_count: int
    platform: str
    python_version: str
    total_cases: int
    total_reports: int


# ── Users ─────────────────────────────────────────────────────────────────────

@router.get("/users", response_model=list[UserOut])
async def list_users(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    result = await db.execute(select(User).order_by(User.created_at))
    return [UserOut.model_validate(u) for u in result.scalars()]


@router.post("/users", response_model=UserOut, status_code=201)
async def create_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    existing = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=409, detail="Email already registered")
    user = User(
        email=body.email,
        display_name=body.display_name,
        password_hash=pwd_context.hash(body.password),
        role=UserRole(body.role),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await log_audit(db, "user.created", actor_id=admin.id, target_user_id=user.id,
                    payload={"email": user.email, "role": body.role})
    return UserOut.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserOut)
async def update_user(
    user_id: UUID,
    body: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Prevent admin from disabling themselves
    if str(user.id) == str(admin.id) and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")
    changes: dict = {}
    if body.display_name is not None:
        changes["display_name"] = body.display_name
        user.display_name = body.display_name
    if body.role is not None:
        changes["role"] = body.role
        user.role = UserRole(body.role)
    if body.is_active is not None:
        changes["is_active"] = body.is_active
        user.is_active = body.is_active
    if body.password is not None:
        changes["password"] = "changed"
        user.password_hash = pwd_context.hash(body.password)
    await db.commit()
    await db.refresh(user)
    await log_audit(db, "user.updated", actor_id=admin.id, target_user_id=user.id,
                    payload={"email": user.email, "changes": changes})
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", status_code=204)
async def delete_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(get_current_admin),
):
    if str(user_id) == str(admin.id):
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    email = user.email
    await db.delete(user)
    await db.commit()
    await log_audit(db, "user.deleted", actor_id=admin.id,
                    payload={"email": email})


# ── Settings ──────────────────────────────────────────────────────────────────

@router.get("/settings", response_model=SettingsOut)
async def get_settings(_admin: User = Depends(get_current_admin)):
    return SettingsOut(
        # App
        env=settings.ENV,
        api_prefix=settings.API_PREFIX,
        secret_key=_secret_val(settings.SECRET_KEY),
        # Database
        database_url=settings.DATABASE_URL,
        # Redis
        redis_url=settings.REDIS_URL,
        # Storage
        s3_endpoint=settings.S3_ENDPOINT,
        s3_bucket_dumps=settings.S3_BUCKET_DUMPS,
        s3_bucket_reports=settings.S3_BUCKET_REPORTS,
        s3_access_key=_secret_val(settings.S3_ACCESS_KEY),
        s3_secret_key=_secret_val(settings.S3_SECRET_KEY),
        # Volatility
        volatility_path=settings.VOLATILITY_PATH,
        symbol_cache_path=settings.SYMBOL_CACHE_PATH,
        dwarf2json_path=settings.DWARF2JSON_PATH,
        worker_tmp_dir=settings.WORKER_TMP_DIR,
        plugin_timeout_seconds=settings.PLUGIN_TIMEOUT_SECONDS,
        max_dump_size_bytes=settings.MAX_DUMP_SIZE_BYTES,
        # AI
        primary_model=settings.PRIMARY_MODEL,
        fast_model=settings.FAST_MODEL,
        ai_max_context_tokens=settings.AI_MAX_CONTEXT_TOKENS,
        summarise_threshold_chars=settings.SUMMARISE_THRESHOLD_CHARS,
        anthropic_api_key=_secret_val(settings.ANTHROPIC_API_KEY),
        openai_api_key=_secret_val(settings.OPENAI_API_KEY),
        # Enrichment
        vt_rate_limit_per_min=settings.VT_RATE_LIMIT_PER_MIN,
        virustotal_api_key=_secret_val(settings.VIRUSTOTAL_API_KEY),
        # Auth
        jwt_algorithm=settings.JWT_ALGORITHM,
        jwt_access_expire_minutes=settings.JWT_ACCESS_EXPIRE_MINUTES,
        jwt_refresh_expire_days=settings.JWT_REFRESH_EXPIRE_DAYS,
        # Celery
        celery_concurrency=settings.CELERY_CONCURRENCY,
        # Retention
        dump_retention_days=settings.DUMP_RETENTION_DAYS,
        report_retention_days=settings.REPORT_RETENTION_DAYS,
    )


@router.patch("/settings", response_model=SettingsOut)
async def patch_settings(
    body: SettingsPatch,
    _admin: User = Depends(get_current_admin),
):
    """
    Applies runtime overrides to the in-memory settings object.
    Changes persist until the process restarts unless .env is also updated.
    """
    from pydantic import SecretStr

    # Map patch field names → settings attribute names
    _field_map = {
        "anthropic_api_key": "ANTHROPIC_API_KEY",
        "openai_api_key":    "OPENAI_API_KEY",
        "virustotal_api_key":"VIRUSTOTAL_API_KEY",
        "secret_key":        "SECRET_KEY",
        "s3_access_key":     "S3_ACCESS_KEY",
        "s3_secret_key":     "S3_SECRET_KEY",
    }
    _secret_fields = set(_field_map.keys())

    updates = body.model_dump(exclude_none=True)
    for key, value in updates.items():
        # Skip blank secret strings (means "leave unchanged")
        if key in _secret_fields and not value:
            continue
        attr = _field_map.get(key, key.upper())
        if not hasattr(settings, attr):
            continue
        # Wrap secret fields back into SecretStr
        if key in _secret_fields:
            value = SecretStr(value)
        object.__setattr__(settings, attr, value)
    return await get_settings(_admin)


# ── System ────────────────────────────────────────────────────────────────────

@router.get("/system/health", response_model=SystemHealth)
async def system_health(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    # DB check
    try:
        total_cases = (await db.execute(select(func.count()).select_from(Case))).scalar() or 0
        total_reports = (await db.execute(select(func.count()).select_from(Report))).scalar() or 0
        db_status = "ok"
    except Exception:
        db_status = "error"
        total_cases = 0
        total_reports = 0

    # Worker count via ping — only workers that reply within timeout are counted
    worker_count = 0
    try:
        from backend.workers.celery_app import celery_app
        pong = celery_app.control.inspect(timeout=3).ping()
        worker_count = len(pong) if pong else 0
    except Exception:
        pass

    import sys
    return SystemHealth(
        api="ok",
        database=db_status,
        worker_count=worker_count,
        platform=platform.platform(),
        python_version=sys.version.split()[0],
        total_cases=total_cases,
        total_reports=total_reports,
    )


@router.post("/system/worker/restart", status_code=202)
async def restart_workers(_admin: User = Depends(get_current_admin)):
    """Send a graceful pool restart signal to all Celery workers."""
    try:
        from backend.workers.celery_app import celery_app
        celery_app.control.pool_restart(reload=True)
        return {"detail": "Restart signal sent"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send restart signal: {e}")


# ── Logs ──────────────────────────────────────────────────────────────────────

class AuditEntry(BaseModel):
    id: str                   # "case-<id>" or "user-<id>" to avoid collisions
    source: str               # "case" | "user"
    event_type: str
    payload: dict
    actor_name: str | None
    target_name: str | None   # case short_id or target user display_name
    created_at: str


class AppLogLine(BaseModel):
    raw: str
    level: str
    timestamp: str
    logger: str
    message: str


def _parse_log_line(line: str) -> AppLogLine:
    """Parse a log line formatted as: YYYY-MM-DD HH:MM:SS LEVEL    [logger] message"""
    parts = line.split(" ", 3)
    try:
        timestamp = f"{parts[0]} {parts[1]}"
        level = parts[2].strip()
        rest = parts[3] if len(parts) > 3 else ""
        if rest.startswith("["):
            bracket_end = rest.index("]")
            logger_name = rest[1:bracket_end]
            message = rest[bracket_end + 2:] if len(rest) > bracket_end + 2 else ""
        else:
            logger_name = ""
            message = rest
    except (IndexError, ValueError):
        timestamp = ""
        level = "INFO"
        logger_name = ""
        message = line
    return AppLogLine(raw=line.rstrip(), level=level, timestamp=timestamp,
                      logger=logger_name, message=message.rstrip())


@router.get("/logs/audit")
async def audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    event_type: str | None = Query(None),
    source: str | None = Query(None),   # "case" | "user" | None = both
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    # ── Fetch case events ──────────────────────────────────────────────────────
    case_rows: list = []
    user_rows: list = []

    if source in (None, "case"):
        q_case = select(CaseEvent)
        if event_type:
            q_case = q_case.where(CaseEvent.event_type == event_type)
        case_rows = list((await db.execute(q_case)).scalars())

    if source in (None, "user"):
        q_user = select(AuditLog)
        if event_type:
            q_user = q_user.where(AuditLog.event_type == event_type)
        user_rows = list((await db.execute(q_user)).scalars())

    # ── Resolve names in bulk ──────────────────────────────────────────────────
    case_ids  = {r.case_id for r in case_rows}
    actor_ids = ({r.actor_id for r in case_rows if r.actor_id} |
                 {r.actor_id for r in user_rows if r.actor_id})
    target_ids = {r.target_user_id for r in user_rows if r.target_user_id}
    all_user_ids = actor_ids | target_ids

    cases_map: dict = {}
    if case_ids:
        for c in (await db.execute(select(Case).where(Case.id.in_(case_ids)))).scalars():
            cases_map[str(c.id)] = c.short_id

    users_map: dict = {}
    if all_user_ids:
        for u in (await db.execute(select(User).where(User.id.in_(all_user_ids)))).scalars():
            users_map[str(u.id)] = u.display_name

    # ── Build unified entries ──────────────────────────────────────────────────
    entries: list[AuditEntry] = []

    for r in case_rows:
        entries.append(AuditEntry(
            id=f"case-{r.id}",
            source="case",
            event_type=r.event_type,
            payload=r.payload or {},
            actor_name=users_map.get(str(r.actor_id)) if r.actor_id else None,
            target_name=cases_map.get(str(r.case_id)),
            created_at=r.created_at.isoformat(),
        ))

    for r in user_rows:
        entries.append(AuditEntry(
            id=f"user-{r.id}",
            source="user",
            event_type=r.event_type,
            payload=r.payload or {},
            actor_name=users_map.get(str(r.actor_id)) if r.actor_id else None,
            target_name=users_map.get(str(r.target_user_id)) if r.target_user_id else None,
            created_at=r.created_at.isoformat(),
        ))

    # ── Sort merged list newest-first, paginate ────────────────────────────────
    entries.sort(key=lambda e: e.created_at, reverse=True)
    total = len(entries)
    page_entries = entries[(page - 1) * page_size : page * page_size]

    return {"items": page_entries, "total": total, "page": page, "page_size": page_size}


@router.get("/logs/audit/event-types")
async def audit_event_types(
    source: str | None = Query(None, pattern="^(user|case)$"),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    types: set[str] = set()
    if source != "user":
        case_types = (await db.execute(
            select(CaseEvent.event_type).distinct()
        )).scalars().all()
        types.update(case_types)
    if source != "case":
        user_types = (await db.execute(
            select(AuditLog.event_type).distinct()
        )).scalars().all()
        types.update(user_types)
    return sorted(types)


@router.get("/logs/app")
async def app_logs(
    lines: int = Query(200, ge=10, le=2000),
    level: Literal["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "ALL",
    _admin: User = Depends(get_current_admin),
):
    log_path = Path(settings.LOG_FILE) if settings.LOG_FILE else None
    if not log_path or not log_path.exists():
        return {"lines": [], "log_file": str(log_path) if log_path else "(not configured)"}

    # Read last N matching lines across current + rotated files
    log_files = sorted(
        [log_path] + list(log_path.parent.glob(f"{log_path.name}.*")),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )

    _LEVELS = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40, "CRITICAL": 50}
    min_level = _LEVELS.get(level, 0)

    buf: collections.deque[AppLogLine] = collections.deque(maxlen=lines)
    for f in log_files:
        try:
            with f.open(encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    parsed = _parse_log_line(raw)
                    if min_level == 0 or _LEVELS.get(parsed.level, 0) >= min_level:
                        buf.append(parsed)
        except OSError:
            continue
        if len(buf) >= lines:
            break

    # Return in chronological order (oldest first) capped at requested count
    result = list(buf)[-lines:]
    return {"lines": result, "log_file": str(log_path)}
