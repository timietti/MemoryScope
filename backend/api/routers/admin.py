# backend/api/routers/admin.py
import platform
from datetime import datetime
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_admin
from backend.db.session import get_db
from backend.config import settings
from backend.db.models.models import User, UserRole, Case, Report

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


class SettingsOut(BaseModel):
    primary_model: str
    fast_model: str
    ai_max_context_tokens: int
    summarise_threshold_chars: int
    plugin_timeout_seconds: int
    worker_tmp_dir: str
    max_dump_size_bytes: int
    symbol_server_url: str
    symbol_cache_path: str
    vt_rate_limit_per_min: int
    celery_concurrency: int
    dump_retention_days: int
    report_retention_days: int
    allowed_origins: list[str]
    env: str


class SettingsPatch(BaseModel):
    primary_model: str | None = None
    fast_model: str | None = None
    ai_max_context_tokens: int | None = None
    summarise_threshold_chars: int | None = None
    plugin_timeout_seconds: int | None = None
    celery_concurrency: int | None = None
    dump_retention_days: int | None = None
    report_retention_days: int | None = None
    vt_rate_limit_per_min: int | None = None


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
    if body.display_name is not None:
        user.display_name = body.display_name
    if body.role is not None:
        user.role = UserRole(body.role)
    if body.is_active is not None:
        user.is_active = body.is_active
    if body.password is not None:
        user.password_hash = pwd_context.hash(body.password)
    await db.commit()
    await db.refresh(user)
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
    await db.delete(user)
    await db.commit()


# ── Settings ──────────────────────────────────────────────────────────────────

@router.get("/settings", response_model=SettingsOut)
async def get_settings(_admin: User = Depends(get_current_admin)):
    return SettingsOut(
        primary_model=settings.PRIMARY_MODEL,
        fast_model=settings.FAST_MODEL,
        ai_max_context_tokens=settings.AI_MAX_CONTEXT_TOKENS,
        summarise_threshold_chars=settings.SUMMARISE_THRESHOLD_CHARS,
        plugin_timeout_seconds=settings.PLUGIN_TIMEOUT_SECONDS,
        worker_tmp_dir=settings.WORKER_TMP_DIR,
        max_dump_size_bytes=settings.MAX_DUMP_SIZE_BYTES,
        symbol_server_url=settings.SYMBOL_SERVER_URL,
        symbol_cache_path=settings.SYMBOL_CACHE_PATH,
        vt_rate_limit_per_min=settings.VT_RATE_LIMIT_PER_MIN,
        celery_concurrency=settings.CELERY_CONCURRENCY,
        dump_retention_days=settings.DUMP_RETENTION_DAYS,
        report_retention_days=settings.REPORT_RETENTION_DAYS,
        allowed_origins=[str(o) for o in settings.ALLOWED_ORIGINS],
        env=settings.ENV,
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
    updates = body.model_dump(exclude_none=True)
    for key, value in updates.items():
        attr = key.upper()
        if hasattr(settings, attr):
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

    # Worker count via celery inspect
    worker_count = 0
    try:
        from backend.workers.celery_app import celery_app
        inspect = celery_app.control.inspect(timeout=2)
        active = inspect.active()
        worker_count = len(active) if active else 0
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
