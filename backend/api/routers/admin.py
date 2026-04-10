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
    username: str | None = None
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
    username: str
    display_name: str
    password: str
    role: Literal["analyst", "admin", "viewer"] = "analyst"


class UserUpdate(BaseModel):
    email: str | None = None
    display_name: str | None = None
    username: str | None = None
    role: Literal["analyst", "admin", "viewer"] | None = None
    is_active: bool | None = None
    password: str | None = None


def _secret_val(secret) -> str:
    """Return the actual secret value, or empty string if not set."""
    if secret is None:
        return ""
    return secret.get_secret_value() if hasattr(secret, 'get_secret_value') else str(secret)


class SettingsOut(BaseModel):
    # Bootstrap (read-only — change via .env)
    env: str
    api_prefix: str
    secret_key: str
    database_url: str
    redis_url: str
    s3_endpoint: str
    s3_bucket_dumps: str
    s3_bucket_reports: str
    s3_access_key: str
    s3_secret_key: str

    # Volatility
    volatility_path: str
    symbol_cache_path: str
    dwarf2json_path: str
    worker_tmp_dir: str
    plugin_timeout_seconds: int
    max_dump_size_bytes: int
    max_cases_per_hour_per_user: int

    # AI
    primary_model: str
    fast_model: str
    ai_max_context_tokens: int
    summarise_threshold_chars: int
    anthropic_api_key: str
    fallback_api_url: str
    fallback_api_key: str
    fallback_model: str

    # Enrichment
    vt_rate_limit_per_min: int
    vt_max_iocs: int
    virustotal_api_key: str

    # Auth
    jwt_algorithm: str
    jwt_access_expire_minutes: int
    jwt_refresh_expire_days: int

    # Celery
    celery_concurrency: int
    strings_max_workers: int

    # Retention
    dump_retention_days: int
    report_retention_days: int

    # MCP Server
    mcp_enabled: bool

    # Watch Folder
    watch_dir_enabled: bool
    watch_dir: str
    watch_dir_poll_interval: int
    watch_dir_stable_age: int

    # OIDC / SSO
    oidc_enabled: bool
    oidc_client_id: str
    oidc_client_secret: str
    oidc_discovery_url: str
    oidc_redirect_uri: str
    oidc_frontend_callback_url: str
    oidc_provider_name: str
    oidc_role_claim: str
    oidc_admin_group: str
    oidc_jit_provisioning: bool
    oidc_verify_ssl: bool

    # LDAP / LDAPS
    ldap_enabled: bool
    ldap_url: str
    ldap_use_starttls: bool
    ldap_tls_verify: bool
    ldap_bind_dn: str
    ldap_bind_password: str
    ldap_base_dn: str
    ldap_user_filter: str
    ldap_attr_email: str
    ldap_attr_display_name: str
    ldap_group_base_dn: str
    ldap_admin_group: str
    ldap_analyst_group: str
    ldap_viewer_group: str
    ldap_jit_provisioning: bool


class SettingsPatch(BaseModel):
    # Volatility
    volatility_path: str | None = None
    symbol_cache_path: str | None = None
    dwarf2json_path: str | None = None
    worker_tmp_dir: str | None = None
    plugin_timeout_seconds: int | None = None
    max_dump_size_bytes: int | None = None
    max_cases_per_hour_per_user: int | None = None

    # AI
    primary_model: str | None = None
    fast_model: str | None = None
    ai_max_context_tokens: int | None = None
    summarise_threshold_chars: int | None = None
    anthropic_api_key: str | None = None
    fallback_api_url: str | None = None
    fallback_api_key: str | None = None
    fallback_model: str | None = None

    # Enrichment
    vt_rate_limit_per_min: int | None = None
    vt_max_iocs: int | None = None
    virustotal_api_key: str | None = None

    # Auth
    jwt_algorithm: str | None = None
    jwt_access_expire_minutes: int | None = None
    jwt_refresh_expire_days: int | None = None

    # Celery
    celery_concurrency: int | None = None
    strings_max_workers: int | None = None

    # Retention
    dump_retention_days: int | None = None
    report_retention_days: int | None = None

    # MCP Server
    mcp_enabled: bool | None = None

    # Watch Folder
    watch_dir_enabled: bool | None = None
    watch_dir: str | None = None
    watch_dir_poll_interval: int | None = None
    watch_dir_stable_age: int | None = None

    # OIDC / SSO
    oidc_enabled: bool | None = None
    oidc_client_id: str | None = None
    oidc_client_secret: str | None = None
    oidc_discovery_url: str | None = None
    oidc_redirect_uri: str | None = None
    oidc_frontend_callback_url: str | None = None
    oidc_provider_name: str | None = None
    oidc_role_claim: str | None = None
    oidc_admin_group: str | None = None
    oidc_jit_provisioning: bool | None = None
    oidc_verify_ssl: bool | None = None

    # LDAP / LDAPS
    ldap_enabled: bool | None = None
    ldap_url: str | None = None
    ldap_use_starttls: bool | None = None
    ldap_tls_verify: bool | None = None
    ldap_bind_dn: str | None = None
    ldap_bind_password: str | None = None
    ldap_base_dn: str | None = None
    ldap_user_filter: str | None = None
    ldap_attr_email: str | None = None
    ldap_attr_display_name: str | None = None
    ldap_group_base_dn: str | None = None
    ldap_admin_group: str | None = None
    ldap_analyst_group: str | None = None
    ldap_viewer_group: str | None = None
    ldap_jit_provisioning: bool | None = None


class SystemHealth(BaseModel):
    api: str
    database: str
    worker_count: int
    platform: str
    python_version: str
    total_cases: int
    total_reports: int
    # Partition stats (from the API container's view — same host partition as MinIO volume)
    disk_total_bytes: int
    disk_used_bytes: int
    disk_free_bytes: int
    disk_device: str        # e.g. /dev/mapper/ubuntu--vg-ubuntu--lv
    disk_type: str          # 'lvm' | 'zfs' | 'btrfs' | 'mdraid' | 'raw' | 'unknown'


class StorageInfo(BaseModel):
    dumps_bytes: int        # total bytes stored in the dumps bucket
    dumps_objects: int
    reports_bytes: int      # total bytes stored in the reports bucket
    reports_objects: int


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
    admin: User = Depends(get_current_admin),
):
    existing_email = (await db.execute(select(User).where(User.email == body.email))).scalar_one_or_none()
    if existing_email:
        raise HTTPException(status_code=409, detail="Email already registered")
    username_lc = body.username.strip().lower()
    existing_username = (await db.execute(select(User).where(User.username == username_lc))).scalar_one_or_none()
    if existing_username:
        raise HTTPException(status_code=409, detail="Username already taken")
    user = User(
        email=body.email,
        username=username_lc,
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
    if body.email is not None:
        new_email = body.email.strip().lower()
        if not new_email:
            raise HTTPException(status_code=422, detail="Email cannot be empty")
        if new_email != user.email:
            existing = (await db.execute(select(User).where(User.email == new_email))).scalar_one_or_none()
            if existing:
                raise HTTPException(status_code=409, detail="Email already registered")
            changes["email"] = new_email
            user.email = new_email
    if body.display_name is not None:
        changes["display_name"] = body.display_name
        user.display_name = body.display_name
    if body.username is not None:
        new_username = body.username.strip().lower()
        if new_username != user.username:
            existing = (await db.execute(select(User).where(User.username == new_username))).scalar_one_or_none()
            if existing:
                raise HTTPException(status_code=409, detail="Username already taken")
            changes["username"] = new_username
            user.username = new_username
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
        # Bootstrap
        env=settings.ENV,
        api_prefix=settings.API_PREFIX,
        secret_key=_secret_val(settings.SECRET_KEY),
        database_url=settings.DATABASE_URL,
        redis_url=settings.REDIS_URL,
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
        max_cases_per_hour_per_user=settings.MAX_CASES_PER_HOUR_PER_USER,
        # AI
        primary_model=settings.PRIMARY_MODEL,
        fast_model=settings.FAST_MODEL,
        ai_max_context_tokens=settings.AI_MAX_CONTEXT_TOKENS,
        summarise_threshold_chars=settings.SUMMARISE_THRESHOLD_CHARS,
        anthropic_api_key=_secret_val(settings.ANTHROPIC_API_KEY),
        fallback_api_url=settings.FALLBACK_API_URL,
        fallback_api_key=_secret_val(settings.FALLBACK_API_KEY),
        fallback_model=settings.FALLBACK_MODEL,
        # Enrichment
        vt_rate_limit_per_min=settings.VT_RATE_LIMIT_PER_MIN,
        vt_max_iocs=settings.VT_MAX_IOCS,
        virustotal_api_key=_secret_val(settings.VIRUSTOTAL_API_KEY),
        # Auth
        jwt_algorithm=settings.JWT_ALGORITHM,
        jwt_access_expire_minutes=settings.JWT_ACCESS_EXPIRE_MINUTES,
        jwt_refresh_expire_days=settings.JWT_REFRESH_EXPIRE_DAYS,
        # Celery
        celery_concurrency=settings.CELERY_CONCURRENCY,
        strings_max_workers=settings.STRINGS_MAX_WORKERS,
        # Retention
        dump_retention_days=settings.DUMP_RETENTION_DAYS,
        report_retention_days=settings.REPORT_RETENTION_DAYS,
        # MCP Server
        mcp_enabled=settings.MCP_ENABLED,
        # Watch Folder
        watch_dir_enabled=settings.WATCH_DIR_ENABLED,
        watch_dir=settings.WATCH_DIR,
        watch_dir_poll_interval=settings.WATCH_DIR_POLL_INTERVAL,
        watch_dir_stable_age=settings.WATCH_DIR_STABLE_AGE,
        # OIDC
        oidc_enabled=settings.OIDC_ENABLED,
        oidc_client_id=settings.OIDC_CLIENT_ID,
        oidc_client_secret=_secret_val(settings.OIDC_CLIENT_SECRET),
        oidc_discovery_url=settings.OIDC_DISCOVERY_URL,
        oidc_redirect_uri=settings.OIDC_REDIRECT_URI,
        oidc_frontend_callback_url=settings.OIDC_FRONTEND_CALLBACK_URL,
        oidc_provider_name=settings.OIDC_PROVIDER_NAME,
        oidc_role_claim=settings.OIDC_ROLE_CLAIM,
        oidc_admin_group=settings.OIDC_ADMIN_GROUP,
        oidc_jit_provisioning=settings.OIDC_JIT_PROVISIONING,
        oidc_verify_ssl=settings.OIDC_VERIFY_SSL,
        # LDAP
        ldap_enabled=settings.LDAP_ENABLED,
        ldap_url=settings.LDAP_URL,
        ldap_use_starttls=settings.LDAP_USE_STARTTLS,
        ldap_tls_verify=settings.LDAP_TLS_VERIFY,
        ldap_bind_dn=settings.LDAP_BIND_DN,
        ldap_bind_password=_secret_val(settings.LDAP_BIND_PASSWORD),
        ldap_base_dn=settings.LDAP_BASE_DN,
        ldap_user_filter=settings.LDAP_USER_FILTER,
        ldap_attr_email=settings.LDAP_ATTR_EMAIL,
        ldap_attr_display_name=settings.LDAP_ATTR_DISPLAY_NAME,
        ldap_group_base_dn=settings.LDAP_GROUP_BASE_DN,
        ldap_admin_group=settings.LDAP_ADMIN_GROUP,
        ldap_analyst_group=settings.LDAP_ANALYST_GROUP,
        ldap_viewer_group=settings.LDAP_VIEWER_GROUP,
        ldap_jit_provisioning=settings.LDAP_JIT_PROVISIONING,
    )


@router.patch("/settings", response_model=SettingsOut)
async def patch_settings(
    body: SettingsPatch,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """
    Persists runtime setting changes to the system_settings table and applies
    them immediately to the in-memory settings object.
    """
    from backend.utils.db_settings import save_setting, SETTING_DEFS

    updates = body.model_dump(exclude_none=True)
    for key, value in updates.items():
        # Skip blank secret strings — treat as "leave unchanged"
        if SETTING_DEFS.get(key, None) and SETTING_DEFS[key].secret and not value:
            continue
        if key not in SETTING_DEFS:
            continue
        raw = "true" if value is True else "false" if value is False else str(value)
        await save_setting(db, key, raw)

    return await get_settings(_admin)


def _detect_host_disk_type() -> tuple[str, str]:
    """
    Detect the storage type of the host partition backing Docker volumes.

    Docker containers always show 'overlay' from df, so we probe:
      1. /proc/mounts — to catch ZFS and Btrfs (they appear in the mount table)
      2. /sys/block   — host block devices are visible inside the container;
                        dm-* with LVM UUIDs → LVM, md* → mdraid, else raw.

    Returns (device_path, disk_type) where disk_type is one of:
        'lvm' | 'zfs' | 'btrfs' | 'mdraid' | 'raw' | 'unknown'
    """
    import os as _os

    # Step 1: scan /proc/mounts for explicit filesystem types
    try:
        with open('/proc/mounts') as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                dev, _mp, fstype = parts[0], parts[1], parts[2]
                if fstype == 'zfs':
                    return dev, 'zfs'
                if fstype == 'btrfs' and _mp == '/':
                    return dev, 'btrfs'
    except Exception:
        pass

    # Step 2: inspect /sys/block — present for host devices inside Docker
    try:
        block_devs = _os.listdir('/sys/block')
    except Exception:
        return 'unknown', 'unknown'

    # LVM: device-mapper devices whose UUID starts with "LVM-"
    for dm in sorted(d for d in block_devs if d.startswith('dm-')):
        try:
            uuid = open(f'/sys/block/{dm}/dm/uuid').read().strip()
            if uuid.startswith('LVM-'):
                name = open(f'/sys/block/{dm}/dm/name').read().strip()
                return f'/dev/mapper/{name}', 'lvm'
        except Exception:
            continue

    # MD RAID
    md_devs = sorted(d for d in block_devs if d.startswith('md') and not d.startswith('md_'))
    if md_devs:
        return f'/dev/{md_devs[0]}', 'mdraid'

    # Plain block device (raw partition / cloud disk)
    skip_prefixes = ('loop', 'ram', 'sr', 'fd', 'zram', 'nbd')
    raw_devs = sorted(
        d for d in block_devs
        if not any(d.startswith(p) for p in skip_prefixes)
    )
    if raw_devs:
        return f'/dev/{raw_devs[0]}', 'raw'

    return 'unknown', 'unknown'


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
    import shutil
    disk = shutil.disk_usage('/')

    # Detect host storage type.
    # df inside a Docker container always reports "overlay" — useless.
    # Instead we probe /proc/mounts (shared with host) and /sys/block
    # (host block devices are visible inside the container).
    disk_device, disk_type = _detect_host_disk_type()

    return SystemHealth(
        api="ok",
        database=db_status,
        worker_count=worker_count,
        platform=platform.platform(),
        python_version=sys.version.split()[0],
        total_cases=total_cases,
        total_reports=total_reports,
        disk_total_bytes=disk.total,
        disk_used_bytes=disk.used,
        disk_free_bytes=disk.free,
        disk_device=disk_device,
        disk_type=disk_type,
    )


@router.get("/settings/oidc/test")
async def test_oidc_connection(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(get_current_admin),
):
    """
    Fetches the OIDC discovery document to verify the provider is reachable
    and the configured Discovery URL is correct.
    Reads the discovery URL live from the DB so all workers see the same value.
    """
    from backend.api.routers.oidc import get_oidc_cfg
    cfg = await get_oidc_cfg(db)
    if not cfg.discovery_url:
        raise HTTPException(status_code=400, detail="OIDC_DISCOVERY_URL is not configured")
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10, verify=cfg.verify_ssl) as client:
            resp = await client.get(cfg.discovery_url)
            resp.raise_for_status()
            doc = resp.json()
        return {
            "ok": True,
            "issuer": doc.get("issuer"),
            "authorization_endpoint": doc.get("authorization_endpoint"),
            "token_endpoint": doc.get("token_endpoint"),
            "userinfo_endpoint": doc.get("userinfo_endpoint"),
            "jwks_uri": doc.get("jwks_uri"),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.get("/settings/ldap/test")
async def test_ldap_connection(
    _admin: User = Depends(get_current_admin),
):
    """
    Test LDAP connectivity and service-account bind using current DB settings.
    Returns {ok, message} on success or {ok, error} on failure.
    """
    import asyncio
    from backend.core.ldap_auth import test_ldap_connection
    result = await asyncio.to_thread(test_ldap_connection)
    return result


@router.post("/system/worker/restart", status_code=202)
async def restart_workers(_admin: User = Depends(get_current_admin)):
    """Send a pool restart signal to all Celery workers and wait for acknowledgement."""
    try:
        from backend.workers.celery_app import celery_app
        # broadcast with reply=True waits up to 5 s and returns per-worker acks
        replies = celery_app.control.broadcast(
            "pool_restart", arguments={"reload": False}, reply=True, timeout=5
        )
        if not replies:
            raise HTTPException(status_code=503, detail="No workers responded within 5 s")
        return {"detail": "Restart signal acknowledged", "workers": len(replies)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to send restart signal: {e}")


@router.get("/system/storage", response_model=StorageInfo)
async def system_storage(_admin: User = Depends(get_current_admin)):
    """
    Sum all object sizes in the dumps and reports buckets.
    Runs in an executor because boto3 pagination is synchronous.
    May take a few seconds on large buckets.
    """
    import asyncio
    from functools import partial
    from backend.core.storage import get_storage_client
    from backend.config import settings as _s

    def _sum_bucket(bucket: str) -> tuple[int, int]:
        client = get_storage_client()
        total_bytes = 0
        total_objects = 0
        paginator = client.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get('Contents', []):
                total_bytes += obj['Size']
                total_objects += 1
        return total_bytes, total_objects

    loop = asyncio.get_event_loop()
    dumps_bytes, dumps_objects = await loop.run_in_executor(
        None, partial(_sum_bucket, _s.S3_BUCKET_DUMPS)
    )
    reports_bytes, reports_objects = await loop.run_in_executor(
        None, partial(_sum_bucket, _s.S3_BUCKET_REPORTS)
    )
    return StorageInfo(
        dumps_bytes=dumps_bytes,
        dumps_objects=dumps_objects,
        reports_bytes=reports_bytes,
        reports_objects=reports_objects,
    )


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


_LOG_SOURCES: dict[str, str] = {
    "api":          "api.log",
    "worker":       "worker.log",
    "beat":         "beat.log",
    "nginx-access": "nginx-access.log",
    "nginx-error":  "nginx-error.log",
}


def _log_dir() -> Path | None:
    """Return the log directory derived from settings.LOG_FILE, or None if not configured."""
    if not settings.LOG_FILE:
        return None
    return Path(settings.LOG_FILE).parent


@router.get("/logs/app")
async def app_logs(
    lines: int = Query(200, ge=10, le=2000),
    level: Literal["ALL", "DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "ALL",
    source: Literal["api", "worker", "beat", "nginx-access", "nginx-error"] = "api",
    _admin: User = Depends(get_current_admin),
):
    log_dir = _log_dir()
    log_path = (log_dir / _LOG_SOURCES[source]) if log_dir else None
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
