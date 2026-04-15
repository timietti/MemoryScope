# backend/utils/db_settings.py
"""
DB-backed runtime settings overlay.

Bootstrap settings (DATABASE_URL, SECRET_KEY, REDIS_URL, S3_*) always come
from the .env file.  Everything else is seeded from .env on first start and
then managed from the Admin UI (persisted in the system_settings table).

Usage (async — API):
    from backend.utils.db_settings import seed_db_settings, load_db_settings
    await seed_db_settings(db)   # once at startup
    await load_db_settings(db)   # once at startup, after seed

Usage (sync — Celery workers):
    from backend.utils.db_settings import load_db_settings_sync
    load_db_settings_sync()      # call at the top of a task to pick up latest values
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from pydantic import SecretStr
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings

logger = logging.getLogger(__name__)


# ── Setting registry ──────────────────────────────────────────────────────────

@dataclass
class SettingDef:
    attr: str        # attribute name on the Settings object
    secret: bool
    category: str
    vtype: str       # "str" | "int" | "bool" | "json"
    default: Any


#: All settings that live in the DB (not bootstrap .env values).
SETTING_DEFS: dict[str, SettingDef] = {
    # ── AI ────────────────────────────────────────────────────────────────────
    "anthropic_api_key":        SettingDef("ANTHROPIC_API_KEY",        True,  "ai",          "str",  ""),
    "fallback_api_url":         SettingDef("FALLBACK_API_URL",         False, "ai",          "str",  ""),
    "fallback_api_key":         SettingDef("FALLBACK_API_KEY",         True,  "ai",          "str",  ""),
    "fallback_model":           SettingDef("FALLBACK_MODEL",           False, "ai",          "str",  ""),
    "primary_model":            SettingDef("PRIMARY_MODEL",            False, "ai",          "str",  "claude-opus-4-5"),
    "fast_model":               SettingDef("FAST_MODEL",               False, "ai",          "str",  "claude-sonnet-4-5"),
    "ai_max_context_tokens":    SettingDef("AI_MAX_CONTEXT_TOKENS",    False, "ai",          "int",  180_000),
    "summarise_threshold_chars":SettingDef("SUMMARISE_THRESHOLD_CHARS",False, "ai",          "int",  80_000),

    # ── Enrichment ────────────────────────────────────────────────────────────
    "virustotal_api_key":       SettingDef("VIRUSTOTAL_API_KEY",       True,  "enrichment",  "str",  ""),
    "vt_rate_limit_per_min":    SettingDef("VT_RATE_LIMIT_PER_MIN",    False, "enrichment",  "int",  500),
    "vt_max_iocs":              SettingDef("VT_MAX_IOCS",              False, "enrichment",  "int",  40),

    # ── Auth ──────────────────────────────────────────────────────────────────
    "jwt_algorithm":            SettingDef("JWT_ALGORITHM",            False, "auth",        "str",  "HS256"),
    "jwt_access_expire_minutes":SettingDef("JWT_ACCESS_EXPIRE_MINUTES",False, "auth",        "int",  60),
    "jwt_refresh_expire_days":  SettingDef("JWT_REFRESH_EXPIRE_DAYS",  False, "auth",        "int",  30),

    # ── Celery ────────────────────────────────────────────────────────────────
    "celery_concurrency":       SettingDef("CELERY_CONCURRENCY",       False, "celery",      "int",  4),
    "strings_max_workers":      SettingDef("STRINGS_MAX_WORKERS",      False, "celery",      "int",  4),
    "max_parallel_plugins":     SettingDef("MAX_PARALLEL_PLUGINS",     False, "celery",      "int",  4),

    # ── Retention ─────────────────────────────────────────────────────────────
    "dump_retention_days":      SettingDef("DUMP_RETENTION_DAYS",      False, "retention",   "int",  30),
    "report_retention_days":    SettingDef("REPORT_RETENTION_DAYS",    False, "retention",   "int",  365),

    # ── Volatility ────────────────────────────────────────────────────────────
    "volatility_path":          SettingDef("VOLATILITY_PATH",          False, "volatility",  "str",  "/opt/volatility3/vol.py"),
    "symbol_cache_path":        SettingDef("SYMBOL_CACHE_PATH",        False, "volatility",  "str",  "/opt/volatility3/volatility3/symbols"),
    "dwarf2json_path":          SettingDef("DWARF2JSON_PATH",          False, "volatility",  "str",  "dwarf2json"),
    "worker_tmp_dir":           SettingDef("WORKER_TMP_DIR",           False, "volatility",  "str",  "/tmp/memoryscope"),
    "plugin_timeout_seconds":   SettingDef("PLUGIN_TIMEOUT_SECONDS",   False, "volatility",  "int",  600),
    "max_dump_size_bytes":      SettingDef("MAX_DUMP_SIZE_BYTES",       False, "volatility",  "int",  64 * 1024 ** 3),
    "max_cases_per_hour_per_user": SettingDef("MAX_CASES_PER_HOUR_PER_USER", False, "volatility", "int", 20),

    # ── MCP Server ────────────────────────────────────────────────────────────
    "mcp_enabled":              SettingDef("MCP_ENABLED",              False, "mcp",         "bool", False),

    # ── Watch Folder ──────────────────────────────────────────────────────────
    "watch_dir_enabled":        SettingDef("WATCH_DIR_ENABLED",        False, "watchdir",    "bool", False),
    "watch_dir":                SettingDef("WATCH_DIR",                False, "watchdir",    "str",  ""),
    "watch_dir_poll_interval":  SettingDef("WATCH_DIR_POLL_INTERVAL",  False, "watchdir",    "int",  30),
    "watch_dir_stable_age":     SettingDef("WATCH_DIR_STABLE_AGE",     False, "watchdir",    "int",  30),

    # ── LDAP ──────────────────────────────────────────────────────────────────
    "ldap_enabled":             SettingDef("LDAP_ENABLED",             False, "ldap",        "bool", False),
    "ldap_url":                 SettingDef("LDAP_URL",                 False, "ldap",        "str",  ""),
    "ldap_use_starttls":        SettingDef("LDAP_USE_STARTTLS",        False, "ldap",        "bool", False),
    "ldap_tls_verify":          SettingDef("LDAP_TLS_VERIFY",          False, "ldap",        "bool", True),
    "ldap_bind_dn":             SettingDef("LDAP_BIND_DN",             False, "ldap",        "str",  ""),
    "ldap_bind_password":       SettingDef("LDAP_BIND_PASSWORD",       True,  "ldap",        "str",  ""),
    "ldap_base_dn":             SettingDef("LDAP_BASE_DN",             False, "ldap",        "str",  ""),
    "ldap_user_filter":         SettingDef("LDAP_USER_FILTER",         False, "ldap",        "str",  "(mail={username})"),
    "ldap_attr_email":          SettingDef("LDAP_ATTR_EMAIL",          False, "ldap",        "str",  "mail"),
    "ldap_attr_display_name":   SettingDef("LDAP_ATTR_DISPLAY_NAME",   False, "ldap",        "str",  "displayName"),
    "ldap_group_base_dn":       SettingDef("LDAP_GROUP_BASE_DN",       False, "ldap",        "str",  ""),
    "ldap_admin_group":         SettingDef("LDAP_ADMIN_GROUP",         False, "ldap",        "str",  ""),
    "ldap_analyst_group":       SettingDef("LDAP_ANALYST_GROUP",       False, "ldap",        "str",  ""),
    "ldap_viewer_group":        SettingDef("LDAP_VIEWER_GROUP",        False, "ldap",        "str",  ""),
    "ldap_jit_provisioning":    SettingDef("LDAP_JIT_PROVISIONING",    False, "ldap",        "bool", True),

    # ── OIDC ──────────────────────────────────────────────────────────────────
    "oidc_enabled":             SettingDef("OIDC_ENABLED",             False, "oidc",        "bool", True),
    "oidc_client_id":           SettingDef("OIDC_CLIENT_ID",           False, "oidc",        "str",  ""),
    "oidc_client_secret":       SettingDef("OIDC_CLIENT_SECRET",       True,  "oidc",        "str",  ""),
    "oidc_discovery_url":       SettingDef("OIDC_DISCOVERY_URL",       False, "oidc",        "str",  ""),
    "oidc_redirect_uri":        SettingDef("OIDC_REDIRECT_URI",        False, "oidc",        "str",  ""),
    "oidc_frontend_callback_url": SettingDef("OIDC_FRONTEND_CALLBACK_URL", False, "oidc",    "str",  "http://localhost:3000/auth/callback"),
    "oidc_provider_name":       SettingDef("OIDC_PROVIDER_NAME",       False, "oidc",        "str",  "SSO"),
    "oidc_role_claim":          SettingDef("OIDC_ROLE_CLAIM",          False, "oidc",        "str",  "groups"),
    "oidc_admin_group":         SettingDef("OIDC_ADMIN_GROUP",         False, "oidc",        "str",  "memoryscope-admins"),
    "oidc_jit_provisioning":    SettingDef("OIDC_JIT_PROVISIONING",    False, "oidc",        "bool", False),
    "oidc_verify_ssl":          SettingDef("OIDC_VERIFY_SSL",          False, "oidc",        "bool", True),
}

# Fields whose Settings attribute holds SecretStr | None (not just SecretStr)
_NULLABLE_SECRETS = {"FALLBACK_API_KEY", "VIRUSTOTAL_API_KEY", "OIDC_CLIENT_SECRET"}


# ── Conversion helpers ────────────────────────────────────────────────────────

def _raw_from_setting(defn: SettingDef) -> str:
    """Read the current value from the in-memory settings object as a plain string."""
    raw = getattr(settings, defn.attr, defn.default)
    if raw is None:
        return ""
    if hasattr(raw, "get_secret_value"):
        return raw.get_secret_value()
    if isinstance(raw, bool):
        return "true" if raw else "false"
    if isinstance(raw, list):
        return json.dumps(raw)
    return str(raw)


def _apply_to_settings(key: str, raw_value: str) -> None:
    """Parse raw DB string and write it onto the in-memory settings object."""
    defn = SETTING_DEFS[key]

    if defn.vtype == "int":
        typed: Any = int(raw_value)
    elif defn.vtype == "bool":
        typed = raw_value.lower() in ("1", "true", "yes")
    elif defn.vtype == "json":
        typed = json.loads(raw_value)
    else:
        typed = raw_value

    if defn.secret:
        if typed == "" and defn.attr in _NULLABLE_SECRETS:
            typed = None
        elif typed != "" or defn.attr not in _NULLABLE_SECRETS:
            typed = SecretStr(typed) if isinstance(typed, str) else typed

    object.__setattr__(settings, defn.attr, typed)


# ── Public async API ──────────────────────────────────────────────────────────

async def seed_db_settings(db: AsyncSession) -> None:
    """
    Insert any missing runtime settings rows using the current env/default values.
    Called once at API startup — safe to call on every boot (idempotent).
    """
    from backend.db.models.models import SystemSetting

    existing_keys: set[str] = set(
        (await db.execute(select(SystemSetting.key))).scalars().all()
    )

    now = datetime.now(timezone.utc)
    new_rows = []
    for key, defn in SETTING_DEFS.items():
        if key not in existing_keys:
            new_rows.append(SystemSetting(
                key=key,
                value=_raw_from_setting(defn),
                is_secret=defn.secret,
                category=defn.category,
                updated_at=now,
            ))

    if new_rows:
        db.add_all(new_rows)
        await db.commit()
        logger.info("Seeded %d runtime setting(s) to system_settings", len(new_rows))


async def load_db_settings(db: AsyncSession) -> None:
    """
    Read all runtime settings from DB and apply them to the in-memory settings object.
    Called once at API startup (after seed_db_settings).
    """
    from backend.db.models.models import SystemSetting

    rows = (await db.execute(select(SystemSetting))).scalars().all()
    for row in rows:
        if row.key not in SETTING_DEFS:
            continue
        try:
            _apply_to_settings(row.key, row.value)
        except Exception as exc:
            logger.warning("Could not apply setting %r from DB: %s", row.key, exc)

    logger.info("Loaded %d runtime setting(s) from DB", len(rows))


async def save_setting(db: AsyncSession, key: str, raw_value: str) -> None:
    """
    Persist a single setting to DB and apply it immediately to the in-memory
    settings object.  Called by the admin PATCH /settings endpoint.
    """
    from backend.db.models.models import SystemSetting

    if key not in SETTING_DEFS:
        raise ValueError(f"Unknown setting key: {key!r}")

    defn = SETTING_DEFS[key]
    row = (await db.execute(select(SystemSetting).where(SystemSetting.key == key))).scalar_one_or_none()
    if row is None:
        row = SystemSetting(key=key, is_secret=defn.secret, category=defn.category,
                            value=raw_value, updated_at=datetime.now(timezone.utc))
        db.add(row)
    else:
        row.value = raw_value
        row.updated_at = datetime.now(timezone.utc)

    await db.commit()
    _apply_to_settings(key, raw_value)


# ── Sync API for Celery workers ───────────────────────────────────────────────

def load_db_settings_sync() -> None:
    """
    Sync version for Celery workers.  Reads system_settings via psycopg2 and
    applies them to the in-memory settings object.  Call at the start of any
    task that depends on runtime-configurable values (e.g. AI model, API keys).
    """
    import psycopg2  # type: ignore[import]

    # Workers use the sync DATABASE_URL (strip +asyncpg if present)
    db_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    try:
        conn = psycopg2.connect(db_url)
        with conn.cursor() as cur:
            cur.execute("SELECT key, value FROM system_settings")
            rows = cur.fetchall()
        conn.close()
    except Exception as exc:
        logger.warning("Could not load DB settings in worker: %s", exc)
        return

    for key, value in rows:
        if key not in SETTING_DEFS:
            continue
        try:
            _apply_to_settings(key, value)
        except Exception as exc:
            logger.warning("Worker: could not apply setting %r: %s", key, exc)

    logger.debug("Worker loaded %d runtime setting(s) from DB", len(rows))
