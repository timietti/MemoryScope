# backend/api/routers/setup.py
"""
First-run setup wizard endpoints.

  GET  /setup/status   — public; returns { needs_setup: true } when no users exist
  POST /setup/complete — public; creates the first admin user + seeds system_settings;
                         returns a JWT pair for immediate login.

Both endpoints return 404 once any user exists (setup is permanently disabled).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import get_db
from backend.db.models.models import User, UserRole

router = APIRouter(prefix="/setup", tags=["setup"])
logger = logging.getLogger(__name__)
_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


async def _assert_needs_setup(db: AsyncSession) -> None:
    """Raise 404 if at least one user already exists."""
    count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
    if count > 0:
        raise HTTPException(status_code=404, detail="Setup already completed")


# ── GET /setup/status ─────────────────────────────────────────────────────────

@router.get("/status")
async def setup_status(db: AsyncSession = Depends(get_db)):
    count = (await db.execute(select(func.count()).select_from(User))).scalar() or 0
    return {"needs_setup": count == 0}


# ── POST /setup/complete ──────────────────────────────────────────────────────

class SetupPayload(BaseModel):
    # Admin account
    email: str
    display_name: str
    password: str

    # AI
    anthropic_api_key: str = ""
    primary_model: str = "claude-opus-4-5"
    fast_model: str = "claude-sonnet-4-5"

    # Volatility
    volatility_path: str = "/opt/volatility3/vol.py"
    symbol_cache_path: str = "/opt/volatility3/symbols"
    dwarf2json_path: str = "dwarf2json"


@router.post("/complete")
async def setup_complete(
    body: SetupPayload,
    db: AsyncSession = Depends(get_db),
):
    await _assert_needs_setup(db)

    # Create the admin user
    user = User(
        email=body.email,
        display_name=body.display_name,
        password_hash=_pwd.hash(body.password),
        role=UserRole.admin,
    )
    db.add(user)
    await db.flush()   # get user.id before committing settings

    # Persist wizard values to system_settings
    from backend.utils.db_settings import save_setting
    wizard_settings: dict[str, str] = {
        "anthropic_api_key": body.anthropic_api_key,
        "primary_model":     body.primary_model,
        "fast_model":        body.fast_model,
        "volatility_path":   body.volatility_path,
        "symbol_cache_path": body.symbol_cache_path,
        "dwarf2json_path":   body.dwarf2json_path,
    }
    for key, value in wizard_settings.items():
        if value:
            await save_setting(db, key, value)

    await db.commit()
    await db.refresh(user)
    logger.info("Setup completed — first admin user created: %s", user.email)

    # Issue a JWT pair so the user is logged in immediately
    from backend.api.routers.auth import create_access_token, _issue_refresh_token
    access_token = create_access_token(str(user.id))
    refresh_raw = await _issue_refresh_token(str(user.id), db)

    return {
        "access_token": access_token,
        "refresh_token": refresh_raw,
        "token_type": "bearer",
    }
