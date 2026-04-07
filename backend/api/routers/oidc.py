# backend/api/routers/oidc.py
"""
OIDC / OAuth2 Authorization Code Flow for Authentik SSO.

Endpoints:
  GET  /auth/oidc/config         — public; tells the frontend whether SSO is enabled
  GET  /auth/oidc/login          — initiates the auth code flow (redirect to Authentik)
  GET  /auth/oidc/callback       — handles the authorization code callback
  POST /auth/oidc/token-exchange — frontend exchanges short-lived code for JWT pair

Flow:
  Browser → /auth/oidc/login
          → Authentik (user authenticates)
          → /auth/oidc/callback?code=...&state=...
          → stores JWT pair in Redis under exchange code (60 s TTL)
          → 302 to OIDC_FRONTEND_CALLBACK_URL?code=<exchange_code>
          → frontend POSTs code to /auth/oidc/token-exchange
          → receives {access_token, refresh_token} in response body

Tokens are never delivered via URL query parameters to avoid logging in
browser history, server access logs, and Referer headers.

SSO is disabled (endpoints return 404) when OIDC_CLIENT_ID is not set.

OIDC settings are read from the database on every request so that all
uvicorn worker processes see the current values without needing a restart.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx
import redis.asyncio as aioredis
from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import settings
from backend.db.models.models import User, UserRole, SystemSetting
from backend.db.session import async_session_factory, get_db
from backend.api.routers.auth import create_access_token, _issue_refresh_token
from backend.utils.audit import log_audit
from backend.api.limiter import limiter

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])
logger = logging.getLogger(__name__)


# ── Live OIDC config (DB-backed, per-request) ─────────────────────────────────

@dataclass
class OIDCConfig:
    client_id: str
    client_secret: str
    discovery_url: str
    redirect_uri: str
    frontend_callback_url: str
    provider_name: str
    role_claim: str
    admin_group: str
    viewer_group: str
    jit_provisioning: bool

    @property
    def enabled(self) -> bool:
        return bool(
            self.client_id
            and self.client_secret
            and self.discovery_url
            and self.redirect_uri
            and self.frontend_callback_url
        )


async def get_oidc_cfg(db: AsyncSession = Depends(get_db)) -> OIDCConfig:
    """
    Load OIDC settings directly from the database on every request.
    This ensures all uvicorn worker processes see the current configuration
    without requiring a restart after Admin UI changes.
    """
    rows = (await db.execute(
        select(SystemSetting).where(SystemSetting.category == "oidc")
    )).scalars().all()
    kv = {r.key: r.value for r in rows}
    return OIDCConfig(
        client_id=kv.get("oidc_client_id", ""),
        client_secret=kv.get("oidc_client_secret", ""),
        discovery_url=kv.get("oidc_discovery_url", ""),
        redirect_uri=kv.get("oidc_redirect_uri", ""),
        frontend_callback_url=kv.get("oidc_frontend_callback_url", "http://localhost:3000/auth/callback"),
        provider_name=kv.get("oidc_provider_name", "SSO"),
        role_claim=kv.get("oidc_role_claim", "groups"),
        admin_group=kv.get("oidc_admin_group", "memoryscope-admins"),
        viewer_group=kv.get("oidc_viewer_group", "memoryscope-viewers"),
        jit_provisioning=kv.get("oidc_jit_provisioning", "false").lower() in ("1", "true", "yes"),
    )


# ── Discovery document cache ───────────────────────────────────────────────────
# Cached per-process; invalidated when the discovery URL changes or on token
# exchange failure.

_discovery_cache: dict[str, Any] | None = None
_discovery_url_cached: str | None = None


async def _get_discovery(discovery_url: str) -> dict[str, Any]:
    global _discovery_cache, _discovery_url_cached
    if _discovery_cache is not None and _discovery_url_cached == discovery_url:
        return _discovery_cache
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery_url)
        resp.raise_for_status()
    _discovery_cache = resp.json()
    _discovery_url_cached = discovery_url
    logger.info("OIDC discovery document fetched from %s", discovery_url)
    return _discovery_cache


async def _get_jwks(discovery_url: str) -> dict[str, Any]:
    discovery = await _get_discovery(discovery_url)
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(discovery["jwks_uri"])
        resp.raise_for_status()
    return resp.json()


# ── State cookie ───────────────────────────────────────────────────────────────
# The state and nonce are packed together and HMAC-signed with SECRET_KEY so
# they cannot be forged. Stored as an httpOnly cookie for 10 minutes.

_STATE_COOKIE = "oidc_state"
_STATE_TTL = 600  # seconds


def _make_state_cookie(state: str, nonce: str) -> str:
    """Return a signed cookie value containing state + nonce."""
    payload = f"{state}:{nonce}"
    sig = hmac.new(
        settings.SECRET_KEY.get_secret_value().encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{payload}:{sig}"


def _parse_state_cookie(cookie: str, expected_state: str) -> str | None:
    """
    Verify the HMAC signature and the state value.
    Returns the nonce on success, None on any failure.
    """
    try:
        # Format: "<state>:<nonce>:<sig>"
        last_colon = cookie.rfind(":")
        if last_colon == -1:
            return None
        payload, sig = cookie[:last_colon], cookie[last_colon + 1:]
        expected_sig = hmac.new(
            settings.SECRET_KEY.get_secret_value().encode(),
            payload.encode(),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        parts = payload.split(":", 1)
        if len(parts) != 2 or parts[0] != expected_state:
            return None
        return parts[1]  # nonce
    except Exception:
        return None


# ── Helper: redirect to frontend with an error param ─────────────────────────

def _error_redirect(frontend_callback_url: str, code: str) -> RedirectResponse:
    base = frontend_callback_url.rstrip("/")
    resp = RedirectResponse(f"{base}?error={code}", status_code=302)
    resp.delete_cookie(_STATE_COOKIE)
    return resp


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/config")
async def oidc_config(cfg: OIDCConfig = Depends(get_oidc_cfg)):
    """
    Public endpoint consumed by the login page to decide whether to show
    the SSO button. Never reveals secrets.
    """
    return {
        "enabled": cfg.enabled,
        "provider_name": cfg.provider_name,
    }


@router.get("/login")
@limiter.limit("10/minute")
async def oidc_login(request: Request, cfg: OIDCConfig = Depends(get_oidc_cfg)):
    """
    Start the OIDC Authorization Code Flow.
    Generates state + nonce, stores them in a signed cookie, and redirects
    the browser to the Authentik authorization endpoint.
    """
    if not cfg.client_id:
        from fastapi import HTTPException
        raise HTTPException(404, "SSO is not configured")

    discovery = await _get_discovery(cfg.discovery_url)
    auth_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    params = "&".join([
        "response_type=code",
        f"client_id={cfg.client_id}",
        f"redirect_uri={cfg.redirect_uri}",
        "scope=openid+email+profile",
        f"state={state}",
        f"nonce={nonce}",
    ])

    response = RedirectResponse(f"{auth_endpoint}?{params}", status_code=302)
    response.set_cookie(
        _STATE_COOKIE,
        _make_state_cookie(state, nonce),
        max_age=_STATE_TTL,
        httponly=True,
        samesite="lax",
        secure=(settings.ENV == "production"),
    )
    return response


@router.get("/callback")
@limiter.limit("20/minute")
async def oidc_callback(
    request: Request,
    cfg: OIDCConfig = Depends(get_oidc_cfg),
    code: str | None = Query(None),
    state: str | None = Query(None),
    error: str | None = Query(None),
    error_description: str | None = Query(None),
):
    """
    Receive the authorization code from Authentik, exchange it for tokens,
    verify the id_token, look up / provision the user, issue our own JWT pair,
    and redirect the browser back to the frontend with the tokens in the URL.
    """
    # Provider sent an error
    if error:
        logger.warning("OIDC provider error: %s — %s", error, error_description)
        return _error_redirect(cfg.frontend_callback_url, error)

    if not code or not state:
        return _error_redirect(cfg.frontend_callback_url, "missing_params")

    # Validate state cookie
    cookie = request.cookies.get(_STATE_COOKIE)
    if not cookie:
        logger.warning("OIDC callback: state cookie missing")
        return _error_redirect(cfg.frontend_callback_url, "invalid_state")

    nonce = _parse_state_cookie(cookie, state)
    if nonce is None:
        logger.warning("OIDC callback: state/signature invalid")
        return _error_redirect(cfg.frontend_callback_url, "invalid_state")

    # Exchange code for tokens
    global _discovery_cache
    try:
        discovery = await _get_discovery(cfg.discovery_url)
        token_endpoint = discovery["token_endpoint"]
    except Exception as exc:
        logger.error("OIDC: failed to fetch discovery document: %s", exc)
        _discovery_cache = None
        return _error_redirect(cfg.frontend_callback_url, "discovery_failed")

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(token_endpoint, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": cfg.redirect_uri,
            "client_id": cfg.client_id,
            "client_secret": cfg.client_secret,
        })

    if token_resp.status_code != 200:
        logger.error("OIDC token exchange failed (%d): %s", token_resp.status_code, token_resp.text)
        _discovery_cache = None   # force rediscovery next attempt
        return _error_redirect(cfg.frontend_callback_url, "token_exchange_failed")

    token_data = token_resp.json()
    id_token_raw = token_data.get("id_token")
    if not id_token_raw:
        logger.error("OIDC: token response missing id_token")
        return _error_redirect(cfg.frontend_callback_url, "no_id_token")

    # Verify id_token signature using the provider's public keys (JWKS)
    try:
        from jose import jwt as jose_jwt
        jwks = await _get_jwks(cfg.discovery_url)
        claims = jose_jwt.decode(
            id_token_raw,
            jwks,
            algorithms=["RS256", "ES256"],
            audience=cfg.client_id,
            options={"verify_at_hash": False},
        )
    except Exception as exc:
        logger.error("OIDC id_token verification failed: %s", exc)
        return _error_redirect(cfg.frontend_callback_url, "token_invalid")

    # Validate nonce (replay protection)
    if claims.get("nonce") != nonce:
        logger.warning("OIDC callback: nonce mismatch")
        return _error_redirect(cfg.frontend_callback_url, "nonce_mismatch")

    # Extract user attributes
    email: str = claims.get("email", "").lower().strip()
    email_verified: bool = claims.get("email_verified", False)
    display_name: str = (
        claims.get("name")
        or claims.get("preferred_username")
        or email.split("@")[0]
    )
    groups: list[str] = claims.get(cfg.role_claim) or []

    if not email:
        logger.error("OIDC callback: id_token contains no email claim")
        return _error_redirect(cfg.frontend_callback_url, "no_email")

    if not email_verified:
        logger.warning("OIDC login rejected: unverified email %s", email)
        return _error_redirect(cfg.frontend_callback_url, "email_not_verified")

    # Look up or provision the user
    async with async_session_factory() as db:
        user = (await db.execute(
            select(User).where(User.email == email)
        )).scalar_one_or_none()

        if user is None:
            if not cfg.jit_provisioning:
                logger.warning("OIDC login rejected: %s has no local account (JIT disabled)", email)
                return _error_redirect(cfg.frontend_callback_url, "not_provisioned")

            if cfg.admin_group and cfg.admin_group in groups:
                role = UserRole.admin
            elif cfg.viewer_group and cfg.viewer_group in groups:
                role = UserRole.viewer
            else:
                role = UserRole.analyst
            user = User(
                email=email,
                display_name=display_name,
                password_hash=None,
                sso_provider="authentik",
                role=role,
            )
            db.add(user)
            await db.commit()
            await db.refresh(user)
            await log_audit(db, "user.created", actor_id=user.id, target_user_id=user.id,
                            payload={"email": email, "method": "oidc_jit", "role": role.value})
            logger.info("JIT-provisioned SSO user %s as %s", email, role.value)

        if not user.is_active:
            logger.warning("OIDC login rejected: account %s is disabled", email)
            return _error_redirect(cfg.frontend_callback_url, "account_disabled")

        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()

        source_ip = request.client.host if request.client else "unknown"
        await log_audit(db, "user.login", actor_id=user.id, target_user_id=user.id,
                        payload={"email": email, "method": "oidc", "provider": "authentik",
                                 "source_ip": source_ip})

        refresh_raw = await _issue_refresh_token(str(user.id), db)
        access_token = create_access_token(str(user.id))

    logger.info("OIDC login successful: %s", email)

    # C-1 fix: do NOT deliver tokens via URL query parameters.
    # Store the JWT pair in Redis under a single-use exchange code (60 s TTL)
    # and redirect with only the code.  The frontend POSTs the code to
    # /auth/oidc/token-exchange to retrieve the tokens over a secure POST body.
    exchange_code = secrets.token_urlsafe(32)
    redis_key = f"oidc_code:{exchange_code}"
    import json as _json
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        await rc.set(redis_key, _json.dumps({
            "access_token": access_token,
            "refresh_token": refresh_raw,
        }), ex=60)

    base = cfg.frontend_callback_url.rstrip("/")
    response = RedirectResponse(f"{base}?code={exchange_code}", status_code=302)
    response.delete_cookie(_STATE_COOKIE)
    return response


# ── Token-exchange endpoint ────────────────────────────────────────────────────

class _ExchangeRequest(BaseModel):
    code: str


@router.post("/token-exchange")
async def oidc_token_exchange(
    body: _ExchangeRequest = Body(...),
    cfg: OIDCConfig = Depends(get_oidc_cfg),
):
    """
    Frontend calls this after landing on /auth/callback?code=<exchange_code>.
    Looks up the short-lived code in Redis (60 s TTL, single-use) and returns
    the JWT pair in the response body — never in a URL.
    """
    if not cfg.client_id:
        from fastapi import HTTPException
        raise HTTPException(404, "SSO is not configured")

    redis_key = f"oidc_code:{body.code}"
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        raw = await rc.getdel(redis_key)   # single-use: delete on read

    if not raw:
        from fastapi import HTTPException
        raise HTTPException(400, "Invalid or expired exchange code")

    import json as _json
    tokens = _json.loads(raw)
    return JSONResponse({"access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"]})
