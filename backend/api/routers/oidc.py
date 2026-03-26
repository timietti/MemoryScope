# backend/api/routers/oidc.py
"""
OIDC / OAuth2 Authorization Code Flow for Authentik SSO.

Endpoints:
  GET /auth/oidc/config    — public; tells the frontend whether SSO is enabled
  GET /auth/oidc/login     — initiates the auth code flow (redirect to Authentik)
  GET /auth/oidc/callback  — handles the authorization code callback

Flow:
  Browser → /auth/oidc/login
          → Authentik (user authenticates)
          → /auth/oidc/callback?code=...&state=...
          → issues our own JWT pair
          → 302 to OIDC_FRONTEND_CALLBACK_URL?access_token=...&refresh_token=...

SSO is disabled (endpoints return 404) when OIDC_CLIENT_ID is not set.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

import httpx
from fastapi import APIRouter, Query, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select

from backend.config import settings
from backend.db.models.models import User, UserRole
from backend.db.session import async_session_factory
from backend.api.routers.auth import create_access_token, _issue_refresh_token
from backend.utils.audit import log_audit

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])
logger = logging.getLogger(__name__)

# ── Discovery document cache ───────────────────────────────────────────────────
# Fetched once and kept in memory; invalidated on any token-exchange failure.

_discovery_cache: dict[str, Any] | None = None


async def _get_discovery() -> dict[str, Any]:
    global _discovery_cache
    if _discovery_cache is not None:
        return _discovery_cache
    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.get(settings.OIDC_DISCOVERY_URL)
        resp.raise_for_status()
    _discovery_cache = resp.json()
    logger.info("OIDC discovery document fetched from %s", settings.OIDC_DISCOVERY_URL)
    return _discovery_cache


async def _get_jwks() -> dict[str, Any]:
    discovery = await _get_discovery()
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

def _error_redirect(code: str) -> RedirectResponse:
    base = settings.OIDC_FRONTEND_CALLBACK_URL.rstrip("/")
    resp = RedirectResponse(f"{base}?error={code}", status_code=302)
    resp.delete_cookie(_STATE_COOKIE)
    return resp


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.get("/config")
async def oidc_config():
    """
    Public endpoint consumed by the login page to decide whether to show
    the SSO button. Never reveals secrets.
    """
    enabled = bool(
        settings.OIDC_CLIENT_ID
        and settings.OIDC_CLIENT_SECRET
        and settings.OIDC_DISCOVERY_URL
        and settings.OIDC_REDIRECT_URI
        and settings.OIDC_FRONTEND_CALLBACK_URL
    )
    return {
        "enabled": enabled,
        "provider_name": settings.OIDC_PROVIDER_NAME,
    }


@router.get("/login")
async def oidc_login():
    """
    Start the OIDC Authorization Code Flow.
    Generates state + nonce, stores them in a signed cookie, and redirects
    the browser to the Authentik authorization endpoint.
    """
    if not settings.OIDC_CLIENT_ID:
        from fastapi import HTTPException
        raise HTTPException(404, "SSO is not configured")

    discovery = await _get_discovery()
    auth_endpoint = discovery["authorization_endpoint"]

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)

    params = "&".join([
        "response_type=code",
        f"client_id={settings.OIDC_CLIENT_ID}",
        f"redirect_uri={settings.OIDC_REDIRECT_URI}",
        "scope=openid+email+profile+groups",
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
async def oidc_callback(
    request: Request,
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
        return _error_redirect(error)

    if not code or not state:
        return _error_redirect("missing_params")

    # Validate state cookie
    cookie = request.cookies.get(_STATE_COOKIE)
    if not cookie:
        logger.warning("OIDC callback: state cookie missing")
        return _error_redirect("invalid_state")

    nonce = _parse_state_cookie(cookie, state)
    if nonce is None:
        logger.warning("OIDC callback: state/signature invalid")
        return _error_redirect("invalid_state")

    # Exchange code for tokens
    global _discovery_cache
    try:
        discovery = await _get_discovery()
        token_endpoint = discovery["token_endpoint"]
    except Exception as exc:
        logger.error("OIDC: failed to fetch discovery document: %s", exc)
        _discovery_cache = None
        return _error_redirect("discovery_failed")

    async with httpx.AsyncClient(timeout=15) as client:
        token_resp = await client.post(token_endpoint, data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": settings.OIDC_REDIRECT_URI,
            "client_id": settings.OIDC_CLIENT_ID,
            "client_secret": settings.OIDC_CLIENT_SECRET.get_secret_value(),
        })

    if token_resp.status_code != 200:
        logger.error("OIDC token exchange failed (%d): %s", token_resp.status_code, token_resp.text)
        _discovery_cache = None   # force rediscovery next attempt
        return _error_redirect("token_exchange_failed")

    token_data = token_resp.json()
    id_token_raw = token_data.get("id_token")
    if not id_token_raw:
        logger.error("OIDC: token response missing id_token")
        return _error_redirect("no_id_token")

    # Verify id_token signature using the provider's public keys (JWKS)
    try:
        from jose import jwt as jose_jwt
        jwks = await _get_jwks()
        claims = jose_jwt.decode(
            id_token_raw,
            jwks,
            algorithms=["RS256", "ES256"],
            audience=settings.OIDC_CLIENT_ID,
            options={"verify_at_hash": False},
        )
    except Exception as exc:
        logger.error("OIDC id_token verification failed: %s", exc)
        return _error_redirect("token_invalid")

    # Validate nonce (replay protection)
    if claims.get("nonce") != nonce:
        logger.warning("OIDC callback: nonce mismatch")
        return _error_redirect("nonce_mismatch")

    # Extract user attributes
    email: str = claims.get("email", "").lower().strip()
    email_verified: bool = claims.get("email_verified", False)
    display_name: str = (
        claims.get("name")
        or claims.get("preferred_username")
        or email.split("@")[0]
    )
    groups: list[str] = claims.get(settings.OIDC_ROLE_CLAIM) or []

    if not email:
        logger.error("OIDC callback: id_token contains no email claim")
        return _error_redirect("no_email")

    if not email_verified:
        logger.warning("OIDC login rejected: unverified email %s", email)
        return _error_redirect("email_not_verified")

    # Look up or provision the user
    async with async_session_factory() as db:
        user = (await db.execute(
            select(User).where(User.email == email)
        )).scalar_one_or_none()

        if user is None:
            if not settings.OIDC_JIT_PROVISIONING:
                logger.warning("OIDC login rejected: %s has no local account (JIT disabled)", email)
                return _error_redirect("not_provisioned")

            role = (
                UserRole.admin
                if settings.OIDC_ADMIN_GROUP and settings.OIDC_ADMIN_GROUP in groups
                else UserRole.analyst
            )
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
            return _error_redirect("account_disabled")

        user.last_login_at = datetime.now(timezone.utc)
        await db.commit()

        await log_audit(db, "user.login", actor_id=user.id, target_user_id=user.id,
                        payload={"email": email, "method": "oidc", "provider": "authentik"})

        refresh_raw = await _issue_refresh_token(str(user.id), db)
        access_token = create_access_token(str(user.id))

    logger.info("OIDC login successful: %s", email)

    base = settings.OIDC_FRONTEND_CALLBACK_URL.rstrip("/")
    response = RedirectResponse(
        f"{base}?access_token={access_token}&refresh_token={refresh_raw}",
        status_code=302,
    )
    response.delete_cookie(_STATE_COOKIE)
    return response
