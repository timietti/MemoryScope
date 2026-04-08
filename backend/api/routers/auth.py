# backend/api/routers/auth.py
import asyncio
import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, field_validator
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.config import settings
from backend.db.session import get_db
from backend.db.models.models import User, RefreshToken, UserRole
from backend.utils.audit import log_audit
from backend.api.limiter import limiter

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Per-email lockout: block after this many failures within the window
_LOCKOUT_THRESHOLD = 10
_LOCKOUT_WINDOW_SECONDS = 15 * 60  # 15 minutes


async def _check_lockout(email: str) -> None:
    """Raise 429 if the email has too many recent failed logins."""
    import redis.asyncio as aioredis
    key = f"login_lockout:{email.lower()}"
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        count = await rc.get(key)
    if count and int(count) >= _LOCKOUT_THRESHOLD:
        raise HTTPException(status_code=429, detail="Account temporarily locked due to too many failed login attempts")


async def _record_failed_login(email: str) -> None:
    """Increment per-email failure counter in Redis."""
    import redis.asyncio as aioredis
    key = f"login_lockout:{email.lower()}"
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        pipe = rc.pipeline()
        pipe.incr(key)
        pipe.expire(key, _LOCKOUT_WINDOW_SECONDS)
        await pipe.execute()


async def _clear_lockout(email: str) -> None:
    """Clear failure counter on successful login."""
    import redis.asyncio as aioredis
    key = f"login_lockout:{email.lower()}"
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        await rc.delete(key)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/token")


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str
    role: str
    sso_provider: str | None = None

    class Config:
        from_attributes = True

    @field_validator('id', 'role', mode='before')
    @classmethod
    def coerce_to_str(cls, v) -> str:
        return v.value if hasattr(v, 'value') else str(v)


class ProfileUpdate(BaseModel):
    email: str | None = None
    display_name: str | None = None
    current_password: str | None = None
    new_password: str | None = None


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_ACCESS_EXPIRE_MINUTES)
    return jwt.encode(
        {"sub": subject, "exp": expire},
        settings.SECRET_KEY.get_secret_value(),
        algorithm=settings.JWT_ALGORITHM,
    )


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


async def _issue_refresh_token(user_id: str, db: AsyncSession) -> str:
    """Generate a new refresh token, persist its hash, and return the raw token."""
    raw = secrets.token_hex(32)
    db.add(RefreshToken(
        user_id=user_id,
        token_hash=_hash_token(raw),
        expires_at=datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS),
    ))
    await db.commit()
    return raw


@router.post("/token", response_model=Token)
@limiter.limit("5/minute")
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    username_raw = form.username.strip()
    email_lc = username_raw.lower()
    source_ip = request.client.host if request.client else "unknown"

    # Per-email/username lockout check
    await _check_lockout(email_lc)

    # ── LDAP authentication path ──────────────────────────────────────────────
    if settings.LDAP_ENABLED:
        user = await _try_ldap_login(username_raw, form.password, email_lc, source_ip, db)
        if user is not None:
            return user

    # ── Local authentication path ─────────────────────────────────────────────
    user = (await db.execute(select(User).where(User.email == email_lc))).scalar_one_or_none()

    # LDAP-only accounts (no password_hash) must authenticate via LDAP
    if user and user.sso_provider == "ldap" and not user.password_hash:
        await _record_failed_login(email_lc)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user or not pwd_context.verify(form.password, user.password_hash or ""):
        if user:
            await log_audit(db, "user.login_failed", actor_id=None, target_user_id=user.id,
                            payload={"email": email_lc, "source_ip": source_ip})
        else:
            await log_audit(db, "user.login_failed", actor_id=None, target_user_id=None,
                            payload={"email": email_lc, "source_ip": source_ip})
        await _record_failed_login(email_lc)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account disabled")

    await _clear_lockout(email_lc)
    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await log_audit(db, "user.login", actor_id=user.id, target_user_id=user.id,
                    payload={"email": user.email, "role": user.role.value, "source_ip": source_ip})
    refresh_raw = await _issue_refresh_token(str(user.id), db)
    return Token(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_raw,
    )


async def _try_ldap_login(
    username: str,
    password: str,
    lockout_key: str,
    source_ip: str,
    db: AsyncSession,
) -> Token | None:
    """
    Attempt LDAP authentication.  Returns a Token on success, None if LDAP
    does not recognise the user (so caller can fall through to local auth).
    Raises HTTPException for LDAP-specific denials (disabled account, not in
    any authorised group).
    """
    from backend.core.ldap_auth import authenticate_ldap, LdapAuthError

    try:
        ldap_info = await asyncio.to_thread(authenticate_ldap, username, password)
    except LdapAuthError as exc:
        logger.debug("LDAP auth failed for %r: %s", username, exc.detail)
        # "not a member of any authorised group" is a definitive denial — don't
        # fall through to local auth, as the user was found but has no access.
        if "not a member of any authorised group" in exc.detail:
            await _record_failed_login(lockout_key)
            await log_audit(db, "user.login_failed", actor_id=None, target_user_id=None,
                            payload={"username": username, "source_ip": source_ip,
                                     "reason": "ldap_no_group"})
            raise HTTPException(status_code=403, detail="Account not authorised — contact your administrator")
        # For all other LDAP errors (user not found, server unreachable, etc.)
        # fall through to local auth so local admin accounts always work.
        return None

    # LDAP auth succeeded — upsert the user record
    email = ldap_info.email
    role = UserRole(ldap_info.role)

    user = (await db.execute(select(User).where(User.email == email))).scalar_one_or_none()

    if user is None:
        if not settings.LDAP_JIT_PROVISIONING:
            logger.info("LDAP JIT provisioning disabled; rejecting new user %s", email)
            await _record_failed_login(lockout_key)
            raise HTTPException(status_code=403, detail="Account not provisioned — contact your administrator")
        user = User(
            email=email,
            display_name=ldap_info.display_name,
            password_hash=None,
            sso_provider="ldap",
            role=role,
            is_active=True,
        )
        db.add(user)
        await db.flush()  # populate user.id
        await log_audit(db, "user.created", actor_id=None, target_user_id=user.id,
                        payload={"email": email, "source": "ldap_jit"})
    else:
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account disabled")
        # Sync role from LDAP on every login
        user.role = role

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()
    await _clear_lockout(lockout_key)
    await log_audit(db, "user.login", actor_id=user.id, target_user_id=user.id,
                    payload={"email": email, "role": role.value, "source_ip": source_ip,
                             "source": "ldap"})
    refresh_raw = await _issue_refresh_token(str(user.id), db)
    return Token(
        access_token=create_access_token(str(user.id)),
        refresh_token=refresh_raw,
    )


@router.post("/refresh", response_model=Token)
async def refresh(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """
    Exchange a valid refresh token for a new access + refresh token pair.
    The old refresh token is revoked (rotation).
    """
    token_hash = _hash_token(body.refresh_token)
    record = (await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )).scalar_one_or_none()

    if not record or record.revoked_at is not None:
        raise HTTPException(status_code=401, detail="Invalid or revoked refresh token")
    if record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Refresh token expired")

    # Rotate: revoke old token, issue new one
    record.revoked_at = datetime.now(timezone.utc)
    await db.commit()

    refresh_raw = await _issue_refresh_token(str(record.user_id), db)
    return Token(
        access_token=create_access_token(str(record.user_id)),
        refresh_token=refresh_raw,
    )


@router.post("/logout", status_code=204)
async def logout(body: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Revoke a refresh token. Silent success if token is unknown."""
    token_hash = _hash_token(body.refresh_token)
    record = (await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )).scalar_one_or_none()
    if record and record.revoked_at is None:
        record.revoked_at = datetime.now(timezone.utc)
        await db.commit()


@router.get("/me", response_model=UserOut)
async def me(db: AsyncSession = Depends(get_db), token: str = Depends(oauth2_scheme)):
    user = await _get_user_from_token(token, db)
    return UserOut.model_validate(user)


@router.patch("/me", response_model=UserOut)
async def update_me(
    body: ProfileUpdate,
    db: AsyncSession = Depends(get_db),
    token: str = Depends(oauth2_scheme),
):
    user = await _get_user_from_token(token, db)

    if body.display_name is not None:
        stripped = body.display_name.strip()
        if not stripped:
            raise HTTPException(status_code=422, detail="Display name cannot be empty")
        user.display_name = stripped

    if body.email is not None:
        new_email = body.email.strip().lower()
        if not new_email:
            raise HTTPException(status_code=422, detail="Email cannot be empty")
        if new_email != user.email:
            existing = (await db.execute(
                select(User).where(User.email == new_email)
            )).scalar_one_or_none()
            if existing:
                raise HTTPException(status_code=409, detail="Email already in use")
            user.email = new_email

    if body.new_password is not None:
        if user.sso_provider:
            raise HTTPException(status_code=400, detail="Password cannot be changed for SSO accounts")
        if not body.current_password:
            raise HTTPException(status_code=422, detail="current_password is required to set a new password")
        if not pwd_context.verify(body.current_password, user.password_hash or ""):
            raise HTTPException(status_code=400, detail="Current password is incorrect")
        if len(body.new_password) < 8:
            raise HTTPException(status_code=422, detail="New password must be at least 8 characters")
        user.password_hash = pwd_context.hash(body.new_password)

    await db.commit()
    await db.refresh(user)
    await log_audit(db, "user.profile_updated", actor_id=user.id, target_user_id=user.id,
                    payload={"fields_changed": [
                        k for k, v in {"email": body.email, "display_name": body.display_name,
                                        "password": body.new_password}.items() if v is not None
                    ]})
    return UserOut.model_validate(user)


async def _get_user_from_token(token: str, db: AsyncSession) -> User:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY.get_secret_value(), algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = (await db.execute(select(User).where(User.id == user_id))).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user
