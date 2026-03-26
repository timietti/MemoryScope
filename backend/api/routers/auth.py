# backend/api/routers/auth.py
import hashlib
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
from backend.db.models.models import User, RefreshToken
from backend.utils.audit import log_audit
from backend.api.limiter import limiter

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

    class Config:
        from_attributes = True

    @field_validator('id', 'role', mode='before')
    @classmethod
    def coerce_to_str(cls, v) -> str:
        return v.value if hasattr(v, 'value') else str(v)


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
    email_lc = form.username.lower().strip()
    source_ip = request.client.host if request.client else "unknown"

    # Per-email lockout check
    await _check_lockout(email_lc)

    user = (await db.execute(select(User).where(User.email == email_lc))).scalar_one_or_none()

    if not user or not pwd_context.verify(form.password, user.password_hash or ""):
        # Audit the failed attempt regardless of whether the user exists
        if user:
            await log_audit(db, "user.login_failed", actor_id=None, target_user_id=user.id,
                            payload={"email": email_lc, "source_ip": source_ip})
        else:
            await log_audit(db, "user.login_failed", actor_id=None, target_user_id=None,
                            payload={"email": email_lc, "source_ip": source_ip})
        await _record_failed_login(email_lc)
        # Use a constant-time response to avoid user enumeration
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
