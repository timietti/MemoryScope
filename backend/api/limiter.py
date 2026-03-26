# backend/api/limiter.py
"""
Shared slowapi rate-limiter instance.

Import this in routers that need per-IP rate limiting.
The limiter uses the Redis backend so limits are consistent across
multiple uvicorn workers.
"""
from slowapi import Limiter
from slowapi.util import get_remote_address

from backend.config import settings

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
)
