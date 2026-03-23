# backend/utils/notifications.py
"""
Publish case events from Celery workers → Redis Pub/Sub → WebSocket clients.
Also persists every event to the case_events audit table.

Used by workers (sync) and can be awaited from async contexts via
asyncio.get_event_loop().run_until_complete() inside Celery tasks.
"""
from __future__ import annotations
import json
import logging

logger = logging.getLogger(__name__)


def publish_case_event(case_id: str, event_type: str, data: dict) -> None:
    """
    Publish a case lifecycle event.
    Safe to call from Celery workers (synchronous).
    Failures are logged and swallowed — events are best-effort.
    """
    import redis as sync_redis
    from backend.config import settings

    payload = json.dumps({"event": event_type, "data": data})
    channel = f"case:{case_id}:events"

    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        r.publish(channel, payload)
        logger.debug("Published %s → %s", event_type, channel)
    except Exception as exc:
        logger.warning("Redis publish failed [%s/%s]: %s", case_id, event_type, exc)
    finally:
        try:
            r.close()
        except Exception:
            pass

    # Persist to audit table (non-fatal if this fails too)
    try:
        _persist_event_sync(case_id, event_type, data)
    except Exception as exc:
        logger.warning("Event persistence failed [%s/%s]: %s", case_id, event_type, exc)


def _persist_event_sync(case_id: str, event_type: str, data: dict) -> None:
    """Write event to case_events using a fresh synchronous DB connection."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy import cast
    from backend.config import settings

    sync_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    engine = create_engine(sync_url, pool_pre_ping=True, pool_size=1, max_overflow=0)

    with engine.begin() as conn:
        conn.execute(
            text("""
                INSERT INTO case_events (case_id, event_type, payload)
                VALUES (:case_id, :event_type, :payload)
            """),
            {
                "case_id": case_id,
                "event_type": event_type,
                "payload": json.dumps(data),
            },
        )

    engine.dispose()
