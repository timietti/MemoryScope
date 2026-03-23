# backend/api/routers/ws.py
"""
WebSocket endpoint for real-time case status updates.
Each connected client subscribes to specific case channels.
Events are published by workers via Redis Pub/Sub → API → WebSocket.
"""
from __future__ import annotations
import asyncio
import json
import logging
from typing import TYPE_CHECKING
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query
from starlette.websockets import WebSocketState

from backend.config import settings
from backend.api.dependencies import verify_ws_token

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


class ConnectionManager:
    """Manages active WebSocket connections grouped by case_id."""

    def __init__(self):
        # case_id → set of WebSocket objects
        self._connections: dict[str, set[WebSocket]] = {}

    async def connect(self, case_id: str, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.setdefault(case_id, set()).add(ws)
        logger.info("WS connected: case=%s total=%d", case_id, len(self._connections[case_id]))

    def disconnect(self, case_id: str, ws: WebSocket) -> None:
        conns = self._connections.get(case_id, set())
        conns.discard(ws)
        if not conns:
            self._connections.pop(case_id, None)
        logger.info("WS disconnected: case=%s remaining=%d", case_id, len(conns))

    async def broadcast(self, case_id: str, message: dict) -> None:
        conns = self._connections.get(case_id, set())
        dead = set()
        payload = json.dumps(message)
        for ws in conns:
            try:
                if ws.client_state == WebSocketState.CONNECTED:
                    await ws.send_text(payload)
            except Exception:
                dead.add(ws)
        for ws in dead:
            conns.discard(ws)

    @property
    def active_cases(self) -> set[str]:
        return set(self._connections.keys())


manager = ConnectionManager()


@router.websocket("/ws/cases/{case_id}")
async def case_websocket(
    ws: WebSocket,
    case_id: UUID,
    token: str = Query(...),  # JWT passed as query param for WS (headers not supported in browser WS)
):
    """
    Subscribe to real-time events for a specific case.

    Events sent to the client:
      {"event": "status_change",  "data": {"status": "analyzing"}}
      {"event": "plugin_started", "data": {"plugin": "windows.malfind"}}
      {"event": "plugin_complete","data": {"plugin": "windows.malfind", "status": "complete", "rows": 12}}
      {"event": "os_detected",    "data": {"os": "windows", "detail": "..."}}
      {"event": "enrichment_complete", "data": {"ioc_count": 45}}
      {"event": "report_ready",   "data": {"verdict": "compromised", "confidence": 88}}
      {"event": "error",          "data": {"message": "...", "stage": "..."}}
      {"event": "ping",           "data": {}}   ← keepalive
    """
    # Accept first — WebSocket frames (including close) require the handshake to complete
    case_id_str = str(case_id)
    await manager.connect(case_id_str, ws)

    user = await verify_ws_token(token)
    if not user:
        await ws.close(code=4001, reason="Unauthorized")
        manager.disconnect(case_id_str, ws)
        return

    # Start Redis subscriber for this case's channel
    redis_client = aioredis.from_url(settings.REDIS_URL)
    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"case:{case_id_str}:events")

    # Send current case state immediately on connect
    await _send_current_state(ws, case_id_str)

    listener_task = asyncio.create_task(_redis_listener(pubsub, ws, case_id_str))
    heartbeat_task = asyncio.create_task(_heartbeat(ws))
    try:
        # Stop as soon as either task exits (disconnect or error)
        done, pending = await asyncio.wait(
            [listener_task, heartbeat_task],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        # Propagate any unexpected exception
        for task in done:
            if not task.cancelled() and task.exception():
                exc = task.exception()
                if not isinstance(exc, WebSocketDisconnect):
                    logger.error("WS task error for case %s: %s", case_id_str, exc)
    except WebSocketDisconnect:
        listener_task.cancel()
        heartbeat_task.cancel()
        logger.info("WS client disconnected: case=%s", case_id_str)
    except Exception as exc:
        listener_task.cancel()
        heartbeat_task.cancel()
        logger.error("WS error for case %s: %s", case_id_str, exc)
    finally:
        manager.disconnect(case_id_str, ws)
        await pubsub.unsubscribe(f"case:{case_id_str}:events")
        await pubsub.close()
        await redis_client.aclose()


async def _redis_listener(pubsub, ws: WebSocket, case_id: str) -> None:
    """Forward Redis Pub/Sub messages to the WebSocket client."""
    async for message in pubsub.listen():
        if message["type"] != "message":
            continue
        if ws.client_state != WebSocketState.CONNECTED:
            break
        try:
            payload = json.loads(message["data"])
            await ws.send_json(payload)
        except Exception as exc:
            logger.warning("WS forward error: %s", exc)
            break


async def _heartbeat(ws: WebSocket) -> None:
    """Send periodic pings to keep the connection alive."""
    while True:
        await asyncio.sleep(30)
        if ws.client_state != WebSocketState.CONNECTED:
            break
        try:
            await ws.send_json({"event": "ping", "data": {}})
        except Exception:
            break


async def _send_current_state(ws: WebSocket, case_id: str) -> None:
    """
    On initial connect, send the current case state so the UI
    doesn't have to poll after reconnecting.
    """
    from sqlalchemy.ext.asyncio import AsyncSession
    from sqlalchemy import select
    from backend.db.session import async_session_factory
    from backend.db.models.models import Case, PluginRun

    try:
        from uuid import UUID as _UUID
        async with async_session_factory() as db:
            case = (await db.execute(select(Case).where(Case.id == _UUID(case_id)))).scalar_one_or_none()
            if not case:
                return

            plugin_runs = (await db.execute(
                select(PluginRun).where(PluginRun.case_id == _UUID(case_id))
            )).scalars().all()

            await ws.send_json({
                "event": "initial_state",
                "data": {
                    "status": case.status,
                    "detected_os": case.detected_os,
                    "plugins": [
                        {
                            "name": r.plugin_name,
                            "domain": r.plugin_domain,
                            "status": r.status,
                            "row_count": r.row_count,
                            "ai_flagged": r.ai_flagged,
                        }
                        for r in plugin_runs
                    ],
                }
            })
    except Exception as exc:
        logger.warning("Could not send initial WS state: %s", exc)


# backend/utils/notifications.py
def publish_case_event(case_id: str, event_type: str, data: dict) -> None:
    """
    Publish a case event to Redis Pub/Sub from a Celery worker.
    Workers use the synchronous Redis client.
    """
    import redis
    import json

    try:
        r = redis.from_url(settings.REDIS_URL)
        payload = json.dumps({"event": event_type, "data": data})
        r.publish(f"case:{case_id}:events", payload)

        # Also persist to case_events table for audit trail
        _persist_event(case_id, event_type, data)
    except Exception as exc:
        # Non-fatal — log and continue
        logger.warning("Failed to publish event %s for case %s: %s", event_type, case_id, exc)
    finally:
        try:
            r.close()
        except Exception:
            pass


def _persist_event(case_id: str, event_type: str, data: dict) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from backend.db.models.models import CaseEvent

    sync_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    engine = create_engine(sync_url)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        event = CaseEvent(case_id=case_id, event_type=event_type, payload=data)
        session.add(event)
        session.commit()
    except Exception:
        session.rollback()
    finally:
        session.close()
        engine.dispose()
