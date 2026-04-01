# backend/api/routers/chat.py
from __future__ import annotations

import logging
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select, delete as sql_delete
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user
from backend.core.agent.chat import stream_chat
from backend.db.models.models import Case, IOC, PluginRun, Report
from backend.db.models.models import ChatMessage as ChatMessageORM, ChatTokenLog
from backend.db.session import get_db, async_session_factory

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["chat"])


class ConversationMessage(BaseModel):
    role: str    # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: list[ConversationMessage]


class ChatHistoryItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    role: str
    content: str
    created_at: datetime


class AppendMessageRequest(BaseModel):
    role: str
    content: str


# ── Streaming chat ─────────────────────────────────────────────────────────────

@router.post("/{case_id}/chat")
async def case_chat(
    case_id: UUID,
    body: ChatRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
) -> StreamingResponse:
    """
    Stream a chat response for a specific case.

    Accepts the full conversation history (messages) and returns an
    SSE stream. The case report and plugin context are included as
    cached system-prompt blocks to minimise per-message token cost.
    """
    case = (
        await db.execute(select(Case).where(Case.id == case_id))
    ).scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    report = (
        await db.execute(
            select(Report)
            .where(Report.case_id == case.id)
            .order_by(Report.updated_at.desc())
            .limit(1)
        )
    ).scalars().first()

    iocs = (
        await db.execute(select(IOC).where(IOC.case_id == case.id))
    ).scalars().all()

    plugin_runs = (
        await db.execute(select(PluginRun).where(PluginRun.case_id == case.id))
    ).scalars().all()

    messages = [{"role": m.role, "content": m.content} for m in body.messages]

    usage: dict = {}

    async def tracked_stream():
        async for chunk in stream_chat(case, report, list(iocs), list(plugin_runs), messages, usage_out=usage):
            yield chunk
        if usage.get("input_tokens") or usage.get("output_tokens"):
            try:
                async with async_session_factory() as log_db:
                    log_db.add(ChatTokenLog(
                        case_id=case_id,
                        input_tokens=usage.get("input_tokens", 0),
                        output_tokens=usage.get("output_tokens", 0),
                        model_used=usage.get("model", ""),
                        created_at=datetime.now(timezone.utc),
                    ))
                    await log_db.commit()
            except Exception:
                logger.exception("Failed to record chat token usage for case %s", case_id)

    return StreamingResponse(
        tracked_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )


# ── Chat history persistence ───────────────────────────────────────────────────

@router.get("/{case_id}/chat/history", response_model=list[ChatHistoryItem])
async def get_chat_history(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    rows = (await db.execute(
        select(ChatMessageORM)
        .where(ChatMessageORM.case_id == case_id)
        .order_by(ChatMessageORM.id)
    )).scalars().all()

    return list(rows)


@router.post("/{case_id}/chat/messages", response_model=ChatHistoryItem, status_code=201)
async def append_chat_message(
    case_id: UUID,
    body: AppendMessageRequest,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    if body.role not in ("user", "assistant"):
        raise HTTPException(status_code=422, detail="role must be 'user' or 'assistant'")

    case = (await db.execute(select(Case).where(Case.id == case_id))).scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    msg = ChatMessageORM(
        case_id=case_id,
        role=body.role,
        content=body.content,
        created_at=datetime.now(timezone.utc),
    )
    db.add(msg)
    await db.flush()
    return msg


@router.delete("/{case_id}/chat/history", status_code=204)
async def clear_chat_history(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user=Depends(get_current_user),
):
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalars().first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    await db.execute(sql_delete(ChatMessageORM).where(ChatMessageORM.case_id == case_id))
