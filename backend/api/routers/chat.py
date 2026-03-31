# backend/api/routers/chat.py
from __future__ import annotations

import logging
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.api.dependencies import get_current_user
from backend.core.agent.chat import stream_chat
from backend.db.models.models import Case, IOC, PluginRun, Report
from backend.db.session import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["chat"])


class ChatMessage(BaseModel):
    role: str    # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    messages: list[ChatMessage]


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

    return StreamingResponse(
        stream_chat(case, report, list(iocs), list(plugin_runs), messages),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering
        },
    )
