# backend/utils/audit.py
"""Helpers for writing to the audit_log table."""
from __future__ import annotations
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.models.models import AuditLog


async def log_audit(
    db: AsyncSession,
    event_type: str,
    *,
    actor_id: str | UUID | None = None,
    target_user_id: str | UUID | None = None,
    payload: dict | None = None,
) -> None:
    """Append one row to audit_log. Commits immediately so the record is never lost."""
    entry = AuditLog(
        event_type=event_type,
        actor_id=UUID(str(actor_id)) if actor_id else None,
        target_user_id=UUID(str(target_user_id)) if target_user_id else None,
        payload=payload or {},
    )
    db.add(entry)
    await db.commit()
