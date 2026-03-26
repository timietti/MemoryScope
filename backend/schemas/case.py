# backend/schemas/case.py
from __future__ import annotations
from datetime import datetime
from typing import Any
from uuid import UUID
from pydantic import BaseModel, ConfigDict, field_validator


# ── Case ──────────────────────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    name: str
    description: str | None = None
    priority: int = 2
    os_hint: str | None = None
    tags: list[str] = []


class CaseResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    short_id: str
    name: str
    description: str | None
    priority: int
    original_filename: str
    file_size_bytes: int
    sha256: str
    detected_os: str
    detected_os_detail: str | None
    volatility_profile: str | None
    os_hint: str | None
    status: str
    error_message: str | None
    tags: list[str]
    created_at: datetime
    queued_at: datetime | None
    detection_started_at: datetime | None
    analysis_started_at: datetime | None
    ai_started_at: datetime | None
    vt_enriched_at: datetime | None
    completed_at: datetime | None
    submitted_by: UUID

    @field_validator('detected_os', 'status', mode='before')
    @classmethod
    def coerce_to_str(cls, v) -> str:
        if v is None:
            return v
        return v.value if hasattr(v, 'value') else str(v)

    @field_validator('os_hint', mode='before')
    @classmethod
    def coerce_optional_to_str(cls, v) -> str | None:
        return str(v) if v is not None else None


class CaseListResponse(BaseModel):
    items: list[CaseResponse]
    total: int
    page: int
    page_size: int


# ── Plugin Run ─────────────────────────────────────────────────────────────────

class PluginRunListItem(BaseModel):
    """Lightweight schema for the plugin list — omits large output fields."""
    model_config = ConfigDict(from_attributes=True)

    @field_validator('status', mode='before')
    @classmethod
    def coerce_status(cls, v) -> str:
        if v is None:
            return v
        return v.value if hasattr(v, 'value') else str(v)

    id: UUID
    case_id: UUID
    plugin_name: str
    plugin_domain: str
    plugin_version: str | None
    status: str
    exit_code: int | None
    started_at: datetime | None
    completed_at: datetime | None
    duration_ms: int | None = None
    row_count: int | None
    error_message: str | None
    ai_flagged: bool
    ai_summary: str | None
    created_at: datetime


class PluginRunResponse(PluginRunListItem):
    """Full schema including output — used for individual plugin detail."""
    parsed_output: Any | None
    raw_output: str | None
    stderr_output: str | None


# ── Report ─────────────────────────────────────────────────────────────────────

class ReportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    case_id: UUID
    verdict: str
    confidence: int
    verdict_reasoning: str
    executive_summary: str
    technical_narrative: str
    mitre_ttps: list[Any]
    timeline: list[Any]
    recommendations: list[Any]
    model_used: str
    agent_version: str
    token_usage: Any | None
    generated_at: datetime
