# backend/core/agent/report_schema.py
"""
Pydantic models for the AI agent's structured output.
These are internal models used by the agent pipeline,
distinct from the API-facing schemas in backend/schemas/.
"""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class Verdict(str, Enum):
    clean        = "clean"
    suspicious   = "suspicious"
    compromised  = "compromised"
    inconclusive = "inconclusive"


class Severity(str, Enum):
    low      = "low"
    medium   = "medium"
    high     = "high"
    critical = "critical"


class MitreTTP(BaseModel):
    tactic:         str   # e.g. "TA0002"
    tactic_name:    str   # e.g. "Execution"
    technique:      str   # e.g. "T1059.001"
    technique_name: str   # e.g. "PowerShell"
    evidence:       str
    severity:       Severity


class IOCEntry(BaseModel):
    ioc_type:     str            # matches db IOCType enum values
    value:        str
    severity:     Severity
    description:  str
    source_plugin: str | None = None
    source_pid:    int | None = None


class TimelineEvent(BaseModel):
    timestamp_estimate: str
    event:              str
    evidence_plugin:    str


class Recommendation(BaseModel):
    priority:   int = Field(ge=1, le=10)
    action:     str
    rationale:  str


class FinalReport(BaseModel):
    verdict:             Verdict
    confidence:          int = Field(ge=0, le=100)
    verdict_reasoning:   str
    executive_summary:   str
    technical_narrative: str
    mitre_ttps:          list[MitreTTP]    = []
    iocs:                list[IOCEntry]    = []
    timeline:            list[TimelineEvent] = []
    recommendations:     list[Recommendation] = []
    model_used:          str
    agent_version:       str
    token_usage:         dict[str, Any] | None = None
