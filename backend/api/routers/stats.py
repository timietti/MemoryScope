# backend/api/routers/stats.py
"""
AI resource usage statistics.
Aggregates token usage from the reports table.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.session import get_db
from backend.db.models.models import Report
from backend.api.dependencies import get_current_user

router = APIRouter(prefix="/stats", tags=["stats"])

# Approximate pricing per million tokens (USD) as of early 2026
_PRICING: dict[str, dict[str, float]] = {
    "claude-opus-4-6":   {"input": 15.0,  "output": 75.0},
    "claude-opus-4-5":   {"input": 15.0,  "output": 75.0},
    "claude-sonnet-4-6": {"input": 3.0,   "output": 15.0},
    "claude-sonnet-4-5": {"input": 3.0,   "output": 15.0},
    "claude-haiku-4-5":  {"input": 0.25,  "output": 1.25},
}
_DEFAULT_PRICING = {"input": 3.0, "output": 15.0}


def _cost(model: str, input_tokens: int, output_tokens: int) -> float:
    p = _PRICING.get(model) or next(
        (v for k, v in _PRICING.items() if k in model), _DEFAULT_PRICING
    )
    return (input_tokens * p["input"] + output_tokens * p["output"]) / 1_000_000


@router.get("/ai")
async def ai_stats(
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    since = datetime.now(timezone.utc) - timedelta(days=30)

    reports = (await db.execute(
        select(Report).where(Report.generated_at >= since)
    )).scalars().all()

    # Build daily buckets
    daily: dict[str, dict] = {}
    by_model: dict[str, dict] = {}

    for report in reports:
        usage = report.token_usage or {}
        # token_usage is stored as {stage: {input_tokens: N, output_tokens: N}, ...}
        # Fall back to flat structure for backwards compatibility
        if "input_tokens" in usage:
            input_t  = int(usage.get("input_tokens", 0) or 0)
            output_t = int(usage.get("output_tokens", 0) or 0)
        else:
            input_t  = sum(int(v.get("input_tokens",  0) or 0) for v in usage.values() if isinstance(v, dict))
            output_t = sum(int(v.get("output_tokens", 0) or 0) for v in usage.values() if isinstance(v, dict))
        model    = report.model_used or "unknown"
        cost     = _cost(model, input_t, output_t)

        day = report.generated_at.strftime("%Y-%m-%d")
        if day not in daily:
            daily[day] = {"date": day, "input_tokens": 0, "output_tokens": 0,
                          "cost_usd": 0.0, "cases": 0}
        daily[day]["input_tokens"]  += input_t
        daily[day]["output_tokens"] += output_t
        daily[day]["cost_usd"]      += cost
        daily[day]["cases"]         += 1

        if model not in by_model:
            by_model[model] = {"model": model, "input_tokens": 0,
                               "output_tokens": 0, "cost_usd": 0.0, "reports": 0}
        by_model[model]["input_tokens"]  += input_t
        by_model[model]["output_tokens"] += output_t
        by_model[model]["cost_usd"]      += cost
        by_model[model]["reports"]       += 1

    # Fill every day in the last 30 days (including days with no reports)
    all_days = []
    for i in range(29, -1, -1):
        day = (datetime.now(timezone.utc) - timedelta(days=i)).strftime("%Y-%m-%d")
        all_days.append(daily.get(day, {"date": day, "input_tokens": 0,
                                        "output_tokens": 0, "cost_usd": 0.0, "cases": 0}))

    total_input  = sum(d["input_tokens"]  for d in all_days)
    total_output = sum(d["output_tokens"] for d in all_days)
    total_cost   = sum(d["cost_usd"]      for d in all_days)
    total_cases  = sum(d["cases"]         for d in all_days)

    return {
        "daily": all_days,
        "totals_30d": {
            "input_tokens":   total_input,
            "output_tokens":  total_output,
            "total_tokens":   total_input + total_output,
            "cost_usd":       round(total_cost, 4),
            "cases_analyzed": total_cases,
            "avg_cost_per_case": round(total_cost / total_cases, 4) if total_cases else 0,
            "report_count":   len(reports),
        },
        "by_model": sorted(by_model.values(), key=lambda m: -m["cost_usd"]),
        "pricing_note": "Cost estimates use list pricing; actual billing may differ.",
    }


