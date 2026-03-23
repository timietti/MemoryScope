# backend/api/routers/stats.py
"""
AI resource usage statistics.
Aggregates token usage from the reports table and optionally
fetches live balance/usage data from the Anthropic API.
"""
from __future__ import annotations
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from backend.db.session import get_db
from backend.db.models.models import Report
from backend.api.dependencies import get_current_user
from backend.config import settings

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
    since = datetime.utcnow() - timedelta(days=30)  # naive UTC matches DB columns

    reports = (await db.execute(
        select(Report).where(Report.generated_at >= since)
    )).scalars().all()

    # Build daily buckets
    daily: dict[str, dict] = {}
    by_model: dict[str, dict] = {}

    for report in reports:
        usage = report.token_usage or {}
        input_t  = usage.get("input_tokens", 0) or 0
        output_t = usage.get("output_tokens", 0) or 0
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

    # Best-effort: fetch Anthropic workspace balance
    balance = await _fetch_anthropic_balance()

    return {
        "daily": all_days,
        "totals_30d": {
            "input_tokens":   total_input,
            "output_tokens":  total_output,
            "total_tokens":   total_input + total_output,
            "cost_usd":       round(total_cost, 4),
            "cases_analyzed": total_cases,
            "avg_cost_per_case": round(total_cost / total_cases, 4) if total_cases else 0,
        },
        "by_model": sorted(by_model.values(), key=lambda m: -m["cost_usd"]),
        "balance": balance,
        "pricing_note": "Cost estimates use list pricing; actual billing may differ.",
    }


async def _fetch_anthropic_balance() -> dict | None:
    """
    Attempt to fetch remaining credit balance from the Anthropic API.
    Returns None gracefully if unavailable (API key permissions, network, etc.).
    """
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(
                "https://api.anthropic.com/v1/organizations/balance",
                headers={
                    "x-api-key": settings.ANTHROPIC_API_KEY.get_secret_value(),
                    "anthropic-version": "2023-06-01",
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "available_usd": data.get("available_credit_usd")
                                     or data.get("available_usd")
                                     or data.get("balance"),
                    "source": "anthropic_api",
                }
    except Exception:
        pass
    return None
