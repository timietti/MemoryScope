# backend/core/agent/orchestrator.py
"""
AI Agent Orchestrator
─────────────────────
Multi-step reasoning pipeline that:
  1. Reviews all available plugin outputs (via index summary)
  2. Dispatches domain sub-agents for deep analysis
  3. Synthesises findings into a structured threat report

Uses Anthropic's tool_use (function calling) pattern so the agent
can pull specific plugin data on demand, keeping context lean.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

import anthropic

from backend.config import settings
from .prompts import (
    ORCHESTRATOR_SYSTEM,
    build_orchestrator_user_prompt,
    build_domain_prompt,
)
from .report_schema import FinalReport, Verdict, MitreTTP, IOCEntry, TimelineEvent, Recommendation
from .tools import AGENT_TOOLS, dispatch_tool_call

logger = logging.getLogger(__name__)


@dataclass
class AgentContext:
    """Everything the agent needs — passed down through the call chain."""
    case_id: str
    detected_os: str
    plugin_index: dict[str, dict]      # plugin_name → {status, row_count, domain, summary_snippet}
    plugin_outputs: dict[str, Any]     # plugin_name → full parsed output (fetched lazily)
    ioc_enrichments: dict[str, Any]    # value → VT result
    token_usage: dict[str, int] = field(default_factory=dict)


async def run_agent(
    case_id: str,
    detected_os: str,
    plugin_outputs: dict[str, Any],
    ioc_enrichments: dict[str, Any],
) -> FinalReport:
    """
    Entry point: run the full agent pipeline and return a FinalReport.

    Args:
        case_id:          UUID of the case being analysed
        detected_os:      'windows' | 'linux' | 'macos'
        plugin_outputs:   All parsed plugin outputs keyed by plugin name
        ioc_enrichments:  VirusTotal results keyed by IOC value

    Returns:
        FinalReport — structured verdict + narrative
    """
    client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY.get_secret_value())

    # Build a lightweight index the orchestrator uses to decide what to dig into
    plugin_index = _build_plugin_index(plugin_outputs)

    ctx = AgentContext(
        case_id=case_id,
        detected_os=detected_os,
        plugin_index=plugin_index,
        plugin_outputs=plugin_outputs,
        ioc_enrichments=ioc_enrichments,
    )

    # ── Phase 1: Domain sub-agent passes ──────────────────────────────────────
    domain_findings: dict[str, str] = {}

    domains_present = {v["domain"] for v in plugin_index.values() if v["status"] == "complete"}
    DOMAIN_PRIORITY = [
        "code_injection", "rootkits", "credentials",
        "network", "persistence", "process_analysis",
        "filesystem", "memory_artifacts", "memory_strings",
    ]
    ordered_domains = [d for d in DOMAIN_PRIORITY if d in domains_present]

    for domain in ordered_domains:
        logger.info("Running sub-agent for domain: %s", domain)
        domain_findings[domain] = await _run_domain_subagent(client, ctx, domain)
        logger.info("Domain %s analysis complete (%d chars)", domain, len(domain_findings[domain]))

    # ── Phase 2: Orchestrator synthesis ───────────────────────────────────────
    logger.info("Running orchestrator synthesis")
    report = await _run_orchestrator_synthesis(client, ctx, domain_findings)

    report.token_usage = ctx.token_usage
    return report


async def _run_domain_subagent(
    client: anthropic.Anthropic,
    ctx: AgentContext,
    domain: str,
) -> str:
    """
    Run a focused sub-agent for one forensic domain.
    Uses tool calls to fetch specific plugin data.

    Returns a plain-text analysis summary for this domain.
    """
    # Collect the plugins in this domain that completed successfully
    domain_plugins = {
        name: info for name, info in ctx.plugin_index.items()
        if info["domain"] == domain and info["status"] == "complete"
    }

    if not domain_plugins:
        return f"No plugin data available for domain '{domain}'."

    messages = [
        {
            "role": "user",
            "content": build_domain_prompt(domain, domain_plugins, ctx.detected_os),
        }
    ]

    # Allow up to 8 tool-call rounds per sub-agent
    for _ in range(8):
        response = client.messages.create(
            model=settings.FAST_MODEL,
            max_tokens=4096,
            system=_domain_system_prompt(domain),
            tools=AGENT_TOOLS,
            messages=messages,
        )

        _track_usage(ctx, f"subagent_{domain}", response.usage)

        if response.stop_reason == "end_turn":
            # Extract text content as the domain finding
            return _extract_text(response.content)

        if response.stop_reason == "tool_use":
            # Execute tool calls and append results
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = await dispatch_tool_call(block.name, block.input, ctx)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str),
                    })

            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
        else:
            # max_tokens or other stop reason — return what we have
            return _extract_text(response.content) or f"Sub-agent stopped: {response.stop_reason}"

    return "Sub-agent reached maximum iterations."


async def _run_orchestrator_synthesis(
    client: anthropic.Anthropic,
    ctx: AgentContext,
    domain_findings: dict[str, str],
) -> FinalReport:
    """
    Final pass: synthesise all domain findings into the structured report.
    The orchestrator uses tool calls to verify specific claims if needed.
    """
    user_prompt = build_orchestrator_user_prompt(
        ctx.plugin_index,
        domain_findings,
        ctx.ioc_enrichments,
        ctx.detected_os,
    )

    messages = [{"role": "user", "content": user_prompt}]

    for _ in range(5):
        response = client.messages.create(
            model=settings.PRIMARY_MODEL,
            max_tokens=8192,
            system=ORCHESTRATOR_SYSTEM,
            tools=AGENT_TOOLS,
            messages=messages,
        )

        _track_usage(ctx, "orchestrator", response.usage)

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    result = await dispatch_tool_call(block.name, block.input, ctx)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": json.dumps(result, default=str),
                    })
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})
            continue

        # Parse the structured JSON response
        text = _extract_text(response.content)
        return _parse_report(text, ctx)

    raise RuntimeError("Orchestrator failed to produce a report within iteration limit")


def _parse_report(text: str, ctx: AgentContext) -> FinalReport:
    """Extract the JSON report block from the model's response."""
    import re
    # Model is instructed to wrap report JSON in <report>...</report>
    match = re.search(r"<report>(.*?)</report>", text, re.DOTALL)
    if match:
        data = json.loads(match.group(1))
    else:
        # Fallback: try parsing entire text as JSON
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.error("Could not parse report JSON from orchestrator response")
            # Return a minimal inconclusive report rather than crashing
            return FinalReport(
                verdict=Verdict.inconclusive,
                confidence=0,
                verdict_reasoning="AI agent failed to produce a parseable report.",
                mitre_ttps=[],
                executive_summary="Analysis incomplete — report parsing failed.",
                technical_narrative=text,
                recommendations=[],
                timeline=[],
                iocs=[],
                model_used=settings.PRIMARY_MODEL,
                agent_version="1.0.0",
            )

    return FinalReport(
        verdict=Verdict(data["verdict"]),
        confidence=data["confidence"],
        verdict_reasoning=data["verdict_reasoning"],
        mitre_ttps=[MitreTTP(**t) for t in data.get("mitre_ttps", [])],
        executive_summary=data["executive_summary"],
        technical_narrative=data["technical_narrative"],
        recommendations=[Recommendation(**r) for r in data.get("recommendations", [])],
        timeline=[TimelineEvent(**e) for e in data.get("timeline", [])],
        iocs=[IOCEntry(**i) for i in data.get("iocs", [])],
        model_used=settings.PRIMARY_MODEL,
        agent_version="1.0.0",
    )


def _build_plugin_index(plugin_outputs: dict[str, Any]) -> dict[str, dict]:
    """
    Build a lightweight summary index so the orchestrator can see what ran
    without loading full output into its context window.
    """
    from backend.core.plugins.registry import get_plugin
    index = {}
    for plugin_name, output in plugin_outputs.items():
        spec = get_plugin(plugin_name)
        rows = output if isinstance(output, list) else output.get("rows", []) if isinstance(output, dict) else []
        snippet = _make_snippet(rows)
        index[plugin_name] = {
            "domain": spec.domain if spec else "unknown",
            "description": spec.description if spec else "",
            "status": "complete" if output else "failed",
            "row_count": len(rows) if isinstance(rows, list) else 0,
            "snippet": snippet,
        }
    return index


def _make_snippet(rows: list) -> str:
    """Return a short representative snippet (first 3 rows as JSON)."""
    if not rows:
        return "(empty)"
    sample = rows[:3]
    text = json.dumps(sample, default=str)
    return text[:400] + ("..." if len(text) > 400 else "")


def _domain_system_prompt(domain: str) -> str:
    domain_focus = {
        "code_injection":   "Focus on injected shellcode, PE headers in RWX regions, hollowed processes.",
        "rootkits":         "Focus on hidden kernel modules, SSDT hooks, DKOM artefacts.",
        "credentials":      "Focus on LSASS tampering, hash extraction, LSA secrets.",
        "network":          "Focus on C2 beacons, unusual ports, connections to known-bad IPs.",
        "persistence":      "Focus on Run keys, services, scheduled tasks, bash history.",
        "process_analysis": "Focus on orphaned processes, unusual parent chains, obfuscated cmdlines.",
        "filesystem":       "Focus on suspicious file objects, dropped malware, temp paths.",
        "memory_artifacts": "Focus on mutex names, handles that fingerprint known malware families.",
        "memory_strings":   "Focus on embedded URLs, IPs, encoded payloads, family strings.",
    }
    focus = domain_focus.get(domain, "Analyse the provided data for signs of compromise.")
    return (
        f"You are a senior digital forensics analyst specialising in memory forensics. "
        f"Domain focus: {domain.replace('_', ' ').title()}. {focus} "
        f"Use the available tools to fetch plugin data as needed. "
        f"Be specific and evidence-based. Cite process names, PIDs, addresses, and plugin names. "
        f"Flag false positives explicitly when the evidence is ambiguous."
    )


def _extract_text(content: list) -> str:
    return "\n".join(block.text for block in content if hasattr(block, "text"))


def _track_usage(ctx: AgentContext, stage: str, usage: Any) -> None:
    ctx.token_usage[stage] = {
        "input_tokens": getattr(usage, "input_tokens", 0),
        "output_tokens": getattr(usage, "output_tokens", 0),
    }
