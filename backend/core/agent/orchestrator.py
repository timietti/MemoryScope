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

import asyncio
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

_RETRY_DELAYS = [60, 90, 120, 180]   # seconds between attempts on rate-limit errors


async def _create_with_retry(client: anthropic.Anthropic, **kwargs) -> Any:
    """
    Wrapper around client.messages.create that retries on 429 rate-limit errors
    with exponential back-off. All other errors propagate immediately.
    """
    for attempt, delay in enumerate([0] + _RETRY_DELAYS):
        if delay:
            logger.warning(
                "Anthropic rate limit hit — waiting %ds before retry (attempt %d/%d)",
                delay, attempt, len(_RETRY_DELAYS) + 1,
            )
            await asyncio.sleep(delay)
        try:
            return client.messages.create(**kwargs)
        except anthropic.RateLimitError as exc:
            if attempt >= len(_RETRY_DELAYS):
                logger.error("Anthropic rate limit exceeded after %d retries; giving up", attempt)
                raise
            logger.warning("Rate limit error: %s", exc)
    # unreachable, but keeps type-checkers happy
    raise RuntimeError("Unexpected exit from retry loop")


@dataclass
class AgentContext:
    """Everything the agent needs — passed down through the call chain."""
    case_id: str
    detected_os: str
    plugin_index: dict[str, dict]      # plugin_name → {status, row_count, domain, summary_snippet}
    plugin_outputs: dict[str, Any]     # plugin_name → full parsed output (fetched lazily)
    ioc_enrichments: dict[str, Any]    # value → VT result
    analyst_notes: list[dict] = field(default_factory=list)  # KB articles: [{title, content}]
    token_usage: dict[str, int] = field(default_factory=dict)


async def run_agent(
    case_id: str,
    detected_os: str,
    plugin_outputs: dict[str, Any],
    ioc_enrichments: dict[str, Any],
    analyst_notes: list[dict] | None = None,
) -> FinalReport:
    """
    Entry point: run the full agent pipeline and return a FinalReport.

    Args:
        case_id:          UUID of the case being analysed
        detected_os:      'windows' | 'linux' | 'macos'
        plugin_outputs:   All parsed plugin outputs keyed by plugin name
        ioc_enrichments:  VirusTotal results keyed by IOC value
        analyst_notes:    KB articles attached to this case (title + content)

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
        analyst_notes=analyst_notes or [],
    )

    domain_findings: dict[str, str] = {}
    try:
        # ── Phase 1: Domain sub-agent passes ──────────────────────────────────

        domains_present = {v["domain"] for v in plugin_index.values() if v["status"] == "complete"}
        DOMAIN_PRIORITY = [
            "code_injection", "rootkits", "credentials",
            "network", "persistence", "process_analysis",
            "filesystem", "memory_artifacts", "memory_strings",
        ]
        ordered_domains = [d for d in DOMAIN_PRIORITY if d in domains_present]

        subagents_ran = 0
        for domain in ordered_domains:
            # Skip domains where every plugin has zero flagged rows — nothing to find
            domain_plugins = {
                name: info for name, info in plugin_index.items()
                if info["domain"] == domain and info["status"] == "complete"
            }
            total_flagged = sum(v.get("flagged_count", 0) for v in domain_plugins.values())
            total_rows    = sum(v.get("row_count", 0)    for v in domain_plugins.values())

            if total_flagged == 0 and total_rows > 0:
                summary = (
                    f"No suspicious indicators detected in domain '{domain}'. "
                    f"All {total_rows} rows across {len(domain_plugins)} plugin(s) "
                    f"passed automated filters — no anomalies flagged."
                )
                logger.info("Skipping sub-agent for domain %s (0 flagged rows)", domain)
                domain_findings[domain] = summary
                continue

            logger.info("Running sub-agent for domain: %s (%d flagged rows)", domain, total_flagged)
            domain_findings[domain] = await _run_domain_subagent(client, ctx, domain)
            logger.info("Domain %s analysis complete (%d chars)", domain, len(domain_findings[domain]))
            subagents_ran += 1

        # ── Short-circuit: nothing flagged across any domain ───────────────────
        # All sub-agents were skipped because automated filters found zero
        # suspicious rows. Running the orchestrator with no signal would waste
        # tokens and produce an unreliable inconclusive result. Return a
        # deterministic clean assessment instead.
        if subagents_ran == 0 and domain_findings:
            analysed_domains = ", ".join(d.replace("_", " ") for d in domain_findings)
            plugin_count = len([v for v in plugin_index.values() if v["status"] == "complete"])
            logger.info(
                "All sub-agents skipped for case %s (%d domains, %d plugins, 0 flagged rows) "
                "— returning clean report without orchestrator call",
                case_id, len(domain_findings), plugin_count,
            )
            technical = "\n\n".join(
                f"### {d.replace('_', ' ').title()}\n{summary}"
                for d, summary in domain_findings.items()
            )
            return FinalReport(
                verdict=Verdict.clean,
                confidence=55,
                verdict_reasoning=(
                    f"Automated analysis of {plugin_count} plugin(s) across "
                    f"{len(domain_findings)} domain(s) ({analysed_domains}) produced zero "
                    f"flagged rows. No suspicious indicators were detected in the analyzed data."
                ),
                executive_summary=(
                    f"No malicious activity was detected across the {len(domain_findings)} "
                    f"plugin domain(s) that were analyzed ({analysed_domains}). Every result "
                    f"passed automated filters without raising any anomalies. Confidence is "
                    f"moderate because only a subset of forensic plugins was run — a broader "
                    f"plugin sweep may surface additional evidence."
                ),
                technical_narrative=technical,
                mitre_ttps=[],
                iocs=[],
                timeline=[],
                recommendations=[
                    Recommendation(
                        priority=1,
                        action="Run additional plugin domains for a more thorough assessment",
                        rationale=(
                            f"Only {analysed_domains} were analyzed. Domains such as "
                            f"code_injection, rootkits, credentials, persistence, and "
                            f"filesystem may reveal indicators not visible in the current results."
                        ),
                    ),
                ],
                model_used="none (no-signal short-circuit)",
                agent_version="1.0.0",
                token_usage=ctx.token_usage,
            )

        # ── Phase 2: Orchestrator synthesis ───────────────────────────────────
        logger.info("Running orchestrator synthesis")
        report = await _run_orchestrator_synthesis(client, ctx, domain_findings)
        report.token_usage = ctx.token_usage
        return report

    except Exception as exc:
        logger.exception("Agent pipeline failed for case %s — persisting partial result", case_id)
        partial_narrative = "\n\n".join(
            f"## {d.replace('_', ' ').title()}\n{f}"
            for d, f in domain_findings.items()
        ) if domain_findings else "Pipeline failed before any domain analysis completed."
        return FinalReport(
            verdict=Verdict.inconclusive,
            confidence=0,
            verdict_reasoning=f"AI pipeline failed: {type(exc).__name__}: {exc}",
            executive_summary="Analysis did not complete due to an error. Token usage up to the point of failure has been recorded.",
            technical_narrative=partial_narrative,
            mitre_ttps=[],
            iocs=[],
            timeline=[],
            recommendations=[],
            model_used=settings.PRIMARY_MODEL,
            agent_version="1.0.0",
            token_usage=ctx.token_usage,
        )


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

    # Allow up to 4 tool-call rounds per sub-agent
    for _ in range(4):
        response = await _create_with_retry(
            client,
            model=settings.FAST_MODEL,
            max_tokens=4096,
            system=_domain_system_prompt(domain),
            tools=AGENT_TOOLS,
            messages=messages,
        )

        _track_usage(ctx, f"subagent_{domain}", response.usage, model=settings.FAST_MODEL)

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
        ctx.analyst_notes,
    )

    messages = [{"role": "user", "content": user_prompt}]

    MAX_TOOL_ROUNDS = 3
    for round_idx in range(MAX_TOOL_ROUNDS):
        response = await _create_with_retry(
            client,
            model=settings.PRIMARY_MODEL,
            max_tokens=8192,
            system=ORCHESTRATOR_SYSTEM,
            tools=AGENT_TOOLS,
            messages=messages,
        )

        _track_usage(ctx, "orchestrator", response.usage, model=settings.PRIMARY_MODEL)

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

            # On the last allowed round, force a text response by disabling tools
            if round_idx == MAX_TOOL_ROUNDS - 1:
                logger.warning("Orchestrator hit tool-call limit; forcing final text response")
                # Append an explicit nudge so the model knows to emit the JSON block now
                nudge_messages = messages + [{
                    "role": "user",
                    "content": (
                        "You have reached the maximum number of tool-call rounds. "
                        "You MUST now produce your final threat assessment. "
                        "Do NOT call any more tools. "
                        "Output the complete JSON report wrapped in <report>...</report> tags."
                    ),
                }]
                final_response = await _create_with_retry(
                    client,
                    model=settings.PRIMARY_MODEL,
                    max_tokens=8192,
                    system=ORCHESTRATOR_SYSTEM,
                    # No tools — forces a plain text response
                    messages=nudge_messages,
                )
                _track_usage(ctx, "orchestrator_final", final_response.usage, model=settings.PRIMARY_MODEL)
                text = _extract_text(final_response.content)
                if text:
                    report = _parse_report(text, ctx)
                    # _parse_report returns inconclusive/0 on parse failure; prefer fallback
                    if report.confidence > 0 or report.verdict != Verdict.inconclusive:
                        return report
                    logger.warning(
                        "Forced final response did not contain a parseable <report> block; "
                        "raw response (first 500 chars): %s", text[:500]
                    )
                break
            continue

        # Parse the structured JSON response
        text = _extract_text(response.content)
        return _parse_report(text, ctx)

    # Fallback: build a minimal report directly from the collected domain findings
    logger.error("Orchestrator exceeded iteration limit; building fallback report from domain findings")
    return _fallback_report(domain_findings, ctx)


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


def _fallback_report(domain_findings: dict[str, str], ctx: AgentContext) -> FinalReport:
    """
    Build a minimal inconclusive report from domain findings when the orchestrator
    synthesis loop exhausts its iteration limit without producing a structured report.
    """
    narrative_parts = []
    for domain, finding in domain_findings.items():
        narrative_parts.append(f"## {domain.replace('_', ' ').title()}\n{finding}")
    narrative = "\n\n".join(narrative_parts) if narrative_parts else "No domain findings collected."

    return FinalReport(
        verdict=Verdict.inconclusive,
        confidence=10,
        verdict_reasoning=(
            "AI orchestrator exceeded its iteration limit before producing a structured report. "
            "Domain sub-agent findings are preserved in the technical narrative below."
        ),
        mitre_ttps=[],
        executive_summary=(
            "Analysis partially completed. The orchestrator collected domain findings "
            "but could not synthesise a final structured verdict. "
            "Review the technical narrative for raw sub-agent output."
        ),
        technical_narrative=narrative,
        recommendations=[],
        timeline=[],
        iocs=[],
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

        total = len(rows) if isinstance(rows, list) else 0
        flagged = 0
        snippet = "(empty)"

        if isinstance(rows, list) and rows:
            if spec:
                parser_instance = spec.parser()
                filtered = parser_instance.filter_for_ai(rows, max_rows=3)
                flagged = filtered.get("flagged_rows", 0)
                sample = filtered["rows"][:3]
            else:
                sample = rows[:3]
            snippet = json.dumps(sample, default=str)[:400] + ("..." if len(json.dumps(sample, default=str)) > 400 else "")

        index[plugin_name] = {
            "domain": spec.domain if spec else "unknown",
            "description": spec.description if spec else "",
            "status": "complete" if output else "failed",
            "row_count": total,
            "flagged_count": flagged,
            "snippet": snippet,
        }
    return index


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


def _track_usage(ctx: AgentContext, stage: str, usage: Any, model: str = "") -> None:
    ctx.token_usage[stage] = {
        "model": model,
        "input_tokens": getattr(usage, "input_tokens", 0),
        "output_tokens": getattr(usage, "output_tokens", 0),
    }
