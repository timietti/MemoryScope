# backend/mcp_server.py
"""
MemoryScope MCP Server
──────────────────────
Exposes cases, plugin outputs, IOCs, and reports as MCP tools and resources
so that Claude Desktop (or any MCP-compatible client) can query the platform
without going through the web UI.

All data is READ-ONLY. This server never writes to the database.

Run (stdio transport, for Claude Desktop):
    PYTHONPATH=. backend/.venv/bin/python -m mcp.cli run backend/mcp_server.py

Or via the MCP CLI:
    PYTHONPATH=. mcp run backend/mcp_server.py

Claude Desktop config (~/.config/claude/claude_desktop_config.json):
    {
      "mcpServers": {
        "memoryscope": {
          "command": "/path/to/backend/.venv/bin/python",
          "args": ["-m", "mcp.cli", "run", "/path/to/backend/mcp_server.py"],
          "env": {
            "PYTHONPATH": "/path/to/repo",
            "DATABASE_URL": "postgresql+asyncpg://memoryscope:yourpass@localhost:5432/memoryscope",
            "SECRET_KEY": "your-secret-key",
            "S3_ACCESS_KEY": "minioadmin",
            "S3_SECRET_KEY": "minioadmin"
          }
        }
      }
    }
"""
from __future__ import annotations

import json
import uuid
from contextlib import asynccontextmanager
from typing import Any

from mcp.server.fastmcp import FastMCP
from sqlalchemy import select, and_
from sqlalchemy.orm import selectinload

from backend.db.session import async_session_factory
from backend.db.models.models import (
    Case, CaseStatus, PluginRun, PluginStatus,
    Report, IOC, KBArticle, CaseKBArticle,
)

mcp = FastMCP(
    "MemoryScope",
    instructions=(
        "You have access to a MemoryScope digital forensics platform. "
        "Cases contain memory dump analyses run through Volatility3. "
        "Use list_cases to find cases, then query plugin outputs or reports. "
        "Plugin outputs are only available for plugins that have already been run "
        "via the web UI. Use list_plugins to see what is available for a given case."
    ),
)

# Disable DNS rebinding protection so the MCP SSE endpoint works behind a
# reverse proxy (nginx) with a non-localhost hostname.  nginx is the security
# perimeter; rejecting non-localhost Host headers here adds no real protection.
try:
    from mcp.server.transport_security import TransportSecuritySettings
    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
except Exception:
    pass  # older SDK version without this setting — proceed as-is


# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt_case(c: Case) -> dict:
    return {
        "id": str(c.id),
        "short_id": c.short_id,
        "name": c.name,
        "status": c.status.value if hasattr(c.status, "value") else str(c.status),
        "detected_os": c.detected_os.value if c.detected_os and hasattr(c.detected_os, "value") else str(c.detected_os or "unknown"),
        "detected_os_detail": c.detected_os_detail,
        "priority": c.priority,
        "tags": c.tags or [],
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "completed_at": c.completed_at.isoformat() if c.completed_at else None,
        "original_filename": c.original_filename,
        "file_size_bytes": c.file_size_bytes,
    }


def _get_rows(parsed_output: Any) -> list:
    if isinstance(parsed_output, list):
        return parsed_output
    if isinstance(parsed_output, dict):
        return parsed_output.get("rows", [])
    return []


def _parse_case_id(case_id: str) -> uuid.UUID:
    try:
        return uuid.UUID(case_id)
    except ValueError:
        raise ValueError(f"Invalid case ID format: {case_id!r}. Expected a UUID.")


# ── Resources ─────────────────────────────────────────────────────────────────

@mcp.resource("cases://list")
async def list_cases_resource() -> str:
    """All active cases with status, OS, priority, and creation date."""
    async with async_session_factory() as db:
        result = await db.execute(
            select(Case)
            .where(Case.deleted_at.is_(None))
            .order_by(Case.created_at.desc())
            .limit(200)
        )
        cases = result.scalars().all()
        return json.dumps([_fmt_case(c) for c in cases], indent=2)


@mcp.resource("cases://{case_id}")
async def get_case_resource(case_id: str) -> str:
    """Full details for a single case including description and error message."""
    uid = _parse_case_id(case_id)
    async with async_session_factory() as db:
        case = await db.get(Case, uid)
        if not case or case.deleted_at:
            return json.dumps({"error": f"Case {case_id} not found"})
        data = _fmt_case(case)
        data["description"] = case.description
        data["error_message"] = case.error_message
        data["sha256"] = case.sha256
        data["volatility_profile"] = case.volatility_profile
        return json.dumps(data, indent=2)


@mcp.resource("cases://{case_id}/report")
async def get_case_report_resource(case_id: str) -> str:
    """The most recent AI-generated report for a case."""
    uid = _parse_case_id(case_id)
    async with async_session_factory() as db:
        result = await db.execute(
            select(Report)
            .where(Report.case_id == uid)
            .where(Report.superseded_at.is_(None))
            .order_by(Report.generated_at.desc())
            .limit(1)
        )
        report = result.scalar_one_or_none()
        if not report:
            return json.dumps({"error": "No report found for this case. AI analysis may not have run yet."})
        return json.dumps({
            "verdict": report.verdict.value if hasattr(report.verdict, "value") else str(report.verdict),
            "confidence": report.confidence,
            "verdict_reasoning": report.verdict_reasoning,
            "executive_summary": report.executive_summary,
            "technical_narrative": report.technical_narrative,
            "mitre_ttps": report.mitre_ttps,
            "recommendations": report.recommendations,
            "timeline": report.timeline,
            "model_used": report.model_used,
            "generated_at": report.generated_at.isoformat(),
        }, indent=2)


@mcp.resource("cases://{case_id}/iocs")
async def get_case_iocs_resource(case_id: str) -> str:
    """All IOCs extracted from a case, with VirusTotal enrichment data where available."""
    uid = _parse_case_id(case_id)
    async with async_session_factory() as db:
        result = await db.execute(
            select(IOC)
            .where(IOC.case_id == uid)
            .order_by(IOC.severity.desc(), IOC.ioc_type)
        )
        iocs = result.scalars().all()
        if not iocs:
            return json.dumps({"iocs": [], "note": "No IOCs found. Enrichment may not have run yet."})
        return json.dumps({
            "total": len(iocs),
            "iocs": [
                {
                    "type": ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type),
                    "value": ioc.value,
                    "severity": ioc.severity.value if hasattr(ioc.severity, "value") else str(ioc.severity),
                    "description": ioc.description,
                    "source_plugin": ioc.source_plugin,
                    "source_pid": ioc.source_pid,
                    "vt_positives": ioc.vt_positives,
                    "vt_total": ioc.vt_total,
                    "vt_permalink": ioc.vt_permalink,
                    "threat_names": ioc.threat_names,
                    "ai_context": ioc.ai_context,
                }
                for ioc in iocs
            ],
        }, indent=2)


# ── Tools ─────────────────────────────────────────────────────────────────────

@mcp.tool()
async def list_plugins(case_id: str) -> str:
    """
    List all Volatility3 plugins that have run for a case, with their status and row counts.
    Call this first to know which plugin names are valid before calling get_plugin_output.

    Args:
        case_id: UUID of the case
    """
    uid = _parse_case_id(case_id)
    async with async_session_factory() as db:
        result = await db.execute(
            select(PluginRun)
            .where(PluginRun.case_id == uid)
            .order_by(PluginRun.plugin_domain, PluginRun.plugin_name)
        )
        runs = result.scalars().all()
        if not runs:
            return json.dumps({"error": "No plugin runs found for this case."})
        return json.dumps({
            "case_id": case_id,
            "plugins": [
                {
                    "name": r.plugin_name,
                    "domain": r.plugin_domain,
                    "status": r.status.value if hasattr(r.status, "value") else str(r.status),
                    "row_count": r.row_count,
                    "ai_flagged": r.ai_flagged,
                    "ai_summary": r.ai_summary,
                    "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                    "error_message": r.error_message,
                }
                for r in runs
            ],
        }, indent=2)


@mcp.tool()
async def get_plugin_output(
    case_id: str,
    plugin_name: str,
    limit: int = 100,
    filter_field: str = "",
    filter_value: str = "",
) -> str:
    """
    Fetch the parsed output of a Volatility3 plugin for a specific case.
    Use list_plugins first to confirm the plugin has run and has output.

    Args:
        case_id: UUID of the case
        plugin_name: Exact plugin name, e.g. 'windows.malfind' or 'linux.pslist'
        limit: Max records to return (default 100, max 500)
        filter_field: Optional field name to filter on (e.g. 'PID', 'ImageFileName')
        filter_value: Value to match against filter_field (substring, case-insensitive)
    """
    from backend.core.plugins.registry import get_plugin

    uid = _parse_case_id(case_id)
    limit = min(limit, 500)

    async with async_session_factory() as db:
        result = await db.execute(
            select(PluginRun).where(
                and_(
                    PluginRun.case_id == uid,
                    PluginRun.plugin_name == plugin_name,
                )
            )
        )
        run = result.scalar_one_or_none()

        if not run:
            return json.dumps({"error": f"Plugin '{plugin_name}' not found for case {case_id}. Use list_plugins to see available plugins."})
        if run.status != PluginStatus.complete:
            return json.dumps({"error": f"Plugin '{plugin_name}' status is '{run.status.value}', not complete.", "error_message": run.error_message})
        if not run.parsed_output:
            # Fall back to raw output if no parsed data
            return json.dumps({"plugin": plugin_name, "raw_output": (run.raw_output or "")[:5000]})

    rows = _get_rows(run.parsed_output)

    # Apply explicit field filter
    if filter_field and filter_value:
        fv = filter_value.lower()
        rows = [r for r in rows if fv in str(r.get(filter_field, "")).lower()]
        return json.dumps({
            "plugin": plugin_name,
            "total_rows": len(rows),
            "filter_note": f"Filtered by {filter_field}={filter_value!r}",
            "rows": rows[:limit],
        }, indent=2)

    # Use the parser's filter_for_ai() for smart noise reduction when available
    spec = get_plugin(plugin_name)
    if spec:
        parser_instance = spec.parser()
        filtered = parser_instance.filter_for_ai(rows, max_rows=limit)
        return json.dumps({"plugin": plugin_name, **filtered}, indent=2)

    return json.dumps({
        "plugin": plugin_name,
        "total_rows": len(rows),
        "rows": rows[:limit],
    }, indent=2)


@mcp.tool()
async def get_process_details(case_id: str, pid: int = 0, process_name: str = "") -> str:
    """
    Get a cross-plugin view of a single process: combines pslist, cmdline, dlllist,
    handles, and netstat data for one PID. Provide either pid or process_name.

    Args:
        case_id: UUID of the case
        pid: Process ID to examine (0 = not specified)
        process_name: Process name as alternative identifier (e.g. 'svchost.exe')
    """
    if not pid and not process_name:
        return json.dumps({"error": "Provide at least one of: pid, process_name"})

    uid = _parse_case_id(case_id)
    proc_name_lower = process_name.lower()

    async with async_session_factory() as db:
        # Load all relevant plugin runs in one query
        result = await db.execute(
            select(PluginRun).where(
                and_(
                    PluginRun.case_id == uid,
                    PluginRun.status == PluginStatus.complete,
                    PluginRun.plugin_name.in_([
                        "windows.pslist", "linux.pslist", "mac.pslist",
                        "windows.cmdline", "windows.dlllist",
                        "windows.handles", "windows.netstat", "windows.netscan",
                        "linux.netstat", "mac.netstat",
                    ]),
                )
            )
        )
        runs = {r.plugin_name: r for r in result.scalars().all()}

    output: dict[str, Any] = {}
    resolved_pid: int | None = pid or None

    # Find the process in pslist variants
    for plugin_name in ("windows.pslist", "linux.pslist", "mac.pslist"):
        run = runs.get(plugin_name)
        if not run or not run.parsed_output:
            continue
        rows = _get_rows(run.parsed_output)
        matches = [
            r for r in rows
            if (resolved_pid and r.get("PID") == resolved_pid)
            or (proc_name_lower and proc_name_lower in str(r.get("ImageFileName", r.get("COMM", ""))).lower())
        ]
        if matches:
            output["process_info"] = matches[0]
            if not resolved_pid:
                resolved_pid = matches[0].get("PID")
            break

    if not output:
        return json.dumps({"error": f"Process not found (pid={pid or 'n/a'}, name={process_name or 'n/a'})"})

    # Fetch supporting plugin data by PID
    if resolved_pid:
        for plugin_name, pid_field in [
            ("windows.cmdline", "PID"),
            ("windows.dlllist", "PID"),
            ("windows.handles", "PID"),
        ]:
            run = runs.get(plugin_name)
            if run and run.parsed_output:
                matches = [r for r in _get_rows(run.parsed_output) if r.get(pid_field) == resolved_pid]
                if matches:
                    output[plugin_name] = matches[:20]

        for plugin_name in ("windows.netstat", "windows.netscan", "linux.netstat", "mac.netstat"):
            run = runs.get(plugin_name)
            if run and run.parsed_output:
                matches = [
                    r for r in _get_rows(run.parsed_output)
                    if r.get("PID") == resolved_pid
                    or (isinstance(r.get("Owner"), dict) and r["Owner"].get("PID") == resolved_pid)
                ]
                if matches:
                    output["network_connections"] = matches
                    break

    return json.dumps(output, indent=2)


@mcp.tool()
async def list_network_connections(
    case_id: str,
    state: str = "",
    remote_ip: str = "",
    exclude_local: bool = True,
) -> str:
    """
    List all network connections found in a memory dump with optional filtering.
    Reads from netstat/netscan plugin output (must have been run via the web UI).

    Args:
        case_id: UUID of the case
        state: Filter by connection state: ESTABLISHED, LISTENING, CLOSE_WAIT, etc.
        remote_ip: Filter by remote IP substring
        exclude_local: Exclude localhost and RFC-1918 private addresses (default True)
    """
    PRIVATE_PREFIXES = (
        "10.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.2", "172.3", "192.168.", "127.", "::1", "fe80:",
    )

    uid = _parse_case_id(case_id)
    state_upper = state.upper()
    remote_ip_lower = remote_ip.lower()

    async with async_session_factory() as db:
        result = await db.execute(
            select(PluginRun).where(
                and_(
                    PluginRun.case_id == uid,
                    PluginRun.status == PluginStatus.complete,
                    PluginRun.plugin_name.in_([
                        "windows.netstat", "windows.netscan",
                        "linux.netstat", "mac.netstat",
                    ]),
                )
            )
        )
        runs = result.scalars().all()

    connections = []
    for run in runs:
        if not run.parsed_output:
            continue
        for row in _get_rows(run.parsed_output):
            remote = str(row.get("ForeignAddr", row.get("RemoteAddr", ""))).lower()
            if exclude_local and any(remote.startswith(p) for p in PRIVATE_PREFIXES):
                continue
            if state_upper and state_upper not in str(row.get("State", "")).upper():
                continue
            if remote_ip_lower and remote_ip_lower not in remote:
                continue
            connections.append({**row, "_source_plugin": run.plugin_name})

    return json.dumps({
        "total": len(connections),
        "filters_applied": {
            "state": state or None,
            "remote_ip": remote_ip or None,
            "exclude_local": exclude_local,
        },
        "connections": connections,
    }, indent=2)


@mcp.tool()
async def search_iocs(value: str) -> str:
    """
    Search all cases for an IOC by value (IP, domain, hash, file path, etc.).
    Returns matching IOCs with their case context and VirusTotal data.

    Args:
        value: The IOC value to search for (substring match, case-insensitive)
    """
    value_lower = value.lower()
    async with async_session_factory() as db:
        result = await db.execute(
            select(IOC).where(IOC.value.ilike(f"%{value}%")).limit(50)
        )
        iocs = result.scalars().all()

    if not iocs:
        return json.dumps({"matches": [], "note": f"No IOCs found matching '{value}'"})

    return json.dumps({
        "query": value,
        "total": len(iocs),
        "matches": [
            {
                "case_id": str(ioc.case_id),
                "type": ioc.ioc_type.value if hasattr(ioc.ioc_type, "value") else str(ioc.ioc_type),
                "value": ioc.value,
                "severity": ioc.severity.value if hasattr(ioc.severity, "value") else str(ioc.severity),
                "description": ioc.description,
                "source_plugin": ioc.source_plugin,
                "vt_positives": ioc.vt_positives,
                "vt_total": ioc.vt_total,
                "threat_names": ioc.threat_names,
                "ai_context": ioc.ai_context,
            }
            for ioc in iocs
        ],
    }, indent=2)


@mcp.tool()
async def get_case_kb_articles(case_id: str) -> str:
    """
    Retrieve all KB articles attached to a case, including the auto-created
    Description note. These are the analyst notes passed to the AI pipeline.

    Args:
        case_id: UUID of the case
    """
    uid = _parse_case_id(case_id)
    async with async_session_factory() as db:
        result = await db.execute(
            select(KBArticle)
            .join(CaseKBArticle, CaseKBArticle.article_id == KBArticle.id)
            .where(CaseKBArticle.case_id == uid)
            .order_by(KBArticle.created_at)
        )
        articles = result.scalars().all()

    if not articles:
        return json.dumps({"articles": [], "note": "No KB articles attached to this case."})

    return json.dumps({
        "total": len(articles),
        "articles": [
            {
                "id": str(a.id),
                "title": a.title,
                "content": a.content,
                "tags": a.tags or [],
                "created_at": a.created_at.isoformat(),
            }
            for a in articles
        ],
    }, indent=2)


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    mcp.run()
