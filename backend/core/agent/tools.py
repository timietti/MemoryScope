# backend/core/agent/tools.py
"""
Tool definitions for the AI agent.
The agent calls these to fetch plugin data on demand,
keeping the main context window lean.
"""
from __future__ import annotations
import json
import logging
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from .orchestrator import AgentContext

logger = logging.getLogger(__name__)

# ── Tool schemas (Anthropic tool_use format) ──────────────────────────────────

AGENT_TOOLS = [
    {
        "name": "get_plugin_output",
        "description": (
            "Fetch the full parsed output of a Volatility3 plugin for this case. "
            "Use this when you need to examine specific plugin data in detail. "
            "Returns a list of records (dicts) or a raw-text fallback."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "plugin_name": {
                    "type": "string",
                    "description": "Exact plugin name, e.g. 'windows.malfind' or 'linux.pslist'"
                },
                "limit": {
                    "type": "integer",
                    "description": "Max records to return (default 200, max 1000)",
                    "default": 200
                },
                "filter_field": {
                    "type": "string",
                    "description": "Optional field name to filter on (e.g. 'PID', 'ImageFileName')"
                },
                "filter_value": {
                    "type": "string",
                    "description": "Value to match against filter_field (substring match)"
                }
            },
            "required": ["plugin_name"]
        }
    },
    {
        "name": "get_process_details",
        "description": (
            "Get a cross-plugin view of a single process: "
            "combines pslist, cmdline, dlllist, handles, and netstat data for one PID."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "description": "Process ID to examine"},
                "process_name": {"type": "string", "description": "Process name as alternative to PID"}
            }
        }
    },
    {
        "name": "search_strings",
        "description": (
            "Search for a pattern across all memory string data. "
            "Useful for finding embedded URLs, IPs, registry paths, or malware family strings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "pattern": {
                    "type": "string",
                    "description": "String to search for (case-insensitive substring)"
                },
                "limit": {"type": "integer", "default": 50}
            },
            "required": ["pattern"]
        }
    },
    {
        "name": "lookup_ioc",
        "description": (
            "Look up an IOC (IP address, domain, file hash) in VirusTotal enrichment data. "
            "Returns detection counts, malware family names, and permalink."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "The IOC value: IP, domain, MD5, SHA1, or SHA256 hash"
                }
            },
            "required": ["value"]
        }
    },
    {
        "name": "list_network_connections",
        "description": "List all network connections found in this dump with optional filtering.",
        "input_schema": {
            "type": "object",
            "properties": {
                "state": {
                    "type": "string",
                    "description": "Filter by state: ESTABLISHED, LISTENING, CLOSE_WAIT, etc."
                },
                "remote_ip": {"type": "string", "description": "Filter by remote IP substring"},
                "exclude_local": {
                    "type": "boolean",
                    "description": "Exclude localhost/private connections",
                    "default": True
                }
            }
        }
    },
    {
        "name": "get_registry_key",
        "description": "Retrieve registry key data from the windows.registry.printkey plugin output.",
        "input_schema": {
            "type": "object",
            "properties": {
                "key_path": {
                    "type": "string",
                    "description": "Registry key path to look up (partial match supported)"
                }
            },
            "required": ["key_path"]
        }
    },
]


# ── Tool dispatcher ────────────────────────────────────────────────────────────

async def dispatch_tool_call(
    tool_name: str,
    tool_input: dict,
    ctx: "AgentContext",
) -> Any:
    """Route a tool call to the appropriate handler."""
    handlers = {
        "get_plugin_output":       _tool_get_plugin_output,
        "get_process_details":     _tool_get_process_details,
        "search_strings":          _tool_search_strings,
        "lookup_ioc":              _tool_lookup_ioc,
        "list_network_connections": _tool_list_network_connections,
        "get_registry_key":        _tool_get_registry_key,
    }
    handler = handlers.get(tool_name)
    if not handler:
        return {"error": f"Unknown tool: {tool_name}"}
    try:
        return await handler(tool_input, ctx)
    except Exception as exc:
        logger.exception("Tool %s failed", tool_name)
        return {"error": str(exc)}


async def _tool_get_plugin_output(inp: dict, ctx: "AgentContext") -> Any:
    plugin_name = inp["plugin_name"]
    limit = min(inp.get("limit", 200), 1000)
    filter_field = inp.get("filter_field")
    filter_value = inp.get("filter_value", "").lower()

    output = ctx.plugin_outputs.get(plugin_name)
    if output is None:
        return {"error": f"Plugin '{plugin_name}' not found or did not run"}

    rows = output if isinstance(output, list) else output.get("rows", output)
    if not isinstance(rows, list):
        return output  # Raw dict fallback

    if filter_field and filter_value:
        rows = [
            r for r in rows
            if filter_value in str(r.get(filter_field, "")).lower()
        ]

    return {"plugin": plugin_name, "total_rows": len(rows), "rows": rows[:limit]}


async def _tool_get_process_details(inp: dict, ctx: "AgentContext") -> dict:
    pid = inp.get("pid")
    proc_name = inp.get("process_name", "").lower()

    result: dict = {}

    for plugin in ["windows.pslist", "linux.pslist", "mac.pslist"]:
        rows = _get_rows(ctx, plugin)
        if not rows:
            continue
        matches = [
            r for r in rows
            if (pid and r.get("PID") == pid) or
               (proc_name and proc_name in str(r.get("ImageFileName", r.get("COMM", ""))).lower())
        ]
        if matches:
            result["process_info"] = matches[0]
            if not pid:
                pid = matches[0].get("PID")
            break

    if pid:
        for plugin, pid_field in [
            ("windows.cmdline", "PID"),
            ("windows.dlllist", "PID"),
            ("windows.handles", "PID"),
        ]:
            rows = _get_rows(ctx, plugin)
            matches = [r for r in rows if r.get(pid_field) == pid]
            if matches:
                result[plugin] = matches[:20]

        # Network connections associated with this PID
        for plugin in ["windows.netstat", "windows.netscan"]:
            rows = _get_rows(ctx, plugin)
            matches = [r for r in rows if r.get("PID") == pid or r.get("Owner", {}).get("PID") == pid]
            if matches:
                result["network_connections"] = matches

    return result if result else {"error": f"Process not found (pid={pid}, name={proc_name})"}


async def _tool_search_strings(inp: dict, ctx: "AgentContext") -> dict:
    pattern = inp["pattern"].lower()
    limit = min(inp.get("limit", 50), 200)

    results = []
    for plugin in ["windows.strings", "linux.strings"]:
        rows = _get_rows(ctx, plugin)
        for row in rows:
            val = str(row.get("String", row.get("Value", ""))).lower()
            if pattern in val:
                results.append({"plugin": plugin, "match": row})
                if len(results) >= limit:
                    break
        if len(results) >= limit:
            break

    return {"pattern": pattern, "matches": results, "total": len(results)}


async def _tool_lookup_ioc(inp: dict, ctx: "AgentContext") -> dict:
    value = inp["value"]
    enrichment = ctx.ioc_enrichments.get(value)
    if not enrichment:
        return {"value": value, "status": "not_enriched", "note": "Not found in VT cache"}
    return {"value": value, "virustotal": enrichment}


async def _tool_list_network_connections(inp: dict, ctx: "AgentContext") -> dict:
    state_filter = inp.get("state", "").upper()
    remote_ip_filter = inp.get("remote_ip", "").lower()
    exclude_local = inp.get("exclude_local", True)

    PRIVATE_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.2", "172.3", "192.168.", "127.", "::1", "fe80:")

    connections = []
    for plugin in ["windows.netstat", "windows.netscan", "linux.netstat", "mac.netstat"]:
        rows = _get_rows(ctx, plugin)
        for row in rows:
            remote = str(row.get("ForeignAddr", row.get("RemoteAddr", ""))).lower()
            if exclude_local and any(remote.startswith(p) for p in PRIVATE_PREFIXES):
                continue
            if state_filter and state_filter not in str(row.get("State", "")).upper():
                continue
            if remote_ip_filter and remote_ip_filter not in remote:
                continue
            connections.append({**row, "_source_plugin": plugin})

    return {"connections": connections, "total": len(connections)}


async def _tool_get_registry_key(inp: dict, ctx: "AgentContext") -> dict:
    key_path = inp["key_path"].lower()
    rows = _get_rows(ctx, "windows.registry.printkey")
    matches = [r for r in rows if key_path in str(r.get("Key", "")).lower()]
    return {"key_path": key_path, "results": matches[:50]}


def _get_rows(ctx: "AgentContext", plugin: str) -> list:
    output = ctx.plugin_outputs.get(plugin, {})
    if isinstance(output, list):
        return output
    if isinstance(output, dict):
        return output.get("rows", [])
    return []
