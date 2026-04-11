# backend/core/agent/chat.py
"""
Interactive case chat assistant with Anthropic streaming + prompt caching.

Reuses AGENT_TOOLS / dispatch_tool_call() from tools.py for on-demand
plugin data fetching. The global knowledge base and case context are marked
as cacheable to minimise per-message input-token costs.

Falls back to any OpenAI-compatible endpoint when ANTHROPIC_API_KEY is not
set and FALLBACK_API_URL / FALLBACK_API_KEY are configured.
"""
from __future__ import annotations

import json
import logging
from typing import Any, AsyncIterator

from anthropic import AsyncAnthropic

from backend.config import settings
from backend.core.agent.tools import AGENT_TOOLS, dispatch_tool_call
from backend.core.agent.orchestrator import AgentContext, _tools_to_oai, _msgs_to_oai

logger = logging.getLogger(__name__)

_CHAT_MODEL = "claude-sonnet-4-6"
_MAX_TOOL_ROUNDS = 5

# ── Global knowledge base ─────────────────────────────────────────────────────
# Cached across all chat sessions (>1024 tokens to hit the caching threshold).
_GLOBAL_KB = """
You are a forensic analysis assistant embedded in MemoryScope, a memory forensics
platform built on Volatility3. You help analysts understand case findings, explain
technical details from the AI-generated report, answer investigation questions, and
fetch specific plugin data on demand.

Your audience is experienced security analysts. Be concise, technical, and precise.
Format responses in Markdown. Use tables for structured data. Do not pad answers.

## Volatility3 plugin reference

### Windows plugins
- **windows.pslist / windows.pstree** — running processes (PID, PPID, name, start time)
- **windows.cmdline** — full command lines for each process
- **windows.dlllist** — DLLs loaded into each process address space
- **windows.handles** — open handles (files, registry keys, mutants, events)
- **windows.malfind** — memory regions with RWX permissions + PE headers (injection indicator)
- **windows.vadinfo** — Virtual Address Descriptor nodes (memory layout per process)
- **windows.netscan / windows.netstat** — network connections and listening sockets
- **windows.modules** — loaded kernel modules
- **windows.ssdt** — System Service Descriptor Table hooks (rootkit indicator)
- **windows.driverirp** — IRP handler hooks per driver
- **windows.registry.printkey** — registry key enumeration
- **windows.registry.run** — autorun / persistence registry keys
- **windows.services** — Windows services (name, binary path, state)
- **windows.hashdump** — NTLM password hashes from SAM
- **windows.lsadump** — LSA secrets (service account passwords, cached creds)
- **windows.cachedump** — domain cached credentials
- **windows.filescan** — file objects cached in kernel pool memory
- **windows.dumpfiles** — extract file data from memory-cached file objects
- **windows.strings** — printable strings attributed to processes

### Linux plugins
- **linux.pslist / linux.pstree** — running processes
- **linux.bash** — bash command history from memory
- **linux.check_syscall** — syscall table hooks (rootkit detection)
- **linux.hidden_modules** — kernel modules not in the visible module list
- **linux.lsmod** — loaded kernel modules
- **linux.netfilter** — netfilter hooks (firewall/rootkit)
- **linux.netstat** — network connections and sockets
- **linux.strings** — process memory strings

### macOS plugins
- **mac.pslist / mac.pstree** — running processes
- **mac.netstat** — network connections
- **mac.lsmod** — kernel extensions
- **mac.check_syscall** — syscall hooks

## MITRE ATT&CK quick reference

| ID | Technique |
|----|-----------|
| T1055 | Process Injection (malfind hits) |
| T1059 | Command and Scripting Interpreter (cmdline analysis) |
| T1547 | Boot/Logon Autostart Execution (registry Run keys, services) |
| T1021 | Remote Services (lateral movement via network connections) |
| T1003 | OS Credential Dumping (hashdump, lsadump, cachedump) |
| T1070 | Indicator Removal (log clearing, timestomping) |
| T1082 | System Information Discovery |
| T1057 | Process Discovery |
| T1049 | System Network Connections Discovery |
| T1014 | Rootkit (SSDT hooks, hidden modules, syscall hooks) |
| T1105 | Ingress Tool Transfer (suspicious network + dropped files) |

## Investigation patterns

**Suspicious process**: Check parent (pstree), command line (cmdline), loaded DLLs
(dlllist), open handles, and network connections. Cross-reference with malfind for
injected code regions.

**Lateral movement**: Look for psexec, wmic, schtasks in cmdline; outbound connections
to internal hosts on ports 445, 135, 5985; credential material in lsadump.

**Persistence**: Registry Run keys, scheduled tasks (schtasks in cmdline), services
with unusual binary paths, bash history modifications.

**Rootkit**: SSDT hook count > 0, hidden processes (compare pslist vs pstree),
hidden modules, modified syscall table entries.

**Credential theft**: hashdump for NTLM hashes, lsadump for plaintext/cached,
lsass.exe open handles to other processes.

## Response guidelines

- If data is not in the case context, say so and offer to fetch it via a tool.
- When fetching plugin output, summarise the most significant rows; do not dump
  thousands of lines unless specifically asked.
- Flag high-confidence IOCs (external IPs, suspicious hashes, injected PE headers)
  clearly.
- Reference MITRE ATT&CK IDs where relevant.
""".strip()

_MAX_CONTEXT_IOC_ROWS = 60
_MAX_CONTEXT_PLUGIN_ROWS = 10  # snippet per plugin in context


# ── Context builder ───────────────────────────────────────────────────────────

def _build_case_context(case: Any, report: Any, iocs: list, plugin_runs: list) -> str:
    lines: list[str] = [
        f"# Case: {case.name}",
        f"- **ID**: {case.short_id}",
        f"- **OS**: {getattr(case, 'os_hint', None) or 'auto-detected'}",
        f"- **Status**: {case.status}",
        f"- **Priority**: P{case.priority}",
        f"- **File**: {case.original_filename or '—'} "
        f"({(case.file_size_bytes or 0) / 1e9:.2f} GB)",
        "",
    ]

    if report and getattr(report, "content", None):
        lines += ["## AI Analysis Report", report.content, ""]

    if iocs:
        lines.append("## IOCs")
        for ioc in iocs[:_MAX_CONTEXT_IOC_ROWS]:
            vt = f" [VT: {ioc.vt_verdict}]" if getattr(ioc, "vt_verdict", None) else ""
            lines.append(f"- `{ioc.value}` ({ioc.ioc_type}){vt}")
        if len(iocs) > _MAX_CONTEXT_IOC_ROWS:
            lines.append(f"- … and {len(iocs) - _MAX_CONTEXT_IOC_ROWS} more")
        lines.append("")

    if plugin_runs:
        lines.append("## Available Plugin Runs")
        lines.append(
            "Use the `get_plugin_output` tool to fetch full data for any completed plugin."
        )
        for pr in plugin_runs:
            status_sym = "✓" if str(pr.status).endswith("complete") else (
                "✗" if str(pr.status).endswith("failed") else "…"
            )
            domain = getattr(pr, "domain", "") or ""
            lines.append(f"- {status_sym} `{pr.plugin_name}` ({domain})")
        lines.append("")

    return "\n".join(lines)


def _build_agent_context(case: Any, iocs: list, plugin_runs: list) -> AgentContext:
    """Build an AgentContext from DB objects so tools.py handlers can be reused."""
    plugin_index: dict[str, dict] = {}
    plugin_outputs: dict[str, Any] = {}

    for pr in plugin_runs:
        po = pr.parsed_output
        row_count = len(po) if isinstance(po, list) else (
            len(po.get("rows", [])) if isinstance(po, dict) else 0
        )
        plugin_index[pr.plugin_name] = {
            "status": str(pr.status),
            "row_count": row_count,
            "domain": getattr(pr, "domain", "") or "",
            "summary_snippet": "",
        }
        if str(pr.status).endswith("complete") and po:
            plugin_outputs[pr.plugin_name] = po

    ioc_enrichments: dict[str, Any] = {}
    for ioc in iocs:
        if getattr(ioc, "vt_verdict", None):
            ioc_enrichments[ioc.value] = {"verdict": ioc.vt_verdict, "type": ioc.ioc_type}

    return AgentContext(
        case_id=str(case.id),
        detected_os=str(getattr(case, "os_hint", "") or ""),
        plugin_index=plugin_index,
        plugin_outputs=plugin_outputs,
        ioc_enrichments=ioc_enrichments,
        analyst_notes=[],
        prior_report=None,
        token_usage={},
    )


# ── Streaming chat ────────────────────────────────────────────────────────────

async def stream_chat(
    case: Any,
    report: Any,
    iocs: list,
    plugin_runs: list,
    messages: list[dict],
    usage_out: dict | None = None,
) -> AsyncIterator[str]:
    """
    Async generator that yields SSE-formatted strings.

    SSE event types:
      {"type": "text",       "text": "..."}         — streamed text chunk
      {"type": "tool_start", "name": "...", "input": {...}}
      {"type": "tool_done",  "name": "..."}
      {"type": "done"}                               — conversation turn complete
      {"type": "error",      "message": "..."}       — fatal error
    """
    ctx = _build_agent_context(case, iocs, plugin_runs)
    case_context = _build_case_context(case, report, iocs, plugin_runs)

    anthropic_key = settings.ANTHROPIC_API_KEY.get_secret_value() if settings.ANTHROPIC_API_KEY else ""
    fallback_url = settings.FALLBACK_API_URL
    fallback_key = settings.FALLBACK_API_KEY.get_secret_value() if settings.FALLBACK_API_KEY else ""

    if anthropic_key:
        async for chunk in _stream_anthropic(ctx, case_context, messages, usage_out):
            yield chunk
    elif fallback_url or fallback_key:
        async for chunk in _stream_oai(ctx, case_context, messages, usage_out, fallback_url, fallback_key):
            yield chunk
    else:
        yield _sse({"type": "error", "message": "No AI provider configured: set ANTHROPIC_API_KEY or FALLBACK_API_URL + FALLBACK_API_KEY"})


async def _stream_anthropic(
    ctx: AgentContext,
    case_context: str,
    messages: list[dict],
    usage_out: dict | None,
) -> AsyncIterator[str]:
    client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY.get_secret_value())  # type: ignore[union-attr]

    system = [
        {"type": "text", "text": _GLOBAL_KB, "cache_control": {"type": "ephemeral"}},
        {"type": "text", "text": case_context, "cache_control": {"type": "ephemeral"}},
    ]

    conversation = list(messages)

    for round_num in range(_MAX_TOOL_ROUNDS + 1):
        pending_tool: dict | None = None
        tool_calls: list[dict] = []

        try:
            async with client.messages.stream(
                model=_CHAT_MODEL,
                max_tokens=2048,
                system=system,
                tools=AGENT_TOOLS,
                messages=conversation,
                extra_headers={"anthropic-beta": "prompt-caching-2024-07-31"},
            ) as stream:
                async for event in stream:
                    etype = event.type

                    if etype == "content_block_start":
                        cb = event.content_block
                        if cb.type == "tool_use":
                            pending_tool = {"id": cb.id, "name": cb.name, "input_json": ""}

                    elif etype == "content_block_delta":
                        delta = event.delta
                        if delta.type == "text_delta":
                            yield _sse({"type": "text", "text": delta.text})
                        elif delta.type == "input_json_delta" and pending_tool:
                            pending_tool["input_json"] += delta.partial_json

                    elif etype == "content_block_stop":
                        if pending_tool:
                            tool_calls.append(pending_tool)
                            pending_tool = None

                final_message = await stream.get_final_message()

                if usage_out is not None and final_message.usage:
                    usage_out["input_tokens"]  = usage_out.get("input_tokens",  0) + (final_message.usage.input_tokens  or 0)
                    usage_out["output_tokens"] = usage_out.get("output_tokens", 0) + (final_message.usage.output_tokens or 0)
                    usage_out["model"] = _CHAT_MODEL

        except Exception as exc:
            logger.exception("Chat stream error (round %d)", round_num)
            yield _sse({"type": "error", "message": str(exc)})
            return

        if not tool_calls or round_num >= _MAX_TOOL_ROUNDS:
            yield _sse({"type": "done"})
            return

        tool_results: list[dict] = []
        for tc in tool_calls:
            try:
                tool_input = json.loads(tc["input_json"]) if tc["input_json"] else {}
            except json.JSONDecodeError:
                tool_input = {}

            yield _sse({"type": "tool_start", "name": tc["name"], "input": tool_input})
            try:
                result = await dispatch_tool_call(tc["name"], tool_input, ctx)
                result_text = json.dumps(result) if not isinstance(result, str) else result
            except Exception as exc:
                result_text = f"Tool error: {exc}"
            yield _sse({"type": "tool_done", "name": tc["name"]})

            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc["id"],
                "content": result_text,
            })

        conversation.append({"role": "assistant", "content": final_message.content})
        conversation.append({"role": "user", "content": tool_results})

    yield _sse({"type": "done"})


async def _stream_oai(
    ctx: AgentContext,
    case_context: str,
    messages: list[dict],
    usage_out: dict | None,
    base_url: str,
    api_key: str,
) -> AsyncIterator[str]:
    import openai

    model = settings.FALLBACK_MODEL or "gpt-4o"
    client = openai.AsyncOpenAI(
        base_url=base_url or None,
        api_key=api_key or "none",
    )

    system_text = f"{_GLOBAL_KB}\n\n{case_context}"
    oai_tools = _tools_to_oai(AGENT_TOOLS)

    conversation = [{"role": "system", "content": system_text}] + _msgs_to_oai(messages)

    for round_num in range(_MAX_TOOL_ROUNDS + 1):
        tool_calls_acc: dict[int, dict] = {}  # index → accumulated call

        try:
            stream = await client.chat.completions.create(
                model=model,
                max_tokens=2048,
                messages=conversation,
                tools=oai_tools,
                stream=True,
            )
            finish_reason: str | None = None
            assistant_text = ""

            async for chunk in stream:
                choice = chunk.choices[0] if chunk.choices else None
                if choice is None:
                    continue

                finish_reason = choice.finish_reason or finish_reason
                delta = choice.delta

                if delta.content:
                    assistant_text += delta.content
                    yield _sse({"type": "text", "text": delta.content})

                for tc_delta in delta.tool_calls or []:
                    idx = tc_delta.index
                    if idx not in tool_calls_acc:
                        tool_calls_acc[idx] = {"id": "", "name": "", "arguments": ""}
                    if tc_delta.id:
                        tool_calls_acc[idx]["id"] = tc_delta.id
                    if tc_delta.function:
                        if tc_delta.function.name:
                            tool_calls_acc[idx]["name"] = tc_delta.function.name
                        if tc_delta.function.arguments:
                            tool_calls_acc[idx]["arguments"] += tc_delta.function.arguments

            if usage_out is not None:
                # OpenAI streams don't expose usage by default; best-effort
                usage_out.setdefault("model", model)

        except Exception as exc:
            logger.exception("Chat OAI stream error (round %d)", round_num)
            yield _sse({"type": "error", "message": str(exc)})
            return

        tool_calls = list(tool_calls_acc.values())

        if not tool_calls or round_num >= _MAX_TOOL_ROUNDS:
            yield _sse({"type": "done"})
            return

        # Build assistant message with tool_calls for the conversation history
        oai_tool_calls = [
            {
                "id": tc["id"],
                "type": "function",
                "function": {"name": tc["name"], "arguments": tc["arguments"]},
            }
            for tc in tool_calls
        ]
        conversation.append({"role": "assistant", "content": assistant_text or None, "tool_calls": oai_tool_calls})

        for tc in tool_calls:
            try:
                tool_input = json.loads(tc["arguments"]) if tc["arguments"] else {}
            except json.JSONDecodeError:
                tool_input = {}

            yield _sse({"type": "tool_start", "name": tc["name"], "input": tool_input})
            try:
                result = await dispatch_tool_call(tc["name"], tool_input, ctx)
                result_text = json.dumps(result) if not isinstance(result, str) else result
            except Exception as exc:
                result_text = f"Tool error: {exc}"
            yield _sse({"type": "tool_done", "name": tc["name"]})

            conversation.append({
                "role": "tool",
                "tool_call_id": tc["id"],
                "content": result_text,
            })

    yield _sse({"type": "done"})


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"
