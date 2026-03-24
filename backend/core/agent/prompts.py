# backend/core/agent/prompts.py
"""
Prompt templates for the AI agent pipeline.
Kept in one file for easy tuning and A/B testing.
"""
from __future__ import annotations
from typing import Any

# ── Orchestrator System Prompt ─────────────────────────────────────────────────

ORCHESTRATOR_SYSTEM = """
You are a senior threat intelligence analyst and memory forensics expert.
You are reviewing the output of a full memory dump analysis performed with Volatility3.
Your task is to synthesise findings from multiple forensic domains into a comprehensive,
evidence-based threat assessment report.

Guidelines:
- Be precise: cite specific process names, PIDs, memory addresses, registry keys, and plugin names.
- Distinguish confirmed compromises from suspicious indicators and false positives.
- Map findings to MITRE ATT&CK techniques (use T-codes).
- Assign a verdict: clean | suspicious | compromised | inconclusive.
- Confidence (0-100) reflects evidence quality, not severity.
- Use tools to verify claims before including them in the report.

Output format:
Your final answer MUST contain a JSON object wrapped in <report>...</report> tags.
The JSON must conform exactly to the schema below. Do not include commentary outside the tags.

Schema:
{
  "verdict": "clean|suspicious|compromised|inconclusive",
  "confidence": 0-100,
  "verdict_reasoning": "2-3 sentence explanation of the verdict",
  "executive_summary": "3-5 sentences suitable for a non-technical stakeholder",
  "technical_narrative": "Detailed multi-paragraph technical analysis",
  "mitre_ttps": [
    {
      "tactic": "TA0002",
      "tactic_name": "Execution",
      "technique": "T1059.001",
      "technique_name": "PowerShell",
      "evidence": "Specific evidence from plugin output",
      "severity": "low|medium|high|critical"
    }
  ],
  "iocs": [
    {
      "ioc_type": "ip|domain|url|md5|sha256|file_path|registry_key|mutex|process_name",
      "value": "the IOC value",
      "severity": "low|medium|high|critical",
      "description": "Why this is suspicious",
      "source_plugin": "plugin name",
      "source_pid": null
    }
  ],
  "timeline": [
    {
      "timestamp_estimate": "relative or absolute if available",
      "event": "What happened",
      "evidence_plugin": "plugin name"
    }
  ],
  "recommendations": [
    {
      "priority": 1,
      "action": "Specific action to take",
      "rationale": "Why this is recommended"
    }
  ]
}
""".strip()


# ── Orchestrator User Prompt ───────────────────────────────────────────────────

def build_orchestrator_user_prompt(
    plugin_index: dict[str, dict],
    domain_findings: dict[str, str],
    ioc_enrichments: dict[str, Any],
    detected_os: str,
    analyst_notes: list[dict] | None = None,
) -> str:
    import json

    index_str = json.dumps(
        {k: {fk: fv for fk, fv in v.items() if fk != "snippet"} for k, v in plugin_index.items()},
        indent=2
    )

    findings_str = "\n\n".join(
        f"### {domain.replace('_', ' ').title()}\n{finding}"
        for domain, finding in domain_findings.items()
    )

    vt_summary = _summarise_vt(ioc_enrichments)
    notes_section = _format_analyst_notes(analyst_notes)

    return f"""
## Memory Dump Analysis — Synthesis Request

**Detected OS:** {detected_os}
{notes_section}
**Plugin Run Summary:**
```json
{index_str}
```

## Domain Analyst Findings

{findings_str}

## VirusTotal IOC Enrichment Summary
{vt_summary}

---

Based on all of the above, synthesise a complete threat assessment report.
Use the available tools to verify specific claims if needed before producing your final report.
Produce your report in the required JSON format inside <report>...</report> tags.
""".strip()


# ── Domain Sub-Agent User Prompt ──────────────────────────────────────────────

def build_domain_prompt(
    domain: str,
    domain_plugins: dict[str, dict],
    detected_os: str,
) -> str:
    import json

    plugin_list = "\n".join(
        f"- `{name}`: {info['description']} ({info['row_count']} rows)\n  Preview: {info['snippet']}"
        for name, info in domain_plugins.items()
    )

    DOMAIN_QUESTIONS = {
        "code_injection": [
            "Are there processes with RWX memory regions containing PE headers?",
            "Is there evidence of process hollowing (VAD mismatches)?",
            "Do any injected regions match known shellcode patterns?",
        ],
        "rootkits": [
            "Are there kernel modules not in PsLoadedModuleList (DKOM hiding)?",
            "Are SSDT entries pointing outside ntoskrnl/win32k?",
            "Are there suspicious kernel callbacks registered?",
        ],
        "network": [
            "Are there connections to known malicious or unusual external IPs?",
            "Are any processes listening on unusual ports?",
            "Is there evidence of C2 beaconing (regular interval connections)?",
        ],
        "persistence": [
            "Are there suspicious Run/RunOnce registry entries?",
            "Are there unusual services or scheduled tasks?",
            "Does bash history reveal attacker commands?",
        ],
        "process_analysis": [
            "Are there processes with unusual parent-child relationships?",
            "Are there processes masquerading as system processes?",
            "Are there obfuscated or encoded command-line arguments?",
        ],
        "credentials": [
            "Is there evidence of LSASS dumping or tampering?",
            "Were password hashes or LSA secrets extracted?",
        ],
        "filesystem": [
            "Are there suspicious files cached in memory?",
            "Do file paths indicate malware dropped to disk?",
        ],
        "memory_artifacts": [
            "Are there mutex names associated with known malware families?",
            "Are there unusual handle types or kernel object references?",
        ],
        "memory_strings": [
            "Are there embedded C2 URLs or IP addresses?",
            "Are there encoded payloads (Base64, hex) in process memory?",
        ],
    }

    questions = DOMAIN_QUESTIONS.get(domain, ["Analyse the data for signs of compromise."])
    questions_str = "\n".join(f"  {i+1}. {q}" for i, q in enumerate(questions))

    return f"""
## Domain Analysis Request: {domain.replace('_', ' ').title()}

**OS:** {detected_os}

**Available plugins in this domain:**
{plugin_list}

**Key questions to answer:**
{questions_str}

Use the `get_plugin_output` tool to fetch data for plugins above.
Use `get_process_details` for deep-dives on specific suspicious processes.
Use `lookup_ioc` for any suspicious IPs, domains, or hashes you encounter.

**Efficiency rules (important — each tool call costs money):**
- Each plugin's `filter_note` and `flagged_rows` count tells you upfront how much suspicious data exists.
- If a plugin reports 0 flagged rows, do NOT fetch it — note it as clean and move on.
- Fetch at most 2–3 plugins per domain. Prioritise plugins with the highest `flagged_count`.
- If after checking the highest-priority plugins you find nothing suspicious, stop immediately and write your finding — do not exhaustively fetch every plugin.
- Keep your written analysis under 400 words.

Provide a structured analysis covering:
1. What is suspicious or anomalous (cite PIDs, addresses, strings)
2. Your confidence assessment with specific evidence
3. Any false positive considerations

If nothing suspicious is found, say so in 2–3 sentences and stop.
""".strip()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_analyst_notes(analyst_notes: list[dict] | None) -> str:
    if not analyst_notes:
        return ""
    parts = ["## Analyst Notes (Knowledge Base)\n"]
    parts.append(
        "The following notes were written by analysts and attached to this case. "
        "Treat them as authoritative context — they may describe known malware, "
        "expected behaviour for this environment, or prior investigation findings.\n"
    )
    for note in analyst_notes:
        parts.append(f"### {note['title']}\n{note['content']}\n")
    return "\n" + "\n".join(parts) + "\n"


def _summarise_vt(ioc_enrichments: dict[str, Any]) -> str:
    if not ioc_enrichments:
        return "No VirusTotal enrichment data available."

    lines = []
    malicious = [(v, d) for v, d in ioc_enrichments.items()
                 if d.get("positives", 0) > 0]
    clean = [(v, d) for v, d in ioc_enrichments.items()
             if d.get("positives", 0) == 0]

    if malicious:
        lines.append(f"**{len(malicious)} IOCs with VT detections:**")
        for value, data in sorted(malicious, key=lambda x: -x[1].get("positives", 0))[:10]:
            pos = data.get("positives", 0)
            total = data.get("total", 0)
            names = ", ".join(data.get("threat_names", [])[:3])
            lines.append(f"  - `{value}`: {pos}/{total} detections. Families: {names or 'N/A'}")

    lines.append(f"\n{len(clean)} IOCs were clean on VirusTotal.")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# backend/core/agent/report_schema.py
from pydantic import BaseModel, Field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    clean = "clean"
    suspicious = "suspicious"
    compromised = "compromised"
    inconclusive = "inconclusive"


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class MitreTTP(BaseModel):
    tactic: str                              # e.g. "TA0002"
    tactic_name: str                         # e.g. "Execution"
    technique: str                           # e.g. "T1059.001"
    technique_name: str                      # e.g. "PowerShell"
    evidence: str
    severity: Severity


class IOCEntry(BaseModel):
    ioc_type: str
    value: str
    severity: Severity
    description: str
    source_plugin: str | None = None
    source_pid: int | None = None


class TimelineEvent(BaseModel):
    timestamp_estimate: str
    event: str
    evidence_plugin: str


class Recommendation(BaseModel):
    priority: int = Field(ge=1, le=10)
    action: str
    rationale: str


class FinalReport(BaseModel):
    verdict: Verdict
    confidence: int = Field(ge=0, le=100)
    verdict_reasoning: str
    executive_summary: str
    technical_narrative: str
    mitre_ttps: list[MitreTTP] = []
    iocs: list[IOCEntry] = []
    timeline: list[TimelineEvent] = []
    recommendations: list[Recommendation] = []
    model_used: str
    agent_version: str
    token_usage: dict[str, Any] | None = None
