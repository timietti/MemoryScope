# backend/utils/pdf_export.py
"""
PDF report generation using WeasyPrint.
"""
from __future__ import annotations
import asyncio
import html
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Verdict colour map (hex)
_VERDICT_COLORS = {
    "clean":        "#2ee88a",
    "suspicious":   "#f5c518",
    "compromised":  "#ff3d57",
    "inconclusive": "#a8c0d8",
}

_SEVERITY_COLORS = {
    "info":     "#a8c0d8",
    "low":      "#2ee88a",
    "medium":   "#f5c518",
    "high":     "#ff8c00",
    "critical": "#ff3d57",
}


def _esc(value) -> str:
    return html.escape(str(value)) if value is not None else ""


def _fmt_dt(dt) -> str:
    if dt is None:
        return "—"
    if isinstance(dt, str):
        try:
            dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
        except ValueError:
            return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def _build_html(report) -> str:
    verdict_str = report.verdict.value if hasattr(report.verdict, "value") else str(report.verdict)
    color = _VERDICT_COLORS.get(verdict_str, "#a8c0d8")

    # ── MITRE ATT&CK rows ───────────────────────────────────────────────────
    mitre_rows = ""
    for t in (report.mitre_ttps or []):
        sev = t.get("severity", "info") if isinstance(t, dict) else getattr(t, "severity", "info")
        sev_str = sev.value if hasattr(sev, "value") else str(sev)
        sev_color = _SEVERITY_COLORS.get(sev_str, "#a8c0d8")
        technique = _esc(t.get("technique") if isinstance(t, dict) else getattr(t, "technique", ""))
        tech_name = _esc(t.get("technique_name") if isinstance(t, dict) else getattr(t, "technique_name", ""))
        tactic_name = _esc(t.get("tactic_name") if isinstance(t, dict) else getattr(t, "tactic_name", ""))
        evidence = _esc(t.get("evidence") if isinstance(t, dict) else getattr(t, "evidence", ""))
        mitre_rows += f"""
        <tr>
          <td><span class="badge" style="background:{sev_color}20;color:{sev_color};border:1px solid {sev_color}40">{sev_str.upper()}</span></td>
          <td><code>{technique}</code></td>
          <td>{tech_name} <span class="dim">({tactic_name})</span></td>
          <td class="evidence">{evidence}</td>
        </tr>"""

    mitre_section = ""
    if report.mitre_ttps:
        mitre_section = f"""
        <h2>MITRE ATT&amp;CK Techniques</h2>
        <table>
          <thead><tr><th>Severity</th><th>Technique</th><th>Name</th><th>Evidence</th></tr></thead>
          <tbody>{mitre_rows}</tbody>
        </table>"""

    # ── Timeline rows ────────────────────────────────────────────────────────
    timeline_html = ""
    if report.timeline:
        items = ""
        for e in report.timeline:
            ts = _esc(e.get("timestamp_estimate") if isinstance(e, dict) else getattr(e, "timestamp_estimate", ""))
            event = _esc(e.get("event") if isinstance(e, dict) else getattr(e, "event", ""))
            plugin = _esc(e.get("evidence_plugin") if isinstance(e, dict) else getattr(e, "evidence_plugin", ""))
            items += f"""<div class="timeline-item">
              <div class="tl-dot"></div>
              <div class="tl-body">
                <div class="tl-ts">{ts}</div>
                <div class="tl-event">{event}</div>
                <div class="dim" style="font-size:11px">via {plugin}</div>
              </div>
            </div>"""
        timeline_html = f"<h2>Event Timeline</h2><div class='timeline'>{items}</div>"

    # ── Recommendations ──────────────────────────────────────────────────────
    rec_html = ""
    if report.recommendations:
        recs = sorted(
            report.recommendations,
            key=lambda r: r.get("priority", 99) if isinstance(r, dict) else getattr(r, "priority", 99),
        )
        items = ""
        for r in recs:
            prio = r.get("priority") if isinstance(r, dict) else getattr(r, "priority", "")
            action = _esc(r.get("action") if isinstance(r, dict) else getattr(r, "action", ""))
            rationale = _esc(r.get("rationale") if isinstance(r, dict) else getattr(r, "rationale", ""))
            items += f"""<div class="rec">
              <div class="rec-prio">{prio}</div>
              <div>
                <div class="rec-action">{action}</div>
                <div class="dim">{rationale}</div>
              </div>
            </div>"""
        rec_html = f"<h2>Recommendations</h2>{items}"

    # ── Assemble ─────────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
  @page {{
    margin: 2cm 2.5cm;
    @top-right {{ content: "MemoryScope — Confidential"; font-size: 9px; color: #666; }}
    @bottom-right {{ content: counter(page) " / " counter(pages); font-size: 9px; color: #666; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: "DejaVu Sans", "Liberation Sans", Arial, sans-serif;
    font-size: 12px;
    color: #1e2530;
    line-height: 1.6;
    background: #fff;
  }}
  code {{ font-family: "DejaVu Sans Mono", monospace; font-size: 11px; }}
  h1 {{ font-size: 22px; font-weight: 700; margin: 0 0 4px; }}
  h2 {{
    font-size: 14px; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.05em; color: #555;
    border-bottom: 1px solid #dde; margin: 28px 0 12px; padding-bottom: 4px;
  }}
  p {{ margin: 0 0 10px; }}
  .dim {{ color: #888; }}

  /* Verdict banner */
  .banner {{
    background: {color}18;
    border: 1px solid {color}50;
    border-radius: 8px;
    padding: 20px 24px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 32px;
    page-break-inside: avoid;
  }}
  .verdict-label {{
    font-size: 28px; font-weight: 800;
    color: {color}; letter-spacing: 0.08em;
    font-family: "DejaVu Sans Mono", monospace;
  }}
  .meta {{ font-size: 11px; color: #666; margin-top: 6px; }}
  .confidence-circle {{
    width: 64px; height: 64px;
    border-radius: 50%;
    border: 3px solid {color};
    display: flex; align-items: center; justify-content: center;
    font-size: 16px; font-weight: 700; color: {color};
    flex-shrink: 0;
    text-align: center;
    line-height: 1;
  }}

  /* Sections */
  .section {{ margin-bottom: 20px; page-break-inside: avoid; }}
  .narrative {{ white-space: pre-wrap; font-size: 11.5px; line-height: 1.75; }}

  /* MITRE table */
  table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
  th {{ background: #f4f5f8; text-align: left; padding: 7px 10px; border-bottom: 2px solid #dde; font-size: 10px; text-transform: uppercase; letter-spacing: 0.04em; color: #666; }}
  td {{ padding: 7px 10px; border-bottom: 1px solid #eef; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  .evidence {{ color: #555; font-size: 10.5px; }}
  .badge {{
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.05em;
    font-family: "DejaVu Sans Mono", monospace;
  }}

  /* Timeline */
  .timeline {{ padding-left: 20px; border-left: 2px solid #dde; }}
  .timeline-item {{ display: flex; gap: 12px; margin-bottom: 14px; position: relative; }}
  .tl-dot {{
    width: 10px; height: 10px; border-radius: 50%;
    background: #4a90e2; flex-shrink: 0; margin-top: 4px;
    margin-left: -25px;
  }}
  .tl-ts {{ font-size: 10px; color: #4a90e2; font-family: "DejaVu Sans Mono", monospace; margin-bottom: 2px; }}
  .tl-event {{ font-size: 12px; }}

  /* Recommendations */
  .rec {{ display: flex; gap: 14px; margin-bottom: 14px; align-items: flex-start; }}
  .rec-prio {{
    width: 24px; height: 24px; border-radius: 50%; background: #eef;
    display: flex; align-items: center; justify-content: center;
    font-size: 11px; font-weight: 700; color: #4a90e2; flex-shrink: 0;
    text-align: center; line-height: 24px;
  }}
  .rec-action {{ font-weight: 600; margin-bottom: 3px; }}

  /* Footer watermark area */
  .footer-meta {{
    margin-top: 40px;
    border-top: 1px solid #dde;
    padding-top: 10px;
    font-size: 10px;
    color: #aaa;
    display: flex;
    justify-content: space-between;
  }}
</style>
</head>
<body>

<h1>Threat Assessment Report</h1>
<p class="dim" style="font-size:11px;margin-bottom:20px">Generated {_fmt_dt(report.generated_at)} &nbsp;·&nbsp; Model: {_esc(report.model_used)} &nbsp;·&nbsp; Agent: {_esc(report.agent_version)}</p>

<div class="banner">
  <div>
    <div class="verdict-label">{verdict_str.upper()}</div>
    <div class="meta">Confidence: <strong style="color:{color}">{report.confidence}%</strong></div>
    <div class="meta" style="margin-top:6px;font-style:italic;max-width:480px">{_esc(report.verdict_reasoning)}</div>
  </div>
  <div class="confidence-circle">{report.confidence}%</div>
</div>

<h2>Executive Summary</h2>
<p>{_esc(report.executive_summary)}</p>

<h2>Technical Analysis</h2>
<p class="narrative">{_esc(report.technical_narrative)}</p>

{mitre_section}

{timeline_html}

{rec_html}

<div class="footer-meta">
  <span>MemoryScope Forensic Platform &mdash; Confidential</span>
  <span>Report generated {_fmt_dt(report.generated_at)}</span>
</div>

</body>
</html>"""


async def generate_pdf(report) -> bytes:
    """Generate a PDF from the AI report object using WeasyPrint."""
    html_content = _build_html(report)

    # WeasyPrint is synchronous; run in thread pool to avoid blocking the event loop
    loop = asyncio.get_event_loop()

    def _render() -> bytes:
        from weasyprint import HTML, CSS  # type: ignore[import]
        return HTML(string=html_content).write_pdf(
            stylesheets=[CSS(string="")]
        )

    pdf_bytes: bytes = await loop.run_in_executor(None, _render)
    return pdf_bytes
