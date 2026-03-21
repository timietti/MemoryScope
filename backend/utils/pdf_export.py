# backend/utils/pdf_export.py
"""
PDF report generation using WeasyPrint.
Phase 3 feature — stub returns a placeholder until implemented.
"""
from __future__ import annotations
import logging

logger = logging.getLogger(__name__)


async def generate_pdf(report) -> bytes:
    """
    Generate a PDF from the AI report object.

    TODO (Phase 3): Implement with WeasyPrint.
    The approach:
      1. Render an HTML template (Jinja2) with report data
      2. Pass rendered HTML to weasyprint.HTML().write_pdf()
      3. Return raw bytes

    Example:
        from jinja2 import Environment, PackageLoader
        from weasyprint import HTML, CSS

        env = Environment(loader=PackageLoader("backend", "templates"))
        template = env.get_template("report.html")
        html_content = template.render(report=report)
        pdf_bytes = HTML(string=html_content).write_pdf(
            stylesheets=[CSS(string="@page { margin: 2cm; }")]
        )
        return pdf_bytes
    """
    raise NotImplementedError(
        "PDF export is a Phase 3 feature. "
        "See backend/utils/pdf_export.py for the implementation guide."
    )
