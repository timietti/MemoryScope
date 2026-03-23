# backend/workers/analysis.py
"""
Celery task chain for the full memory analysis pipeline:

  upload_complete
      → triage_task          (OS detection)
      → plugin_group         (parallel plugin execution)
      → enrichment_task      (IOC → VirusTotal)
      → ai_analysis_task     (LLM agent → report)
      → notify_complete      (WebSocket event)
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from pathlib import Path
from typing import Any
from uuid import UUID

from celery import chord, chain, group
from celery.utils.log import get_task_logger

from .celery_app import celery_app
from backend.config import settings
from backend.core.plugins.registry import get_plugins_for_os, get_plugin
from backend.core.plugins.runner import (
    run_plugin, run_os_detection,
    prepare_work_dir, cleanup_work_dir,
)
from backend.core.storage import download_dump, get_storage_client
from backend.utils.enrichment import enrich_iocs
from backend.utils.notifications import publish_case_event

logger = get_task_logger(__name__)


# ── Database helpers (sync wrappers for async SQLAlchemy) ─────────────────────

def _get_db_session():
    """Return a synchronous database session for use inside Celery tasks."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    # Use sync driver (psycopg2) inside Celery workers
    sync_url = settings.DATABASE_URL.replace("postgresql+asyncpg://", "postgresql://")
    engine = create_engine(sync_url)
    Session = sessionmaker(bind=engine)
    return Session()


def _update_case(session, case_id: str, **kwargs) -> None:
    from backend.db.models.models import Case
    from datetime import datetime, timezone
    session.query(Case).filter(Case.id == case_id).update(
        {**kwargs, "updated_at": datetime.now(timezone.utc)}
    )
    session.commit()


def _update_plugin_run(session, case_id: str, plugin_name: str, **kwargs) -> None:
    from backend.db.models.models import PluginRun
    from datetime import datetime, timezone
    session.query(PluginRun).filter(
        PluginRun.case_id == case_id,
        PluginRun.plugin_name == plugin_name,
    ).update({**kwargs, "updated_at": datetime.now(timezone.utc)})
    session.commit()


# ── Task 1: Triage — OS Detection ─────────────────────────────────────────────

@celery_app.task(
    name="workers.triage",
    bind=True,
    max_retries=2,
    acks_late=True,
    time_limit=300,  # 5 min hard limit
)
def triage_task(self, case_id: str) -> dict:
    """
    Download dump, detect OS, enqueue plugin tasks.
    Returns: {"case_id": ..., "os_type": ..., "storage_key": ..., "work_dir": ...}
    """
    session = _get_db_session()
    try:
        from backend.db.models.models import Case, CaseStatus
        from datetime import datetime, timezone

        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case {case_id} not found")

        logger.info("Triage starting for case %s (%s)", case_id, case.original_filename)

        _update_case(session, case_id,
                     status=CaseStatus.detecting,
                     detection_started_at=datetime.now(timezone.utc),
                     celery_task_id=self.request.id)
        publish_case_event(case_id, "status_change", {"status": "detecting"})

        # Prepare isolated working directory
        work_dir = prepare_work_dir(case_id)

        # Download dump from object storage to tmpfs
        dump_path = str(work_dir / "dump.raw")
        download_dump(case.storage_key, dump_path)
        logger.info("Dump downloaded to %s (%d bytes)", dump_path, os.path.getsize(dump_path))

        # Detect OS
        os_type, os_detail = asyncio.run(run_os_detection(dump_path, work_dir))

        # Allow analyst OS hint to override if detection failed
        if os_type == "unknown" and case.os_hint:
            os_type = case.os_hint
            os_detail = f"Manual override: {case.os_hint}"
            logger.warning("OS detection failed, using analyst hint: %s", os_type)

        _update_case(session, case_id,
                     detected_os=os_type,
                     detected_os_detail=os_detail,
                     status=CaseStatus.triage_complete)
        publish_case_event(case_id, "os_detected", {"os": os_type, "detail": os_detail})
        publish_case_event(case_id, "status_change", {"status": "triage_complete"})

        # Create PluginRun records for all applicable plugins so the UI knows what's available
        _create_plugin_run_records(session, case_id, os_type)

        # NOTE: Pipeline stops here. The analyst selects plugins manually via the UI.
        return {
            "case_id": case_id,
            "os_type": os_type,
            "dump_path": dump_path,
            "work_dir": str(work_dir),
        }

    except Exception as exc:
        logger.exception("Triage failed for case %s", case_id)
        from backend.db.models.models import CaseStatus
        _update_case(session, case_id, status=CaseStatus.failed, error_message=str(exc))
        publish_case_event(case_id, "error", {"message": str(exc), "stage": "triage"})
        raise
    finally:
        session.close()


def _create_plugin_run_records(session, case_id: str, os_type: str) -> None:
    from backend.db.models.models import PluginRun, PluginStatus
    plugins = get_plugins_for_os(os_type)
    for spec in plugins:
        run = PluginRun(
            case_id=case_id,
            plugin_name=spec.name,
            plugin_domain=spec.domain,
            status=PluginStatus.pending,
        )
        session.add(run)
    session.commit()
    logger.info("Created %d plugin run records for %s", len(plugins), os_type)


# ── Task 2: Single Plugin Execution ───────────────────────────────────────────

@celery_app.task(
    name="workers.run_plugin",
    bind=True,
    acks_late=True,
    time_limit=settings.PLUGIN_TIMEOUT_SECONDS + 60,
)
def run_plugin_task(self, plugin_name: str, case_id: str, dump_path: str, work_dir: str) -> dict:
    """Execute a single Volatility3 plugin and store results."""
    session = _get_db_session()
    try:
        from backend.db.models.models import PluginRun, PluginStatus
        from datetime import datetime, timezone

        spec = get_plugin(plugin_name)
        if not spec:
            raise ValueError(f"Unknown plugin: {plugin_name}")

        logger.info("Running plugin %s for case %s", plugin_name, case_id)

        _update_plugin_run(session, case_id, plugin_name,
                           status=PluginStatus.running,
                           started_at=datetime.now(timezone.utc))
        publish_case_event(case_id, "plugin_started", {"plugin": plugin_name})

        result = asyncio.run(run_plugin(spec, dump_path, Path(work_dir)))

        status = PluginStatus.complete if result.success else (
            PluginStatus.timeout if "timed out" in (result.error_message or "")
            else PluginStatus.failed
        )

        _update_plugin_run(session, case_id, plugin_name,
                           status=status,
                           exit_code=result.exit_code,
                           completed_at=datetime.now(timezone.utc),
                           raw_output=result.raw_output,
                           stderr_output=result.stderr_output,
                           parsed_output=result.parsed_output,
                           row_count=result.row_count,
                           error_message=result.error_message)

        publish_case_event(case_id, "plugin_complete", {
            "plugin": plugin_name,
            "status": status,
            "rows": result.row_count,
            "duration_ms": result.duration_ms,
        })

        return {"case_id": case_id, "plugin": plugin_name, "success": result.success}

    except Exception as exc:
        logger.exception("Plugin %s failed for case %s", plugin_name, case_id)
        from backend.db.models.models import PluginStatus
        _update_plugin_run(session, case_id, plugin_name,
                           status=PluginStatus.failed,
                           error_message=str(exc))
        return {"case_id": case_id, "plugin": plugin_name, "success": False, "error": str(exc)}
    finally:
        session.close()


# ── Task 3: IOC Enrichment ────────────────────────────────────────────────────

@celery_app.task(name="workers.enrich_iocs", acks_late=True, time_limit=300)
def enrichment_task(phase_result: dict) -> dict:
    """Collect IOCs from plugin outputs and enrich with VirusTotal."""
    case_id = phase_result["case_id"]
    dump_path = phase_result["dump_path"]
    work_dir = phase_result["work_dir"]

    session = _get_db_session()
    try:
        logger.info("Starting IOC enrichment for case %s", case_id)
        publish_case_event(case_id, "enrichment_started", {})

        # Collect raw plugin outputs from DB
        from backend.db.models.models import PluginRun
        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()

        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}

        # Extract IOCs from plugin outputs
        raw_iocs = _extract_iocs_from_outputs(plugin_outputs)
        logger.info("Extracted %d unique IOCs for enrichment", len(raw_iocs))

        # Enrich with VirusTotal
        enrichments = {}
        if settings.VIRUSTOTAL_API_KEY and raw_iocs:
            enrichments = asyncio.run(enrich_iocs(raw_iocs))

        publish_case_event(case_id, "enrichment_complete", {"ioc_count": len(enrichments)})

        return {
            "case_id": case_id,
            "dump_path": dump_path,
            "work_dir": work_dir,
            "enrichments": enrichments,
        }

    except Exception as exc:
        logger.exception("Enrichment failed for case %s", case_id)
        # Non-fatal — continue to AI analysis without enrichment
        return {"case_id": case_id, "dump_path": dump_path, "work_dir": work_dir, "enrichments": {}}
    finally:
        session.close()


def _extract_iocs_from_outputs(plugin_outputs: dict) -> list[dict]:
    """Pull IPs, domains, hashes from normalised plugin output."""
    import re
    iocs = []
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    hash_re = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

    for plugin_name, output in plugin_outputs.items():
        rows = output if isinstance(output, list) else output.get("rows", []) if isinstance(output, dict) else []
        for row in rows:
            row_str = str(row)
            for ip in ip_re.findall(row_str):
                if not ip.startswith(("127.", "0.", "255.")):
                    iocs.append({"type": "ip", "value": ip, "source": plugin_name})
            for h in hash_re.findall(row_str):
                length = len(h)
                ioc_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(length)
                if ioc_type:
                    iocs.append({"type": ioc_type, "value": h.lower(), "source": plugin_name})

    # Deduplicate by value
    seen = set()
    unique = []
    for ioc in iocs:
        if ioc["value"] not in seen:
            seen.add(ioc["value"])
            unique.append(ioc)

    return unique


# ── Task 4: AI Analysis ───────────────────────────────────────────────────────

@celery_app.task(
    name="workers.ai_analysis",
    bind=True,
    acks_late=True,
    time_limit=3600,   # 1 hour — large dumps with many plugins take time
    max_retries=1,
)
def ai_analysis_task(self, enrichment_result: dict) -> dict:
    """Run the AI agent pipeline and store the final report."""
    case_id = enrichment_result["case_id"]
    dump_path = enrichment_result["dump_path"]
    work_dir = enrichment_result["work_dir"]
    enrichments = enrichment_result.get("enrichments", {})

    session = _get_db_session()
    try:
        from backend.db.models.models import Case, CaseStatus, PluginRun, Report, Verdict
        from backend.core.agent.orchestrator import run_agent
        from datetime import datetime, timezone

        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case {case_id} not found")

        _update_case(session, case_id,
                     status=CaseStatus.ai_analysis,
                     ai_started_at=datetime.now(timezone.utc))
        publish_case_event(case_id, "status_change", {"status": "ai_analysis"})

        # Load all plugin outputs
        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()
        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}

        logger.info("Starting AI agent for case %s with %d plugin outputs", case_id, len(plugin_outputs))

        # Run the agent
        report_data = asyncio.run(run_agent(
            case_id=case_id,
            detected_os=case.detected_os,
            plugin_outputs=plugin_outputs,
            ioc_enrichments=enrichments,
        ))

        logger.info("Agent complete. Verdict: %s (%d confidence)", report_data.verdict, report_data.confidence)

        # Persist report
        report = Report(
            case_id=case_id,
            verdict=Verdict(report_data.verdict),
            confidence=report_data.confidence,
            verdict_reasoning=report_data.verdict_reasoning,
            mitre_ttps=[t.model_dump() for t in report_data.mitre_ttps],
            executive_summary=report_data.executive_summary,
            technical_narrative=report_data.technical_narrative,
            recommendations=[r.model_dump() for r in report_data.recommendations],
            timeline=[e.model_dump() for e in report_data.timeline],
            model_used=report_data.model_used,
            agent_version=report_data.agent_version,
            token_usage=report_data.token_usage,
        )
        session.add(report)

        # Update plugin_runs with AI flags
        _apply_ai_flags_to_plugins(session, case_id, report_data)

        # Persist IOCs
        _persist_iocs(session, case_id, str(report.id), report_data.iocs, enrichments)

        _update_case(session, case_id,
                     status=CaseStatus.complete,
                     completed_at=datetime.now(timezone.utc))
        session.commit()

        publish_case_event(case_id, "report_ready", {
            "verdict": report_data.verdict,
            "confidence": report_data.confidence,
        })

        return {"case_id": case_id, "verdict": report_data.verdict, "success": True}

    except Exception as exc:
        logger.exception("AI analysis failed for case %s", case_id)
        from backend.db.models.models import CaseStatus
        _update_case(session, case_id, status=CaseStatus.failed, error_message=str(exc))
        publish_case_event(case_id, "error", {"message": str(exc), "stage": "ai_analysis"})
        raise
    finally:
        # Always clean up the work directory
        cleanup_work_dir(Path(work_dir))
        session.close()


def _apply_ai_flags_to_plugins(session, case_id: str, report_data) -> None:
    """Mark plugin runs that contributed suspicious findings."""
    from backend.db.models.models import PluginRun
    flagged_plugins = {ioc.source_plugin for ioc in report_data.iocs if ioc.source_plugin}
    flagged_plugins |= {ttp.evidence[:50] for ttp in report_data.mitre_ttps}  # crude signal

    for plugin_name in flagged_plugins:
        session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.plugin_name == plugin_name,
        ).update({"ai_flagged": True})


def _persist_iocs(session, case_id: str, report_id: str, iocs: list, enrichments: dict) -> None:
    from backend.db.models.models import IOC, IOCType, Severity
    for ioc_entry in iocs:
        vt = enrichments.get(ioc_entry.value, {})
        ioc = IOC(
            case_id=case_id,
            report_id=report_id,
            ioc_type=IOCType(ioc_entry.ioc_type),
            value=ioc_entry.value,
            severity=Severity(ioc_entry.severity),
            description=ioc_entry.description,
            source_plugin=ioc_entry.source_plugin,
            source_pid=ioc_entry.source_pid,
            vt_positives=vt.get("positives"),
            vt_total=vt.get("total"),
            vt_permalink=vt.get("permalink"),
            threat_names=vt.get("threat_names", []),
            ai_context=ioc_entry.description,
        )
        session.add(ioc)


# ── Task: Run Selected Plugins (manual trigger) ───────────────────────────────

@celery_app.task(
    name="workers.run_selected_plugins",
    bind=True,
    acks_late=True,
    time_limit=3600,
)
def run_selected_plugins_task(self, case_id: str, plugin_names: list[str]) -> dict:
    """
    Run a user-selected subset of plugins for a case.
    Downloads the dump if not already present in the work directory.
    """
    session = _get_db_session()
    try:
        from backend.db.models.models import Case, CaseStatus
        from datetime import datetime, timezone

        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case {case_id} not found")

        _update_case(session, case_id,
                     status=CaseStatus.analyzing,
                     analysis_started_at=datetime.now(timezone.utc))
        publish_case_event(case_id, "status_change", {"status": "analyzing"})

        # Prepare work directory — creates it if missing (exist_ok=True)
        work_dir = prepare_work_dir(case_id)
        dump_path = str(work_dir / "dump.raw")

        # Re-download dump if it was cleaned up or this is a fresh worker node
        if not os.path.exists(dump_path):
            logger.info("Dump not found locally, downloading for case %s", case_id)
            download_dump(case.storage_key, dump_path)

        logger.info("Running %d selected plugins for case %s", len(plugin_names), case_id)

        results = []
        for plugin_name in plugin_names:
            result = run_plugin_task.run(plugin_name, case_id, dump_path, str(work_dir))
            results.append(result)

        _update_case(session, case_id, status=CaseStatus.triage_complete)
        publish_case_event(case_id, "status_change", {"status": "triage_complete"})

        return {"case_id": case_id, "plugin_results": results}

    except Exception as exc:
        logger.exception("Plugin run failed for case %s", case_id)
        from backend.db.models.models import CaseStatus
        _update_case(session, case_id, status=CaseStatus.failed, error_message=str(exc))
        publish_case_event(case_id, "error", {"message": str(exc), "stage": "plugin_run"})
        raise
    finally:
        session.close()


# ── Task: Manual Enrichment ───────────────────────────────────────────────────

@celery_app.task(name="workers.manual_enrich", acks_late=True, time_limit=300)
def manual_enrich_task(case_id: str) -> dict:
    """Standalone enrichment task triggered manually by the analyst."""
    session = _get_db_session()
    try:
        from backend.db.models.models import PluginRun
        logger.info("Starting manual IOC enrichment for case %s", case_id)
        publish_case_event(case_id, "enrichment_started", {})

        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()
        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}
        raw_iocs = _extract_iocs_from_outputs(plugin_outputs)

        enrichments = {}
        if settings.VIRUSTOTAL_API_KEY and raw_iocs:
            enrichments = asyncio.run(enrich_iocs(raw_iocs))

        publish_case_event(case_id, "enrichment_complete", {"ioc_count": len(enrichments)})
        return {"case_id": case_id, "enrichments": enrichments}

    except Exception as exc:
        logger.exception("Manual enrichment failed for case %s", case_id)
        return {"case_id": case_id, "enrichments": {}}
    finally:
        session.close()


# ── Dispatch Functions ────────────────────────────────────────────────────────

def dispatch_triage(case_id: str) -> str:
    """Dispatch triage only. Pipeline stops at triage_complete."""
    task = triage_task.apply_async(args=[case_id])
    return task.id


def dispatch_selected_plugins(case_id: str, plugin_names: list[str]) -> str:
    """Dispatch selected plugins for manual plugin run."""
    task = run_selected_plugins_task.apply_async(args=[case_id, plugin_names])
    return task.id


def dispatch_enrich(case_id: str) -> str:
    """Dispatch standalone enrichment."""
    task = manual_enrich_task.apply_async(args=[case_id])
    return task.id


def dispatch_ai_analysis(case_id: str) -> str:
    """Dispatch enrichment → AI analysis chain."""
    # Re-download dump if needed (ai_analysis_task reads from DB, not file system)
    session = _get_db_session()
    try:
        from backend.db.models.models import Case
        case = session.query(Case).filter(Case.id == case_id).first()
        if not case:
            raise ValueError(f"Case {case_id} not found")
        storage_key = case.storage_key
    finally:
        session.close()

    # Build a small chain: enrich → ai_analysis
    # Enrichment passes its result dict to ai_analysis_task
    # ai_analysis_task needs case_id, dump_path, work_dir
    work_dir = prepare_work_dir(case_id)
    dump_path = str(work_dir / "dump.raw")

    task = chain(
        _enrich_for_ai.s(case_id, storage_key, dump_path, str(work_dir)),
        ai_analysis_task.s(),
    ).apply_async()
    return task.id


@celery_app.task(name="workers.enrich_for_ai", acks_late=True, time_limit=300)
def _enrich_for_ai(case_id: str, storage_key: str, dump_path: str, work_dir: str) -> dict:
    """Download dump (if needed) and enrich IOCs, returning result dict for ai_analysis_task."""
    if not os.path.exists(dump_path):
        download_dump(storage_key, dump_path)

    session = _get_db_session()
    try:
        from backend.db.models.models import PluginRun
        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()
        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}
        raw_iocs = _extract_iocs_from_outputs(plugin_outputs)

        enrichments = {}
        if settings.VIRUSTOTAL_API_KEY and raw_iocs:
            enrichments = asyncio.run(enrich_iocs(raw_iocs))

        publish_case_event(case_id, "enrichment_complete", {"ioc_count": len(enrichments)})
        return {"case_id": case_id, "dump_path": dump_path, "work_dir": work_dir, "enrichments": enrichments}
    except Exception as exc:
        logger.exception("Enrichment step failed for case %s", case_id)
        return {"case_id": case_id, "dump_path": dump_path, "work_dir": work_dir, "enrichments": {}}
    finally:
        session.close()


# ── Legacy full-pipeline dispatch (kept for reference, no longer used) ─────────

def _plugin_phase_legacy(triage_result: dict) -> dict:
    """Previously used in automatic pipeline. Kept here in case needed."""
    case_id = triage_result["case_id"]
    os_type = triage_result["os_type"]
    dump_path = triage_result["dump_path"]
    work_dir = triage_result["work_dir"]

    plugins = get_plugins_for_os(os_type)
    results = []
    for spec in plugins:
        result = run_plugin_task.run(spec.name, case_id, dump_path, work_dir)
        results.append(result)

    return {"case_id": case_id, "dump_path": dump_path, "work_dir": work_dir, "plugin_results": results}
