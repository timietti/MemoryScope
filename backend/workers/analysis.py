# backend/workers/analysis.py
"""
Celery tasks for the memory analysis pipeline.

Automatic pipeline (triggered on case submit):
  upload_complete
      → triage_task            (OS detection)
      → plugin_group           (parallel plugin execution)
      → notify_complete        (WebSocket event)

Manual triggers (analyst-initiated):
  dispatch_enrich       → manual_enrich_task   (IOC extraction + hashlookup + VT)
  dispatch_ai_analysis  → _enrich_for_ai       (IOC extraction + hashlookup + VT)
                        → ai_analysis_task      (LLM agent → report)
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import UUID

from celery import chord, chain, group
from celery.exceptions import SoftTimeLimitExceeded
from celery.utils.log import get_task_logger

from .celery_app import celery_app
from backend.config import settings
from backend.core.plugins.registry import get_plugins_for_os, get_plugin
from backend.core.plugins.runner import (
    run_plugin, run_os_detection,
    prepare_work_dir, cleanup_work_dir,
)
from backend.core.storage import download_dump, try_download_file, get_storage_client
from backend.utils.enrichment import enrich_iocs
from backend.utils.hashlookup import lookup_hashes
from backend.utils.notifications import publish_case_event

logger = get_task_logger(__name__)


# ── Storage helpers ───────────────────────────────────────────────────────────

_COMPANION_EXTENSIONS = ('.vmss', '.vmsn')


def _get_dump_path(storage_key: str, work_dir) -> str:
    """Derive the local dump file path from the storage key, preserving extension."""
    ext = Path(storage_key).suffix or '.raw'
    return str(Path(work_dir) / f"dump{ext}")


def _download_companions(storage_key: str, work_dir) -> None:
    """
    For VMEM dumps, download any companion files (.vmss/.vmsn) stored alongside
    the primary dump in object storage into the same working directory.
    Volatility3 expects the companion to share the same base name as the VMEM file.
    """
    if Path(storage_key).suffix.lower() != '.vmem':
        return
    base_key = storage_key.rsplit('.', 1)[0]   # strip .vmem
    dump_base = str(Path(work_dir) / "dump")   # local base path
    for ext in _COMPANION_EXTENSIONS:
        companion_key = base_key + ext
        companion_path = dump_base + ext
        found = try_download_file(companion_key, companion_path)
        if found:
            logger.info("Downloaded companion file %s", companion_path)


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
    soft_time_limit=settings.PLUGIN_TIMEOUT_SECONDS * 2 + 30,
    time_limit=settings.PLUGIN_TIMEOUT_SECONDS * 2 + 60,  # two detection probes + overhead
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
        dump_path = _get_dump_path(case.storage_key, work_dir)
        download_dump(case.storage_key, dump_path)
        logger.info("Dump downloaded to %s (%d bytes)", dump_path, os.path.getsize(dump_path))

        # Download companion files (e.g. .vmss/.vmsn for VMEM dumps)
        _download_companions(case.storage_key, work_dir)

        # Detect OS
        os_type, os_detail = asyncio.run(run_os_detection(dump_path, work_dir))

        # Allow analyst OS hint to override if detection failed
        if os_type == "unknown" and case.os_hint:
            os_type = case.os_hint
            os_detail = f"Manual override: {case.os_hint}"
            logger.warning("OS detection failed, using analyst hint: %s", os_type)

        # For Linux: hold in building_symbols until the ISF is ready.
        # For all other OSes: go straight to triage_complete.
        building_linux = str(os_type).lower() == "linux" and os_detail
        next_status = CaseStatus.building_symbols if building_linux else CaseStatus.triage_complete

        _update_case(session, case_id,
                     detected_os=os_type,
                     detected_os_detail=os_detail,
                     status=next_status)
        publish_case_event(case_id, "os_detected", {"os": os_type, "detail": os_detail})
        publish_case_event(case_id, "status_change", {"status": next_status.value})

        # Create PluginRun records for all applicable plugins so the UI knows what's available
        _create_plugin_run_records(session, case_id, os_type)

        # For Linux dumps: kick off symbol table build; status advances to
        # triage_complete inside build_linux_symbols_task when done (or on failure).
        if building_linux:
            logger.info("Dispatching Linux symbol build for case %s", case_id)
            build_linux_symbols_task.delay(case_id, os_detail, case.storage_key)

        # Dispatch strings extraction NOW — after Volatility3 has finished and
        # released the dump from memory.  Doing this here (rather than in parallel
        # with triage at submit time) prevents both tasks from downloading and
        # mmapping the same large dump simultaneously.
        priority = getattr(case, "priority", 2)
        dispatch_strings(case_id, case.storage_key, priority=priority)
        logger.info("Dispatched strings extraction for case %s", case_id)

        # NOTE: Pipeline stops here. The analyst selects plugins manually via the UI.
        return {
            "case_id": case_id,
            "os_type": os_type,
            "dump_path": dump_path,
            "work_dir": str(work_dir),
        }

    except SoftTimeLimitExceeded:
        logger.error("Triage timed out for case %s", case_id)
        from backend.db.models.models import CaseStatus
        _update_case(session, case_id, status=CaseStatus.failed, error_message="Triage timed out")
        publish_case_event(case_id, "error", {"message": "Triage timed out", "stage": "triage"})
        raise
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
    from sqlalchemy.dialects.postgresql import insert as pg_insert

    plugins = get_plugins_for_os(os_type)
    if not plugins:
        return

    # INSERT ... ON CONFLICT DO NOTHING is atomic — safe on retries and
    # concurrent runs without any pre-check that could have visibility issues.
    stmt = pg_insert(PluginRun).values([
        {
            "case_id": case_id,
            "plugin_name": spec.name,
            "plugin_domain": spec.domain,
            "status": PluginStatus.pending,
        }
        for spec in plugins
    ]).on_conflict_do_nothing(index_elements=["case_id", "plugin_name"])

    result = session.execute(stmt)
    session.commit()
    logger.info(
        "Plugin run records for %s: %d inserted (duplicates silently skipped)",
        os_type, result.rowcount,
    )


# ── Task 1b: Linux/macOS Symbol Table Builder ─────────────────────────────────

# Strings in Volatility3 stderr that indicate a symbol table was NOT found
_VOL_SYMBOL_ERRORS = (
    "No symbol table",
    "Unable to find",
    "unsatisfied requirement",
    "MissingModuleException",
    "symbol table could not",
)


def _try_vol_pslist(
    dump_path: str,
    work_dir,
    os_type: str,
    remote_isf_url: str | None = None,
) -> bool:
    """
    Run vol.py linux.pslist (or mac.pslist) as a quick symbol-table probe.

    Returns True if Volatility exits cleanly with a matching symbol table,
    False if it fails or no symbol table was found.

    Args:
        dump_path:      Local path to the memory dump.
        work_dir:       Working directory (used for the vol log file).
        os_type:        'linux' or 'macos'
        remote_isf_url: If set, passed as --remote-isf-url so Volatility
                        downloads the ISF from an online banner index.
    """
    import subprocess as _sp

    plugin = "linux.pslist" if os_type == "linux" else "mac.pslist"
    cmd = ["python3", settings.VOLATILITY_PATH, "-r", "json"]
    if remote_isf_url:
        cmd += ["--remote-isf-url", remote_isf_url]
    if settings.SYMBOL_CACHE_PATH:
        cmd += ["--symbol-dirs", settings.SYMBOL_CACHE_PATH]
    cmd += ["-f", dump_path, plugin]

    label = remote_isf_url or "local cache"
    logger.info("Symbol probe [%s]: %s", label, " ".join(cmd))

    try:
        result = _sp.run(
            cmd,
            capture_output=True,
            timeout=120,
            cwd=str(work_dir),
        )
    except _sp.TimeoutExpired:
        logger.warning("Symbol probe timed out [%s]", label)
        return False
    except Exception as exc:
        logger.warning("Symbol probe error [%s]: %s", label, exc)
        return False

    stderr = result.stderr.decode(errors="replace")
    if result.returncode != 0:
        logger.debug("Symbol probe failed (rc=%d) [%s]: %s", result.returncode, label, stderr[:300])
        return False
    if any(err in stderr for err in _VOL_SYMBOL_ERRORS):
        logger.debug("Symbol probe: symbol error in stderr [%s]: %s", label, stderr[:300])
        return False

    logger.info("Symbol probe succeeded [%s]", label)
    return True


@celery_app.task(
    name="workers.build_linux_symbols",
    bind=True,
    max_retries=1,
    acks_late=True,
    time_limit=3600,  # 1 hour — large ddeb + dwarf2json can be slow
)
def build_linux_symbols_task(self, case_id: str, banner: str, storage_key: str) -> dict:
    """
    Ensure a matching Volatility3 symbol table exists for a Linux/macOS dump.

    Waterfall (stops at first success):
      1. Probe vol.py against local SYMBOL_CACHE_PATH (already cached?).
      2. Try each REMOTE_ISF_URL — Volatility downloads + caches the ISF.
      3. Build from source: Launchpad → dpkg-deb → dwarf2json (Linux/Ubuntu only).

    In all outcomes the case is advanced to triage_complete so the analyst
    is never permanently blocked.
    """
    from backend.core.symbols.linux_builder import (
        build_debian_symbols, build_fedora_symbols, build_rhel_symbols,
        build_symbols_via_debuginfod, build_ubuntu_symbols,
        parse_debian_banner, parse_fedora_banner, parse_rhel_banner,
        parse_ubuntu_banner,
    )
    from backend.db.models.models import CaseStatus

    logger.info("Symbol resolution started for case %s", case_id)
    session = _get_db_session()

    def _finish(result: dict) -> dict:
        """Advance the case to triage_complete and return result dict."""
        kernel = result.get("kernel", "unknown")
        _update_case(session, case_id, status=CaseStatus.triage_complete)
        session.close()
        publish_case_event(case_id, "symbols_ready", {
            "kernel": kernel,
            "isf_path": result.get("isf_path"),
            **({"warning": result["warning"]} if "warning" in result else {}),
        })
        publish_case_event(case_id, "status_change", {"status": "triage_complete"})
        return {"case_id": case_id, **result}

    # Detect OS from banner (needed for pslist command choice)
    ubuntu_info = parse_ubuntu_banner(banner)
    debian_info = parse_debian_banner(banner) if ubuntu_info is None else None
    fedora_info = parse_fedora_banner(banner) if ubuntu_info is None and debian_info is None else None
    rhel_info   = parse_rhel_banner(banner)   if ubuntu_info is None and debian_info is None and fedora_info is None else None
    info = ubuntu_info or debian_info or fedora_info or rhel_info
    os_type = "linux"  # default; mac would need a different banner parser

    # Ensure dump is on disk — triage may have cleaned the work_dir already
    work_dir = prepare_work_dir(case_id)
    dump_path = _get_dump_path(storage_key, work_dir)
    if not os.path.exists(dump_path):
        logger.info("Dump not on disk, re-downloading for symbol probe")
        download_dump(storage_key, dump_path)
        _download_companions(storage_key, work_dir)

    # ── Step 1: Check local symbol cache ──────────────────────────────────────
    logger.info("Step 1: probing local symbol cache for case %s", case_id)
    if _try_vol_pslist(dump_path, work_dir, os_type):
        logger.info("Local symbol table found for case %s — skipping build", case_id)
        return _finish({"status": "cached", "kernel": info.version_short if info else "unknown"})

    # ── Step 2: Try remote ISF repositories ───────────────────────────────────
    for i, url in enumerate(settings.REMOTE_ISF_URLS, start=1):
        logger.info("Step 2.%d: trying remote ISF URL for case %s: %s", i, case_id, url)
        if _try_vol_pslist(dump_path, work_dir, os_type, remote_isf_url=url):
            logger.info("Remote ISF matched for case %s (source %d)", case_id, i)
            return _finish({"status": "remote_isf", "kernel": info.version_short if info else "unknown", "source": url})

    # ── Step 2.5: Debuginfod fallback ─────────────────────────────────────────
    # Tries to fetch the debuginfo ELF by build-ID before downloading a full
    # distro debug package.  Works for any distro and is much lighter-weight.
    logger.info("Step 2.5: trying debuginfod fallback for case %s", case_id)
    try:
        isf_path = build_symbols_via_debuginfod(Path(dump_path), banner)
    except Exception:
        logger.exception("debuginfod fallback raised for case %s — continuing", case_id)
        isf_path = None
    if isf_path is not None:
        kernel = info.version_short if info else "unknown"
        logger.info("debuginfod produced ISF for case %s: %s", case_id, isf_path)
        return _finish({"status": "ok", "kernel": kernel, "isf_path": str(isf_path)})

    # ── Step 3: Build from source ─────────────────────────────────────────────
    if info is None:
        logger.warning(
            "No symbol table found and banner is not a supported distro — cannot build for case %s. "
            "Analyst will need to upload a custom symbol table.",
            case_id,
        )
        return _finish({"status": "failed", "kernel": "unknown", "warning": "no_builder_no_remote"})

    logger.info("Step 3: building symbol table from source for case %s (kernel %s)", case_id, info.version_short)
    try:
        if ubuntu_info is not None:
            isf_path = build_ubuntu_symbols(banner)
        elif debian_info is not None:
            isf_path = build_debian_symbols(banner)
        elif fedora_info is not None:
            isf_path = build_fedora_symbols(banner)
        else:
            isf_path = build_rhel_symbols(banner)
    except Exception as exc:
        logger.exception("Symbol build failed for case %s", case_id)
        if self.request.retries < self.max_retries:
            session.close()
            raise self.retry(exc=exc, countdown=60)
        logger.warning("Symbol build retries exhausted for case %s — advancing to triage_complete", case_id)
        return _finish({"status": "failed", "kernel": info.version_short, "warning": "build_failed"})

    if isf_path is None:
        logger.warning("Symbol build returned None for case %s (%s)", case_id, info.version_short)
        return _finish({"status": "failed", "kernel": info.version_short, "warning": "not_found"})

    logger.info("Symbol table built for case %s: %s", case_id, isf_path)
    return _finish({"status": "ok", "kernel": info.version_short, "isf_path": str(isf_path)})


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


def _is_valid_ip(ip: str) -> bool:
    """Return True only if all four octets are in 0–255."""
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


# Private / non-routable prefixes not worth enriching
_SKIP_PREFIXES = (
    "0.",
    "10.",
    "127.",
    "169.254.",
    "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.",
    "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.",
    "224.", "225.", "226.", "227.", "228.", "229.",
    "230.", "231.", "232.", "233.", "234.", "235.",
    "236.", "237.", "238.", "239.",   # multicast
    "240.", "241.", "242.", "243.", "244.", "245.",
    "246.", "247.", "248.", "249.", "250.", "251.",
    "252.", "253.", "254.", "255.",   # reserved / broadcast
)


import re as _re

# Field key names that are likely to hold a file hash value.
# Matched case-insensitively as a full word component.
_HASH_KEY_RE = _re.compile(
    r'\b(sha256|sha1|sha|md5|hash|checksum|digest|imphash|pesha)\b',
    _re.IGNORECASE,
)

# Field key names that look hash-like but are NOT file hashes — skip these.
# NT/LM hashes are Windows credential (NTLM) hashes; VT has no endpoint for them.
# "offset", "base", "ptr", "address" are memory/registry addresses stored as hex.
# bootcode_md5 / full_mbr_md5 are MD5s of MBR boot-sector bytes, not PE files.
_NON_FILE_HASH_KEY_RE = _re.compile(
    r'\b(lm_hash|lmhash|nt_hash|nthash|offset|base|ptr|address|handle|hive_offset|id'
    r'|bootcode_md5|full_mbr_md5)\b',
    _re.IGNORECASE,
)


def _is_hash_field(key: str) -> bool:
    """Return True if the field key name suggests the value is a file hash."""
    return bool(_HASH_KEY_RE.search(key)) and not bool(_NON_FILE_HASH_KEY_RE.search(key))


# Plugins that should never contribute IOCs.
# windows.mbrscan: scans every 512-byte MBR-like region in memory — produces
# thousands of rows whose "Bootcode MD5" / "Full MBR MD5" fields are boot-sector
# checksums (not PE file hashes) and whose disasm text generates false-positive IPs.
_NO_IOC_PLUGINS: frozenset[str] = frozenset({
    "windows.mbrscan",
})


def _extract_iocs_from_outputs(plugin_outputs: dict) -> list[dict]:
    """Pull IPs and file hashes from normalised plugin output.

    IPs: extracted from all string values in every row — already validated by
    _is_valid_ip so garbage strings are rejected.

    Hashes: extracted ONLY from dict values whose field key name semantically
    indicates a file hash (sha256, md5, sha1, imphash, …).  Fields like
    lm_hash / nt_hash (Windows credential hashes), offset, base, and address
    (memory / registry addresses) are explicitly excluded regardless of whether
    their value matches the hex-length pattern.
    """
    iocs = []
    ip_re = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    bare_hash_re = _re.compile(r"^[0-9a-fA-F]{32,64}$")
    hash_in_str_re = _re.compile(r"\b[0-9a-fA-F]{32,64}\b")

    for plugin_name, output in plugin_outputs.items():
        if plugin_name in _NO_IOC_PLUGINS:
            continue
        rows = output if isinstance(output, list) else output.get("rows", []) if isinstance(output, dict) else []
        for row in rows:
            if not isinstance(row, dict):
                # For non-dict rows fall back to scanning the string, but skip hashes
                # (too noisy without field-name context).
                row_str = str(row)
                for ip in ip_re.findall(row_str):
                    if _is_valid_ip(ip) and not ip.startswith(_SKIP_PREFIXES):
                        iocs.append({"type": "ip", "value": ip, "source": plugin_name})
                continue

            for key, val in row.items():
                if val is None:
                    continue
                val_str = str(val)

                # ── IPs: scan every string field ─────────────────────────────
                for ip in ip_re.findall(val_str):
                    if _is_valid_ip(ip) and not ip.startswith(_SKIP_PREFIXES):
                        iocs.append({"type": "ip", "value": ip, "source": plugin_name})

                # ── Hashes: only from fields whose name indicates a file hash ─
                if not _is_hash_field(key):
                    continue

                # Only extract file hashes from rows that are explicitly flagged
                # suspicious. Rows from parsers that emit is_suspicious (shimcache,
                # amcache, dlllist, etc.) are safe to filter this way. Rows from
                # parsers that never set the field (row.get returns None) are
                # skipped too — without suspicious context a 32/40/64-char hex
                # string in a hash field is too noisy to be worth a VT lookup.
                if not row.get("is_suspicious"):
                    continue

                # Prefer the whole value if it is itself a bare hex hash
                stripped = val_str.strip()
                candidates = (
                    [stripped] if bare_hash_re.match(stripped)
                    else hash_in_str_re.findall(val_str)
                )
                for h in candidates:
                    ioc_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h))
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
    from backend.utils.db_settings import load_db_settings_sync
    load_db_settings_sync()

    case_id = enrichment_result["case_id"]
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

        # ── Incremental analysis: detect prior report ─────────────────────────
        # If a prior active report exists, only the plugin outputs completed
        # AFTER that report was generated are truly new evidence. The agent
        # receives the prior report as context and only re-analyses new data,
        # avoiding re-spending tokens on evidence it has already reasoned about.
        prior_report_row = session.query(Report).filter(
            Report.case_id == case_id,
            Report.superseded_at.is_(None),
        ).first()

        # Load all plugin outputs (with parsed output available)
        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()

        prior_context: dict | None = None
        if prior_report_row is not None:
            cutoff = prior_report_row.generated_at
            new_runs = [r for r in runs if r.completed_at is None or r.completed_at > cutoff]
            seen_runs = [r for r in runs if r.completed_at is not None and r.completed_at <= cutoff]

            if new_runs:
                logger.info(
                    "Incremental analysis for case %s: %d new plugin(s) since prior report, "
                    "%d already analysed — reusing prior report as context",
                    case_id, len(new_runs), len(seen_runs),
                )
                plugin_outputs = {r.plugin_name: r.parsed_output for r in new_runs}
                # Build prior-report context dict for the agent
                from backend.db.models.models import IOC as IOCModel
                prior_iocs = session.query(IOCModel).filter(
                    IOCModel.case_id == case_id,
                    IOCModel.report_id == prior_report_row.id,
                ).all()
                prior_context = {
                    "verdict": prior_report_row.verdict.value if hasattr(prior_report_row.verdict, "value") else str(prior_report_row.verdict),
                    "confidence": prior_report_row.confidence,
                    "verdict_reasoning": prior_report_row.verdict_reasoning,
                    "executive_summary": prior_report_row.executive_summary,
                    "technical_narrative": prior_report_row.technical_narrative,
                    "mitre_ttps": prior_report_row.mitre_ttps or [],
                    "iocs": [
                        {
                            "ioc_type": i.ioc_type.value if hasattr(i.ioc_type, "value") else str(i.ioc_type),
                            "value": i.value,
                            "severity": i.severity.value if hasattr(i.severity, "value") else str(i.severity),
                            "description": i.description or "",
                        }
                        for i in prior_iocs
                    ],
                    "plugins_analysed": [r.plugin_name for r in seen_runs],
                    "generated_at": cutoff.isoformat(),
                }
            else:
                # No new plugins since last report — full re-analysis
                logger.info(
                    "No new plugin outputs since prior report for case %s — full re-analysis",
                    case_id,
                )
                plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}
        else:
            plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}

        # Load KB articles attached to this case as analyst context
        from backend.db.models.models import KBArticle, CaseKBArticle
        kb_rows = (
            session.query(KBArticle)
            .join(CaseKBArticle, CaseKBArticle.article_id == KBArticle.id)
            .filter(CaseKBArticle.case_id == case_id)
            .all()
        )
        analyst_notes = [{"title": a.title, "content": a.content} for a in kb_rows]
        if analyst_notes:
            logger.info("Injecting %d KB article(s) into AI context for case %s", len(analyst_notes), case_id)

        logger.info(
            "Starting AI agent for case %s with %d plugin outputs (%s)",
            case_id, len(plugin_outputs),
            "incremental" if prior_context else "full",
        )

        # Run the agent
        report_data = asyncio.run(run_agent(
            case_id=case_id,
            detected_os=case.detected_os,
            plugin_outputs=plugin_outputs,
            ioc_enrichments=enrichments,
            analyst_notes=analyst_notes,
            prior_report=prior_context,
        ))

        logger.info("Agent complete. Verdict: %s (%d confidence)", report_data.verdict, report_data.confidence)

        # Supersede any active report (preserves token_usage history in stats).
        # IOCs are NOT deleted — _persist_iocs upserts them so manual enrichment
        # data is preserved and severity can only increase.
        now = datetime.now(timezone.utc)
        session.query(Report).filter(
            Report.case_id == case_id,
            Report.superseded_at.is_(None),
        ).update({"superseded_at": now}, synchronize_session=False)

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


def _persist_raw_iocs(session, case_id: str, raw_iocs: list, enrichments: dict) -> None:
    """
    Upsert raw extracted IOCs (pre-AI) so they appear in the UI immediately after
    enrichment. Rows with no VT hit are still created with severity=info.
    When AI analysis later calls _persist_iocs, ON CONFLICT DO UPDATE fills in
    the AI-generated severity, description, and ai_context.
    """
    from backend.db.models.models import IOC, IOCType, Severity
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    for raw in raw_iocs:
        enrichment = enrichments.get(raw["value"], {})
        known_good      = enrichment.get("known_good", False)
        known_malicious = enrichment.get("known_malicious", False)

        if known_good or known_malicious:
            severity    = Severity.high if known_malicious else Severity.info
            description = _hl_description(enrichment)
        else:
            vt = enrichment
            positives = vt.get("positives", 0) or 0
            # Derive a basic severity from VT positives until AI assigns one
            if positives >= 10:
                severity = Severity.high
            elif positives >= 3:
                severity = Severity.medium
            elif positives >= 1:
                severity = Severity.low
            else:
                severity = Severity.info
            description = None

        existing = session.query(IOC).filter_by(
            case_id=case_id,
            ioc_type=IOCType(raw["type"]),
            value=raw["value"],
        ).first()

        hl_hit = known_good or known_malicious

        if existing:
            if hl_hit:
                existing.description = description
                if not existing.report_id:
                    existing.severity = severity
            else:
                vt = enrichment
                # Update VT data on re-enrichment
                existing.vt_positives = vt.get("positives")
                existing.vt_total = vt.get("total")
                existing.vt_permalink = vt.get("permalink")
                existing.threat_names = vt.get("threat_names", [])
                existing.vt_checked_at = now
                if not existing.report_id:
                    # Only overwrite severity if AI hasn't set it yet
                    existing.severity = severity
        else:
            vt = {} if hl_hit else enrichment
            ioc = IOC(
                case_id=case_id,
                ioc_type=IOCType(raw["type"]),
                value=raw["value"],
                severity=severity,
                description=description,
                source_plugin=raw.get("source"),
                vt_positives=vt.get("positives"),
                vt_total=vt.get("total"),
                vt_permalink=vt.get("permalink"),
                threat_names=vt.get("threat_names", []),
                vt_checked_at=now if vt.get("positives") is not None else None,
            )
            session.add(ioc)


def _hl_description(hl: dict) -> str:
    """Build a human-readable description from a hashlookup result."""
    if hl.get("known_malicious"):
        prefix = "Known-malicious file (CIRCL hashlookup"
        trust = hl.get("hl_trust")
        prefix += f", trust score: {trust})." if trust is not None else ")."
    else:
        prefix = "Known-good file (CIRCL hashlookup)."
    parts = [prefix]
    if hl.get("hl_filename"):
        parts.append(f"Filename: {hl['hl_filename']}.")
    if hl.get("hl_mimetype"):
        parts.append(f"MIME type: {hl['hl_mimetype']}.")
    if hl.get("hl_size") is not None:
        parts.append(f"Size: {hl['hl_size']} bytes.")
    return " ".join(parts)


_SEVERITY_RANK: dict[str, int] = {
    "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}


def _severity_value(sev) -> str:
    """Return the string value of a severity, whether it's an enum or a string."""
    return sev.value if hasattr(sev, "value") else str(sev)


def _persist_iocs(session, case_id: str, report_id: str, iocs: list, enrichments: dict) -> None:
    """
    Upsert AI-identified IOCs into the database.

    - Existing IOCs (matched by case_id + ioc_type + value) are updated:
        * severity is promoted if the AI rates it higher (never downgraded)
        * AI fields (report_id, description, ai_context) are always written
        * VT fields are refreshed if the enrichment run produced data
    - New IOCs are inserted.
    """
    from backend.db.models.models import IOC, IOCType, Severity
    from datetime import datetime, timezone

    now = datetime.now(timezone.utc)

    for ioc_entry in iocs:
        enrichment      = enrichments.get(ioc_entry.value, {})
        known_good      = enrichment.get("known_good", False)
        known_malicious = enrichment.get("known_malicious", False)
        vt = {} if (known_good or known_malicious) else enrichment
        ai_severity = Severity(ioc_entry.severity)

        # For hashlookup hits prepend the classification note to the AI description
        # so analysts see both the origin and the AI's reasoning.
        description = ioc_entry.description
        if known_good or known_malicious:
            hl_note = _hl_description(enrichment)
            description = f"{hl_note}\n\n{description}" if description else hl_note

        existing = session.query(IOC).filter_by(
            case_id=case_id,
            ioc_type=IOCType(ioc_entry.ioc_type),
            value=ioc_entry.value,
        ).first()

        if existing:
            # Promote severity if the AI's rating is higher; never downgrade
            existing_rank = _SEVERITY_RANK.get(_severity_value(existing.severity), 0)
            ai_rank      = _SEVERITY_RANK.get(_severity_value(ai_severity), 0)
            if ai_rank > existing_rank:
                existing.severity = ai_severity

            # Always apply AI-provided context
            existing.report_id   = report_id
            existing.description = description
            existing.ai_context  = ioc_entry.description
            if ioc_entry.source_plugin:
                existing.source_plugin = ioc_entry.source_plugin
            if ioc_entry.source_pid:
                existing.source_pid = ioc_entry.source_pid

            # Refresh VT fields only when VT data is present (not for known-good)
            if vt:
                existing.vt_positives  = vt.get("positives")
                existing.vt_total      = vt.get("total")
                existing.vt_permalink  = vt.get("permalink")
                existing.threat_names  = vt.get("threat_names", [])
                existing.vt_checked_at = now
        else:
            session.add(IOC(
                case_id=case_id,
                report_id=report_id,
                ioc_type=IOCType(ioc_entry.ioc_type),
                value=ioc_entry.value,
                severity=ai_severity,
                description=description,
                source_plugin=ioc_entry.source_plugin,
                source_pid=ioc_entry.source_pid,
                vt_positives=vt.get("positives"),
                vt_total=vt.get("total"),
                vt_permalink=vt.get("permalink"),
                threat_names=vt.get("threat_names", []),
                ai_context=ioc_entry.description,
                vt_checked_at=now if vt else None,
            ))


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
        dump_path = _get_dump_path(case.storage_key, work_dir)

        # Re-download dump and companions if cleaned up or this is a fresh worker node
        if not os.path.exists(dump_path):
            logger.info("Dump not found locally, downloading for case %s", case_id)
            download_dump(case.storage_key, dump_path)
            _download_companions(case.storage_key, work_dir)

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


# ── Shared enrichment helper ─────────────────────────────────────────────────

def _run_ioc_enrichment(session, case_id: str, plugin_outputs: dict) -> tuple[list, dict]:
    """Extract IOCs, run hashlookup + VT, persist raw results.

    Returns (raw_iocs, enrichments) so callers can use them in return values,
    logging, and status updates.
    """
    raw_iocs = _extract_iocs_from_outputs(plugin_outputs)
    logger.info("Extracted %d unique IOCs for enrichment", len(raw_iocs))

    hash_iocs = [i for i in raw_iocs if i["type"] in ("md5", "sha1", "sha256")]
    hl_results: dict = {}
    if hash_iocs:
        hl_results = asyncio.run(lookup_hashes(hash_iocs))

    # Only known-good hashes skip VT; known-malicious still go to VT for full detail
    known_good_values = {v for v, e in hl_results.items() if e.get("known_good")}

    vt_iocs = [i for i in raw_iocs if i["value"] not in known_good_values]
    enrichments: dict = {}
    if settings.VIRUSTOTAL_API_KEY and vt_iocs:
        enrichments = asyncio.run(enrich_iocs(vt_iocs))

    enrichments.update(hl_results)

    _persist_raw_iocs(session, case_id, raw_iocs, enrichments)
    return raw_iocs, enrichments


# ── Task: Manual Enrichment ───────────────────────────────────────────────────

@celery_app.task(name="workers.manual_enrich", acks_late=True, time_limit=900)
def manual_enrich_task(case_id: str) -> dict:
    """Standalone enrichment task triggered manually by the analyst."""
    from backend.utils.db_settings import load_db_settings_sync
    load_db_settings_sync()
    session = _get_db_session()
    prev_status = None
    try:
        from backend.db.models.models import Case, CaseStatus, PluginRun
        logger.info("Starting manual IOC enrichment for case %s", case_id)

        # Remember the current status so we can restore it when done.
        case = session.query(Case).filter(Case.id == case_id).first()
        prev_status = case.status if case else CaseStatus.complete
        _update_case(session, case_id, status=CaseStatus.enriching)
        publish_case_event(case_id, "status_change", {"status": "enriching"})
        publish_case_event(case_id, "enrichment_started", {})

        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()
        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}

        raw_iocs, enrichments = _run_ioc_enrichment(session, case_id, plugin_outputs)

        _update_case(session, case_id,
                     status=prev_status,
                     vt_enriched_at=datetime.now(timezone.utc))
        session.commit()

        vt_enriched = sum(1 for v in enrichments.values()
                          if not v.get("known_good") and v.get("status") != "not_found")
        logger.info("VT enrichment complete: %d/%d IOCs enriched",
                    vt_enriched, len(raw_iocs))
        publish_case_event(case_id, "status_change", {"status": prev_status.value if hasattr(prev_status, "value") else str(prev_status)})
        publish_case_event(case_id, "enrichment_complete", {"ioc_count": len(enrichments)})
        return {"case_id": case_id, "enrichments": enrichments}

    except Exception as exc:
        logger.exception("Manual enrichment failed for case %s", case_id)
        session.rollback()
        if prev_status is not None:
            try:
                _update_case(session, case_id, status=prev_status)
                session.commit()
                publish_case_event(case_id, "status_change", {
                    "status": prev_status.value if hasattr(prev_status, "value") else str(prev_status)
                })
            except Exception:
                logger.exception("Failed to restore status for case %s", case_id)
        return {"case_id": case_id, "enrichments": {}}
    finally:
        session.close()


# ── Dispatch Helpers ──────────────────────────────────────────────────────────

# Case priority (1–4) → Celery/Redis priority (0–9, lower = higher priority)
_PRIORITY_MAP = {1: 9, 2: 6, 3: 3, 4: 0}


def _celery_priority(case_priority: int) -> int:
    return _PRIORITY_MAP.get(case_priority, 6)


# ── Dispatch Functions ────────────────────────────────────────────────────────

def dispatch_triage(case_id: str, priority: int = 2) -> str:
    """Dispatch triage only. Pipeline stops at triage_complete."""
    task = triage_task.apply_async(args=[case_id], priority=_celery_priority(priority))
    return task.id


def dispatch_selected_plugins(case_id: str, plugin_names: list[str], priority: int = 2) -> str:
    """Dispatch selected plugins for manual plugin run."""
    task = run_selected_plugins_task.apply_async(
        args=[case_id, plugin_names], priority=_celery_priority(priority)
    )
    return task.id


def dispatch_enrich(case_id: str, priority: int = 2) -> str:
    """Dispatch standalone enrichment."""
    task = manual_enrich_task.apply_async(args=[case_id], priority=_celery_priority(priority))
    return task.id


def dispatch_ai_analysis(case_id: str, priority: int = 2) -> str:
    """Dispatch enrichment → AI analysis chain."""
    work_dir = prepare_work_dir(case_id)
    task = chain(
        _enrich_for_ai.s(case_id, str(work_dir)),
        ai_analysis_task.s(),
    ).apply_async(priority=_celery_priority(priority))
    return task.id


@celery_app.task(name="workers.enrich_for_ai", acks_late=True, time_limit=900)
def _enrich_for_ai(case_id: str, work_dir: str) -> dict:
    """Enrich IOCs and return result dict for ai_analysis_task."""
    from backend.utils.db_settings import load_db_settings_sync
    load_db_settings_sync()

    session = _get_db_session()
    try:
        from backend.db.models.models import CaseStatus, PluginRun
        _update_case(session, case_id, status=CaseStatus.enriching)
        publish_case_event(case_id, "status_change", {"status": "enriching"})

        runs = session.query(PluginRun).filter(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None)
        ).all()
        plugin_outputs = {r.plugin_name: r.parsed_output for r in runs}

        _, enrichments = _run_ioc_enrichment(session, case_id, plugin_outputs)

        _update_case(session, case_id, vt_enriched_at=datetime.now(timezone.utc))
        session.commit()

        publish_case_event(case_id, "enrichment_complete", {"ioc_count": len(enrichments)})
        return {"case_id": case_id, "work_dir": work_dir, "enrichments": enrichments}
    except Exception as exc:
        logger.exception("Enrichment step failed for case %s", case_id)
        session.rollback()
        return {"case_id": case_id, "work_dir": work_dir, "enrichments": {}}
    finally:
        session.close()


# ── Strings Extraction ───────────────────────────────────────────────────────

@celery_app.task(
    name="workers.strings",
    bind=True,
    acks_late=True,
    # No hard cap on time — large dumps can take many minutes.
    # Set a generous soft limit; the task handles SoftTimeLimitExceeded.
    soft_time_limit=3600,
    time_limit=3660,
)
def strings_task(self, case_id: str, storage_key: str) -> dict:
    """
    Download the memory dump, run parallel strings extraction, compress the
    output, upload to MinIO, and update the StringsRun record.

    Dispatched immediately alongside triage_task so strings extraction runs
    in parallel with OS detection.
    """
    from backend.db.models.models import StringsRun, PluginStatus
    from backend.core.strings_extractor import extract_strings
    from backend.core.storage import upload_bytes_sync

    session = _get_db_session()
    work_dir = None
    try:
        # Locate the StringsRun record created by the API
        sr = session.query(StringsRun).filter(StringsRun.case_id == case_id).first()
        if not sr:
            logger.error("strings_task: no StringsRun record for case %s", case_id)
            return {"case_id": case_id}

        sr.status = PluginStatus.running
        sr.started_at = datetime.now(timezone.utc)
        session.commit()

        publish_case_event(case_id, "strings_started", {})

        # Download the dump into a temp directory
        work_dir = prepare_work_dir(case_id)
        dump_path = _get_dump_path(storage_key, work_dir)
        download_dump(storage_key, dump_path)

        # Resolve destination key before extraction
        case_obj = session.query(
            __import__("backend.db.models.models", fromlist=["Case"]).Case
        ).filter_by(id=case_id).first()
        short_id = case_obj.short_id if case_obj else case_id
        strings_key = f"cases/{short_id}/strings.txt.gz"

        # Run parallel extraction — writes directly to a gzip file on disk.
        # No bytes object is returned; peak RAM is sort's 256 MB buffer.
        gz_path = os.path.join(work_dir, "strings.txt.gz")
        line_count = extract_strings(
            dump_path,
            gz_path,
            max_workers=settings.STRINGS_MAX_WORKERS,
        )

        # Stream-upload the gzip file to MinIO — never loads it into RAM.
        from backend.core.storage import upload_fileobj_multipart
        with open(gz_path, "rb") as gz_fh:
            upload_fileobj_multipart(gz_fh, strings_key, settings.S3_BUCKET_DUMPS)
        compressed_size = os.path.getsize(gz_path)

        sr.status = PluginStatus.complete
        sr.storage_key = strings_key
        sr.line_count = line_count
        sr.compressed_size = compressed_size
        sr.completed_at = datetime.now(timezone.utc)
        session.commit()

        publish_case_event(case_id, "strings_complete", {
            "line_count": line_count,
            "compressed_size": compressed_size,
        })
        logger.info(
            "strings_task: case %s — %d lines, %d KB compressed",
            case_id, line_count, compressed_size // 1024,
        )
        return {"case_id": case_id, "line_count": line_count}

    except SoftTimeLimitExceeded:
        logger.error("strings_task: timed out for case %s", case_id)
        if session:
            try:
                sr = session.query(StringsRun).filter(StringsRun.case_id == case_id).first()
                if sr:
                    sr.status = PluginStatus.timeout
                    sr.error_message = "Strings extraction timed out"
                    sr.completed_at = datetime.now(timezone.utc)
                    session.commit()
            except Exception:
                pass
        return {"case_id": case_id}
    except Exception as exc:
        logger.exception("strings_task: failed for case %s", case_id)
        try:
            sr = session.query(StringsRun).filter(StringsRun.case_id == case_id).first()
            if sr:
                sr.status = PluginStatus.failed
                sr.error_message = str(exc)[:1024]
                sr.completed_at = datetime.now(timezone.utc)
                session.commit()
        except Exception:
            pass
        publish_case_event(case_id, "strings_failed", {"error": str(exc)[:256]})
        return {"case_id": case_id}
    finally:
        session.close()
        if work_dir:
            cleanup_work_dir(work_dir)


def dispatch_strings(case_id: str, storage_key: str, priority: int = 2) -> str:
    """Dispatch strings extraction — runs independently of the analysis pipeline."""
    task = strings_task.apply_async(
        args=[case_id, storage_key],
        priority=_celery_priority(priority),
    )
    return task.id


# ── Watch Folder ──────────────────────────────────────────────────────────────

_WATCH_DUMP_EXTS = {'.raw', '.mem', '.dmp', '.vmem', '.lime', '.bin', '.zip'}
_WATCH_LOCK_SUFFIX = '.importing'


def _is_watch_symbol_file(path: Path) -> bool:
    """Return True for .json and .json.xz files (Volatility3 ISF symbol tables)."""
    n = path.name.lower()
    return n.endswith('.json') or n.endswith('.json.xz')


def _watch_generate_short_id() -> str:
    import random
    chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
    return ''.join(random.choices(chars, k=8))


def _watch_hash_file(path: Path) -> str:
    """Stream-hash a file without buffering it in memory."""
    import hashlib
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def _watch_upload_file(path: Path, storage_key: str) -> None:
    """Upload a local file to MinIO by streaming it through boto3."""
    from backend.core.storage import _get_client
    client = _get_client()
    with path.open('rb') as f:
        client.upload_fileobj(f, settings.S3_BUCKET_DUMPS, storage_key)
    logger.info("Watch: uploaded %s (%d bytes) → %s", path.name, path.stat().st_size, storage_key)


def _watch_process_symbol_file(file_path: Path) -> None:
    """
    Move a Volatility3 ISF symbol file (.json / .json.xz) found in the watch
    directory to SYMBOL_CACHE_PATH/uploads/, creating the directory if needed.
    """
    dest_dir = Path(settings.SYMBOL_CACHE_PATH) / 'uploads'
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / file_path.name
    if dest.exists():
        import time as _time
        dest = dest_dir / f"{int(_time.time())}_{file_path.name}"
    file_path.rename(dest)
    logger.info("Watch: symbol file %s → %s", file_path.name, dest)


def _watch_process_file(file_path: Path, session) -> None:
    """
    Import a single dump file from the watch directory as a new Case.
    Deletes the source file after uploading to MinIO (or on duplicate detection).
    """
    from backend.db.models.models import Case, CaseStatus, User, UserRole

    # ── Find the system admin user to assign the case to ──────────────────────
    admin = (
        session.query(User)
        .filter(User.role == UserRole.admin, User.is_active.is_(True))
        .order_by(User.created_at)
        .first()
    )
    if not admin:
        logger.error("Watch: no active admin user found — cannot auto-import %s", file_path.name)
        return

    short_id = _watch_generate_short_id()
    original_filename = file_path.name

    # ── Handle ZIP archives (extract the dump) ────────────────────────────────
    if file_path.suffix.lower() == '.zip':
        import zipfile, io
        with file_path.open('rb') as zf_handle:
            zip_data = zf_handle.read()
        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            dump_entries = [
                e for e in zf.infolist()
                if not e.is_dir() and Path(e.filename).suffix.lower() in (_WATCH_DUMP_EXTS - {'.zip'})
            ]
            if not dump_entries:
                logger.warning("Watch: ZIP %s contains no recognised dump files — skipping", file_path.name)
                return
            entry = max(dump_entries, key=lambda e: e.file_size)
            dump_data = zf.read(entry.filename)
        original_filename = Path(entry.filename).name
        dump_ext = Path(original_filename).suffix.lower() or '.raw'
        storage_key = f"cases/{short_id}/dump{dump_ext}"
        sha256 = __import__('hashlib').sha256(dump_data).hexdigest()
        file_size = len(dump_data)

        existing = session.query(Case).filter(Case.sha256 == sha256).first()
        if existing:
            logger.info("Watch: %s already imported as case %s — removing", file_path.name, existing.short_id)
            file_path.unlink()
            return

        from backend.core.storage import upload_bytes_sync
        upload_bytes_sync(dump_data, storage_key, settings.S3_BUCKET_DUMPS)

    else:
        # ── Direct dump file ──────────────────────────────────────────────────
        dump_ext = file_path.suffix.lower() or '.raw'
        storage_key = f"cases/{short_id}/dump{dump_ext}"
        sha256 = _watch_hash_file(file_path)
        file_size = file_path.stat().st_size

        existing = session.query(Case).filter(Case.sha256 == sha256).first()
        if existing:
            logger.info("Watch: %s already imported as case %s — removing", file_path.name, existing.short_id)
            file_path.unlink()
            return

        _watch_upload_file(file_path, storage_key)

    # ── Create Case record ────────────────────────────────────────────────────
    from datetime import datetime, timezone
    case = Case(
        short_id=short_id,
        name=Path(original_filename).stem,
        priority=2,
        submitted_by=admin.id,
        tags=['watch-folder'],
        original_filename=original_filename,
        file_size_bytes=file_size,
        sha256=sha256,
        storage_key=storage_key,
        status=CaseStatus.queued,
        queued_at=datetime.now(timezone.utc),
    )
    session.add(case)
    session.commit()
    session.refresh(case)
    logger.info("Watch: created case %s (%s) for %s", case.short_id, case.id, original_filename)

    # ── Dispatch triage ───────────────────────────────────────────────────────
    task = triage_task.apply_async(args=[str(case.id)], priority=_celery_priority(2))
    session.query(Case).filter(Case.id == case.id).update(
        {"celery_task_id": task.id, "updated_at": datetime.now(timezone.utc)}
    )
    session.commit()

    # ── Delete source file (already uploaded to MinIO) ────────────────────────
    file_path.unlink()
    logger.info("Watch: deleted %s after import as case %s", file_path.name, case.short_id)


@celery_app.task(
    name="workers.scan_watch_dir",
    acks_late=True,
    time_limit=300,
)
def scan_watch_dir_task() -> dict:
    """
    Periodic task (run by Celery beat) that scans WATCH_DIR for new memory
    dumps and auto-creates cases for them.

    Files are skipped until their mtime is older than WATCH_DIR_STABLE_AGE
    seconds, which prevents picking up files that are still being written.
    Processed files are moved into WATCH_DIR/.processed/ to avoid re-import.
    """
    from backend.utils.db_settings import load_db_settings_sync
    load_db_settings_sync()   # always use the latest DB settings

    if not settings.WATCH_DIR_ENABLED or not settings.WATCH_DIR:
        return {"skipped": True, "reason": "watch dir disabled or not configured"}

    watch_path = Path(settings.WATCH_DIR)
    if not watch_path.exists():
        logger.warning("Watch: configured directory does not exist: %s", watch_path)
        return {"skipped": True, "reason": "directory not found"}

    import time
    now = time.time()
    stable_age = settings.WATCH_DIR_STABLE_AGE

    all_files = [
        f for f in sorted(watch_path.iterdir())
        if f.is_file()
        and not f.name.startswith('.')
        and (now - f.stat().st_mtime) >= stable_age
    ]

    candidates = [f for f in all_files if f.suffix.lower() in _WATCH_DUMP_EXTS]
    symbol_candidates = [f for f in all_files if _is_watch_symbol_file(f)]

    if not candidates and not symbol_candidates:
        return {"processed": 0}

    logger.info(
        "Watch: found %d dump(s), %d symbol file(s) in %s",
        len(candidates), len(symbol_candidates), watch_path,
    )

    processed = 0
    errors = 0

    # ── Symbol files (.json / .json.xz) → SYMBOL_CACHE_PATH/uploads/ ─────────
    for file_path in symbol_candidates:
        lock = file_path.with_suffix(file_path.suffix + _WATCH_LOCK_SUFFIX)
        if lock.exists():
            logger.debug("Watch: %s is already being processed (lock exists)", file_path.name)
            continue
        try:
            lock.touch()
            _watch_process_symbol_file(file_path)
            processed += 1
        except Exception:
            logger.exception("Watch: error processing symbol file %s", file_path.name)
            errors += 1
        finally:
            lock.unlink(missing_ok=True)

    # ── Dump files → new Case ─────────────────────────────────────────────────
    if candidates:
        session = _get_db_session()
        try:
            for file_path in candidates:
                lock = file_path.with_suffix(file_path.suffix + _WATCH_LOCK_SUFFIX)
                if lock.exists():
                    logger.debug("Watch: %s is already being processed (lock exists)", file_path.name)
                    continue
                try:
                    lock.touch()
                    _watch_process_file(file_path, session)
                    processed += 1
                except Exception:
                    logger.exception("Watch: error processing %s", file_path.name)
                    errors += 1
                finally:
                    lock.unlink(missing_ok=True)
        finally:
            session.close()

    logger.info("Watch: scan complete — %d processed, %d errors", processed, errors)
    return {"processed": processed, "errors": errors}


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
