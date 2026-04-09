# backend/api/routers/cases.py
"""
Case management endpoints:
  POST /cases          — upload + submit
  GET  /cases          — list with pagination
  GET  /cases/{id}     — case detail
  GET  /cases/{id}/plugins  — plugin run list
  GET  /cases/{id}/plugins/{plugin} — plugin output
  GET  /cases/{id}/report  — AI report
  DELETE /cases/{id}   — soft delete
"""
from __future__ import annotations
import hashlib
import secrets
import string
from datetime import datetime, timezone
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from backend.db.session import get_db
from backend.db.models.models import Case, CaseStatus, OSType, PluginRun, PluginStatus, Report, IOC, KBArticle, CaseKBArticle, StringsRun
from backend.core.storage import upload_dump_stream, upload_bytes_sync, upload_fileobj_multipart, delete_case_files, download_object_bytes
from botocore.exceptions import ClientError as _S3ClientError
from backend.workers.analysis import dispatch_triage, dispatch_selected_plugins, dispatch_enrich, dispatch_ai_analysis, dispatch_strings, dispatch_run_strings_plugin, STRINGS_PLUGIN_FOR_OS
from backend.utils.notifications import publish_case_event
from backend.schemas.case import (
    CaseCreate, CaseResponse, CaseListResponse,
    PluginRunListItem, PluginRunResponse, ReportResponse,
    StringsRunSchema, StringsSearchResponse,
    RunStringsPluginRequest, RunStringsPluginResponse,
)
from backend.api.dependencies import get_current_user, get_current_admin, require_not_viewer
from backend.config import settings

router = APIRouter(prefix="/cases", tags=["cases"])


# ── Submit a new case ─────────────────────────────────────────────────────────

_DUMP_EXTENSIONS = {'.raw', '.mem', '.dmp', '.vmem', '.lime', '.bin'}
_COMPANION_EXTENSIONS = {'.vmss', '.vmsn'}


def _extract_dump_from_zip(zip_data: bytes) -> tuple[bytes, str, list[tuple[str, bytes]]]:
    """
    Extract the memory dump and optional companion files from a ZIP archive.

    Returns:
        (dump_bytes, dump_filename, [(companion_filename, companion_bytes), ...])

    Raises HTTPException 422 if no recognizable dump file is found.
    """
    import zipfile
    import io
    from pathlib import Path as _Path

    with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
        dump_entries = []
        companion_entries = []
        for info in zf.infolist():
            if info.is_dir():
                continue
            # H-3: check declared uncompressed size before extracting to prevent
            # decompression bombs.  info.file_size is from the ZIP central
            # directory and does not require reading the compressed data.
            if info.file_size > settings.MAX_DUMP_SIZE_BYTES:
                raise HTTPException(
                    413,
                    f"ZIP entry '{_Path(info.filename).name}' declares an "
                    f"uncompressed size of {info.file_size // 1024 ** 3} GB "
                    f"which exceeds the {settings.MAX_DUMP_SIZE_BYTES // 1024 ** 3} GB limit."
                )
            fname = _Path(info.filename).name
            ext = _Path(fname).suffix.lower()
            if ext in _DUMP_EXTENSIONS:
                dump_entries.append(info)
            elif ext in _COMPANION_EXTENSIONS:
                companion_entries.append(info)

        if not dump_entries:
            raise HTTPException(
                422,
                "ZIP contains no recognizable memory dump "
                f"({', '.join(sorted(_DUMP_EXTENSIONS))}). "
                "Please check the archive contents."
            )

        # If multiple dump files, pick the largest by uncompressed size
        dump_entry = max(dump_entries, key=lambda e: e.file_size)
        dump_filename = _Path(dump_entry.filename).name
        dump_data = zf.read(dump_entry.filename)

        companions = [
            (_Path(ce.filename).name, zf.read(ce.filename))
            for ce in companion_entries
        ]
        return dump_data, dump_filename, companions


async def _check_upload_rate(user_id: str) -> None:
    """Enforce per-user upload rate limit using Redis. Raises 429 if exceeded."""
    import redis.asyncio as aioredis
    key = f"upload_rate:{user_id}"
    async with aioredis.from_url(settings.REDIS_URL) as rc:
        pipe = rc.pipeline()
        pipe.incr(key)
        pipe.expire(key, 3600)   # 1-hour sliding window
        results = await pipe.execute()
    count = results[0]
    limit = settings.MAX_CASES_PER_HOUR_PER_USER
    if count > limit:
        raise HTTPException(
            status_code=429,
            detail=f"Upload rate limit exceeded: max {limit} case submissions per hour",
        )


@router.post("", response_model=CaseResponse, status_code=201)
async def submit_case(
    # File + form fields (multipart)
    dump_file: UploadFile = File(..., description="Memory dump file (.raw/.mem/.dmp/.vmem/.lime/.bin or .zip)"),
    name: str = Form(..., max_length=255),
    description: str = Form(default="", max_length=4096),
    priority: int = Form(default=2, ge=1, le=4),
    os_hint: str | None = Form(default=None, pattern="^(windows|linux|macos)$"),
    tags: str = Form(default=""),   # comma-separated
    symbols_file: UploadFile | None = File(default=None, description="Optional Volatility3 symbol table (.json or .json.xz) for Linux/macOS"),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> CaseResponse:
    """
    Upload a memory dump (or a ZIP containing one) and queue it for analysis.

    ZIP archives are extracted server-side. If the archive contains a VMEM file
    paired with a VMSS/VMSN companion, both files are stored and made available
    to Volatility in the same working directory.
    """
    from pathlib import Path as _Path

    # Per-user upload rate limit (H-2)
    await _check_upload_rate(str(current_user.id))

    # Validate file size before reading
    if dump_file.size and dump_file.size > settings.MAX_DUMP_SIZE_BYTES:
        raise HTTPException(413, f"File too large. Max {settings.MAX_DUMP_SIZE_BYTES // 1024**3} GB")

    short_id = _generate_short_id()
    is_zip = (dump_file.filename or "").lower().endswith(".zip")

    if is_zip:
        # Starlette spools uploads > 1 MB to a temp file on disk.
        # Open the SpooledTemporaryFile directly with zipfile so the ZIP is
        # never copied into a Python bytes object in memory.
        import asyncio as _asyncio
        import zipfile as _zipfile

        zip_fileobj = dump_file.file
        zip_fileobj.seek(0)

        # Scan the central directory to find dump and companion entries.
        dump_entries = []
        companion_entries_info = []
        with _zipfile.ZipFile(zip_fileobj) as _zf:
            for info in _zf.infolist():
                if info.is_dir():
                    continue
                if info.file_size > settings.MAX_DUMP_SIZE_BYTES:
                    raise HTTPException(
                        413,
                        f"ZIP entry '{_Path(info.filename).name}' declares an "
                        f"uncompressed size of {info.file_size // 1024 ** 3} GB "
                        f"which exceeds the {settings.MAX_DUMP_SIZE_BYTES // 1024 ** 3} GB limit."
                    )
                fname = _Path(info.filename).name
                ext = _Path(fname).suffix.lower()
                if ext in _DUMP_EXTENSIONS:
                    dump_entries.append(info)
                elif ext in _COMPANION_EXTENSIONS:
                    companion_entries_info.append(info)

        if not dump_entries:
            raise HTTPException(
                422,
                "ZIP contains no recognizable memory dump "
                f"({', '.join(sorted(_DUMP_EXTENSIONS))}). "
                "Please check the archive contents."
            )

        dump_entry_info = max(dump_entries, key=lambda e: e.file_size)
        original_filename = _Path(dump_entry_info.filename).name
        dump_ext = _Path(original_filename).suffix.lower() or ".raw"
        storage_key = f"cases/{short_id}/dump{dump_ext}"

        # Stream the dump entry through a SHA256-computing wrapper into MinIO
        # multipart upload.  Only 64 MB is held in memory at a time.
        # Run in a thread executor because both zipfile and boto3 are sync.
        _hasher = hashlib.sha256()
        _total_ref: list[int] = [0]

        class _HashingReader:
            """Wraps a readable file-like object, updating a SHA256 hasher on read."""
            def __init__(self, underlying) -> None:
                self._f = underlying
            def read(self, n: int = -1) -> bytes:
                data = self._f.read(n)
                if data:
                    _hasher.update(data)
                    _total_ref[0] += len(data)
                return data

        zip_fileobj.seek(0)
        _zf2 = _zipfile.ZipFile(zip_fileobj)
        _entry_stream = _zf2.open(dump_entry_info)
        try:
            _loop = _asyncio.get_running_loop()
            _reader = _HashingReader(_entry_stream)
            try:
                await _loop.run_in_executor(
                    None,
                    lambda: upload_fileobj_multipart(_reader, storage_key, settings.S3_BUCKET_DUMPS),
                )
            except _S3ClientError as exc:
                _code = exc.response.get("Error", {}).get("Code", "")
                if _code == "XMinioStorageFull":
                    raise HTTPException(
                        507,
                        "Storage is full — the object store has reached its minimum free space threshold. "
                        "An administrator must expand the disk before new uploads are possible.",
                    )
                raise
        finally:
            _entry_stream.close()
            _zf2.close()

        sha256 = _hasher.hexdigest()
        total_bytes = _total_ref[0]

        # Duplicate check after upload (hash only known after streaming)
        from sqlalchemy import select as _select
        dup = (await db.execute(_select(Case).where(Case.sha256 == sha256))).scalars().first()
        if dup:
            delete_case_files(short_id)
            raise HTTPException(
                status_code=409,
                detail={"message": "Duplicate file — this dump has already been imported.", "existing_case_id": str(dup.id), "existing_case": dup.short_id},
            )

        # Upload companion files (e.g. .vmss/.vmsn) — typically small, one at a time
        zip_fileobj.seek(0)
        with _zipfile.ZipFile(zip_fileobj) as _zf3:
            for comp_info in companion_entries_info:
                companion_ext = _Path(comp_info.filename).suffix.lower()
                companion_key = f"cases/{short_id}/dump{companion_ext}"
                with _zf3.open(comp_info) as comp_stream:
                    await _loop.run_in_executor(
                        None,
                        lambda: upload_fileobj_multipart(comp_stream, companion_key, settings.S3_BUCKET_DUMPS),
                    )
                import logging as _log
                _log.getLogger(__name__).info(
                    "Uploaded companion %s as %s",
                    _Path(comp_info.filename).name, companion_key,
                )
    else:
        # Stream directly to object storage while computing hash
        original_filename = dump_file.filename or "dump.raw"
        dump_ext = _Path(original_filename).suffix.lower() or ".raw"
        storage_key = f"cases/{short_id}/dump{dump_ext}"

        hasher = hashlib.sha256()
        total_bytes = 0

        async def _hashing_stream():
            nonlocal total_bytes
            while chunk := await dump_file.read(1024 * 1024):
                hasher.update(chunk)
                total_bytes += len(chunk)
                yield chunk

        try:
            await upload_dump_stream(_hashing_stream(), storage_key, settings.S3_BUCKET_DUMPS)
        except _S3ClientError as exc:
            _code = exc.response.get("Error", {}).get("Code", "")
            if _code == "XMinioStorageFull":
                raise HTTPException(
                    507,
                    "Storage is full — the object store has reached its minimum free space threshold. "
                    "An administrator must expand the disk before new uploads are possible.",
                )
            raise
        sha256 = hasher.hexdigest()
        companions = []

        # Duplicate check after upload (hash only known after streaming)
        from sqlalchemy import select as _select
        dup = (await db.execute(_select(Case).where(Case.sha256 == sha256))).scalars().first()
        if dup:
            delete_case_files(short_id)  # clean up the orphaned MinIO object
            raise HTTPException(
                status_code=409,
                detail={"message": "Duplicate file — this dump has already been imported.", "existing_case_id": str(dup.id), "existing_case": dup.short_id},
            )

    # Create case record
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    case = Case(
        short_id=short_id,
        name=name,
        description=description or None,
        priority=priority,
        submitted_by=current_user.id,
        tags=tag_list,
        original_filename=original_filename,
        file_size_bytes=total_bytes,
        sha256=sha256,
        storage_key=storage_key,
        os_hint=os_hint,
        status=CaseStatus.queued,
        queued_at=datetime.now(timezone.utc),
    )
    db.add(case)
    await db.commit()
    await db.refresh(case)

    # If a custom symbol table was uploaded, save it to the Volatility symbol cache
    if symbols_file and os_hint in ("linux", "macos"):
        import re as _re
        sym_filename = _Path(symbols_file.filename or "").name  # strip any directory prefix

        # H-4: validate filename against safe character set before writing to disk
        _safe_name_re = _re.compile(r'^[A-Za-z0-9_\-\.]+$')
        if not sym_filename or not _safe_name_re.match(sym_filename):
            raise HTTPException(422, "Symbol filename contains invalid characters. Use only A-Z, a-z, 0-9, _, -, .")
        if not (sym_filename.endswith(".json") or sym_filename.endswith(".json.xz")):
            raise HTTPException(422, "Symbol file must be a .json or .json.xz file")

        sym_data = await symbols_file.read()
        # Enforce max symbol file size (32 MB is generous for an ISF)
        _MAX_SYM_BYTES = 32 * 1024 * 1024
        if len(sym_data) > _MAX_SYM_BYTES:
            raise HTTPException(413, f"Symbol file too large. Max {_MAX_SYM_BYTES // 1024 ** 2} MB")

        subdir = "linux" if os_hint == "linux" else "mac"
        sym_dir = _Path(settings.SYMBOL_CACHE_PATH) / subdir
        sym_dir.mkdir(parents=True, exist_ok=True)
        sym_dest = sym_dir / sym_filename
        sym_dest.write_bytes(sym_data)
        import logging as _log
        _log.getLogger(__name__).info("Saved custom symbol table %s (%d bytes) to %s", sym_filename, len(sym_data), sym_dest)

    # If a description was provided, save it as a KB article attached to this case
    # so it is visible in the Overview tab and automatically passed to the AI agent.
    if description:
        kb_article = KBArticle(
            title="Description",
            content=description,
            tags=[],
            created_by=current_user.id,
        )
        db.add(kb_article)
        await db.flush()  # populate kb_article.id before creating the link
        db.add(CaseKBArticle(case_id=case.id, article_id=kb_article.id))
        await db.commit()

    # Create a StringsRun record immediately so the tab shows "pending" status
    db.add(StringsRun(case_id=case.id))
    await db.flush()

    # If OS hint + custom symbol table were both provided, triage can be skipped:
    # we already know the OS and the symbol table is in place.
    if os_hint and symbols_file:
        from backend.core.plugins.registry import get_plugins_for_os
        os_detail = "Symbol table uploaded by analyst — triage skipped"
        case.detected_os = OSType(os_hint)
        case.detected_os_detail = os_detail
        case.status = CaseStatus.triage_complete
        case.detection_started_at = datetime.now(timezone.utc)
        # Pre-create PluginRun records so the UI can show the full plugin list
        for spec in get_plugins_for_os(os_hint):
            db.add(PluginRun(
                case_id=case.id,
                plugin_name=spec.name,
                plugin_domain=spec.domain,
                status=PluginStatus.pending,
            ))
        await db.commit()
        actor = str(current_user.id)
        publish_case_event(str(case.id), "os_detected", {"os": os_hint, "detail": os_detail}, actor_id=actor)
        publish_case_event(str(case.id), "status_change", {"status": "triage_complete"}, actor_id=actor)
    else:
        # Normal path: dispatch triage for OS detection.
        # strings_task is dispatched from the END of triage_task (after Volatility3
        # finishes) so the two tasks never download and mmap the dump simultaneously.
        task_id = dispatch_triage(str(case.id), priority=case.priority)
        case.celery_task_id = task_id
        await db.commit()
        return CaseResponse.model_validate(case)

    # Triage-skip path only: no triage task will run, so dispatch strings here.
    dispatch_strings(str(case.id), storage_key, priority=case.priority)

    return CaseResponse.model_validate(case)


# ── List cases ────────────────────────────────────────────────────────────────

@router.get("", response_model=CaseListResponse)
async def list_cases(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    status: str | None = Query(default=None),
    os_type: str | None = Query(default=None),
    search: str | None = Query(default=None, max_length=128),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> CaseListResponse:
    from sqlalchemy import select, func, desc, or_

    q = select(Case).where(Case.deleted_at.is_(None))

    if status:
        q = q.where(Case.status == status)
    if os_type:
        q = q.where(Case.detected_os == os_type)
    if search:
        q = q.where(or_(
            Case.name.ilike(f"%{search}%"),
            Case.short_id.ilike(f"%{search}%"),
            Case.sha256.startswith(search.lower()),
        ))

    # Count
    count_q = select(func.count()).select_from(q.subquery())
    total = (await db.execute(count_q)).scalar_one()

    # Paginate
    q = q.order_by(desc(Case.created_at)).offset((page - 1) * page_size).limit(page_size)
    cases = (await db.execute(q)).scalars().all()

    # Batch-fetch verdicts for complete cases
    case_ids = [c.id for c in cases]
    verdict_map: dict = {}
    if case_ids:
        from sqlalchemy import select as _select
        rows = (await db.execute(
            _select(Report.case_id, Report.verdict).where(Report.case_id.in_(case_ids))
        )).all()
        verdict_map = {
            row.case_id: (row.verdict.value if hasattr(row.verdict, 'value') else str(row.verdict))
            for row in rows
        }

    items = [
        CaseResponse.model_validate(c).model_copy(update={'verdict': verdict_map.get(c.id)})
        for c in cases
    ]
    return CaseListResponse(items=items, total=total, page=page, page_size=page_size)


# ── Case detail ───────────────────────────────────────────────────────────────

@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> CaseResponse:
    case = await _get_case_or_404(db, case_id)
    return CaseResponse.model_validate(case)


# ── Plugin runs ───────────────────────────────────────────────────────────────

@router.get("/{case_id}/plugins", response_model=list[PluginRunListItem])
async def list_plugin_runs(
    case_id: UUID,
    domain: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> list[PluginRunListItem]:
    from sqlalchemy import select
    from backend.core.plugins.registry import get_plugins_for_os

    case = await _get_case_or_404(db, case_id)

    # Auto-add any registry plugins that don't yet have a PluginRun row for
    # this case (happens when new plugins are added after the case was created).
    if case.detected_os and case.detected_os.value not in ("unknown", ""):
        existing_q = select(PluginRun.plugin_name).where(PluginRun.case_id == case_id)
        existing_names = set((await db.execute(existing_q)).scalars().all())
        new_rows = [
            PluginRun(
                case_id=case_id,
                plugin_name=spec.name,
                plugin_domain=spec.domain,
                status=PluginStatus.pending,
            )
            for spec in get_plugins_for_os(case.detected_os.value)
            if spec.priority != 1 and spec.name not in existing_names
        ]
        if new_rows:
            db.add_all(new_rows)
            await db.commit()

    q = select(PluginRun).where(PluginRun.case_id == case_id)
    if domain:
        q = q.where(PluginRun.plugin_domain == domain)
    q = q.order_by(PluginRun.plugin_domain, PluginRun.plugin_name)

    runs = (await db.execute(q)).scalars().all()
    return [PluginRunListItem.model_validate(r) for r in runs]


@router.get("/{case_id}/plugins/download")
async def download_all_plugin_outputs(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Stream a ZIP archive of all completed plugin outputs for a case."""
    import io, json, zipfile
    from sqlalchemy import select
    case = (await db.execute(select(Case).where(Case.id == case_id))).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    runs = (await db.execute(
        select(PluginRun).where(
            PluginRun.case_id == case_id,
            PluginRun.parsed_output.isnot(None),
        )
    )).scalars().all()
    if not runs:
        raise HTTPException(404, "No completed plugin outputs found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for run in runs:
            safe_name = run.plugin_name.replace("/", "_").replace("\\", "_")
            zf.writestr(f"{safe_name}.json", json.dumps(run.parsed_output, indent=2))
    buf.seek(0)

    slug = (case.name or str(case_id))[:40].replace(" ", "_")
    filename = f"{slug}_plugins.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@router.get("/{case_id}/plugins/{plugin_name:path}/download")
async def download_plugin_output(
    case_id: UUID,
    plugin_name: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Stream a single plugin's parsed output as a JSON file."""
    import json
    from sqlalchemy import select
    run = (await db.execute(
        select(PluginRun).where(
            PluginRun.case_id == case_id,
            PluginRun.plugin_name == plugin_name,
        )
    )).scalar_one_or_none()
    if not run or run.parsed_output is None:
        raise HTTPException(404, f"No output found for plugin '{plugin_name}'")
    safe_name = plugin_name.replace("/", "_").replace("\\", "_")
    return StreamingResponse(
        iter([json.dumps(run.parsed_output, indent=2).encode()]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename={safe_name}.json"},
    )


@router.get("/{case_id}/plugins/{plugin_name:path}", response_model=PluginRunResponse)
async def get_plugin_output(
    case_id: UUID,
    plugin_name: str,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> PluginRunResponse:
    from sqlalchemy import select
    q = select(PluginRun).where(
        PluginRun.case_id == case_id,
        PluginRun.plugin_name == plugin_name,
    )
    run = (await db.execute(q)).scalar_one_or_none()
    if not run:
        raise HTTPException(404, f"Plugin '{plugin_name}' not found for this case")
    return PluginRunResponse.model_validate(run)


# ── Report ────────────────────────────────────────────────────────────────────

@router.get("/{case_id}/report", response_model=ReportResponse)
async def get_report(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> ReportResponse:
    from sqlalchemy import select
    q = select(Report).where(Report.case_id == case_id, Report.superseded_at.is_(None))
    report = (await db.execute(q)).scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not yet available")
    return ReportResponse.model_validate(report)


@router.get("/{case_id}/report/history", response_model=list[ReportResponse])
async def get_report_history(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> list[ReportResponse]:
    from sqlalchemy import select, desc
    reports = (await db.execute(
        select(Report)
        .where(Report.case_id == case_id, Report.superseded_at.is_not(None))
        .order_by(desc(Report.superseded_at))
    )).scalars().all()
    return [ReportResponse.model_validate(r) for r in reports]


@router.get("/{case_id}/report/pdf")
async def download_report_pdf(
    case_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Generate and stream a PDF report."""
    from sqlalchemy import select
    report = (await db.execute(select(Report).where(Report.case_id == case_id, Report.superseded_at.is_(None)))).scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not found")

    from backend.utils.pdf_export import generate_pdf
    pdf_bytes = await generate_pdf(report)

    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=report-{case_id}.pdf"},
    )


# ── IOCs ──────────────────────────────────────────────────────────────────────

@router.get("/{case_id}/iocs")
async def list_iocs(
    case_id: UUID,
    severity: str | None = Query(default=None),
    ioc_type: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    from sqlalchemy import select
    q = select(IOC).where(IOC.case_id == case_id)
    if severity:
        q = q.where(IOC.severity == severity)
    if ioc_type:
        q = q.where(IOC.ioc_type == ioc_type)
    iocs = (await db.execute(q)).scalars().all()
    return [{"id": str(i.id),
             "ioc_type":    i.ioc_type.value    if hasattr(i.ioc_type,    "value") else str(i.ioc_type),
             "value":       i.value,
             "severity":    i.severity.value    if hasattr(i.severity,    "value") else str(i.severity),
             "vt_positives": i.vt_positives,
             "vt_total":    i.vt_total,
             "vt_permalink": i.vt_permalink,
             "source_plugin": i.source_plugin,
             "description": i.description} for i in iocs]


# ── Reanalyze ─────────────────────────────────────────────────────────────────

@router.post("/{case_id}/reanalyze", response_model=CaseResponse)
async def reanalyze_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> CaseResponse:
    """
    Reset a case and re-run the full analysis pipeline.
    Allowed only when the case is in a terminal state (failed or complete).
    The original dump in object storage is reused — no re-upload needed.
    """
    from sqlalchemy import delete

    case = await _get_case_or_404(db, case_id)

    REANALYZABLE = {
        CaseStatus.failed, CaseStatus.complete, CaseStatus.cancelled,
        CaseStatus.triage_complete,
        # Also allow stuck in-progress states (worker died mid-task)
        CaseStatus.queued, CaseStatus.detecting, CaseStatus.analyzing, CaseStatus.ai_analysis,
    }
    if case.status not in REANALYZABLE:
        raise HTTPException(409, f"Cannot reanalyze a case with status '{case.status}'.")

    if case.dump_purged_at:
        raise HTTPException(410, "The dump file for this case has been purged and cannot be reanalyzed.")

    # Clear plugin runs and IOCs — re-generated on each analysis.
    # Reports are preserved (superseded by the worker) to retain token usage history.
    await db.execute(delete(PluginRun).where(PluginRun.case_id == case_id))
    await db.execute(delete(IOC).where(IOC.case_id == case_id))

    # Reset case to queued state
    case.status = CaseStatus.queued
    case.detected_os = OSType.unknown
    case.detected_os_detail = None
    case.volatility_profile = None
    case.error_message = None
    case.celery_task_id = None
    case.detection_started_at = None
    case.analysis_started_at = None
    case.ai_started_at = None
    case.completed_at = None
    case.queued_at = datetime.now(timezone.utc)
    case.updated_at = datetime.now(timezone.utc)

    await db.commit()
    await db.refresh(case)

    # Re-dispatch triage only
    task_id = dispatch_triage(str(case.id), priority=case.priority)
    case.celery_task_id = task_id
    await db.commit()

    return CaseResponse.model_validate(case)


# ── Manual workflow triggers ──────────────────────────────────────────────────

from pydantic import BaseModel

class RunPluginsRequest(BaseModel):
    plugin_names: list[str]


@router.post("/{case_id}/plugins/run", response_model=CaseResponse)
async def run_plugins(
    case_id: UUID,
    body: RunPluginsRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> CaseResponse:
    """Manually trigger selected Volatility3 plugins for a triage-complete case."""
    from backend.core.plugins.registry import get_plugin

    case = await _get_case_or_404(db, case_id)

    allowed = {CaseStatus.triage_complete, CaseStatus.complete, CaseStatus.failed}
    if case.status not in allowed:
        raise HTTPException(409, f"Cannot run plugins on a case with status '{case.status}'. Case must be in triage_complete or complete state.")

    if not body.plugin_names:
        raise HTTPException(422, "plugin_names must not be empty")

    # Validate that all requested plugins exist in the registry
    unknown = [n for n in body.plugin_names if not get_plugin(n)]
    if unknown:
        raise HTTPException(422, f"Unknown plugin(s): {', '.join(unknown)}")

    task_id = dispatch_selected_plugins(str(case_id), body.plugin_names, priority=case.priority)
    case.celery_task_id = task_id
    case.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)

    return CaseResponse.model_validate(case)


@router.post("/{case_id}/enrich", response_model=CaseResponse)
async def enrich_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> CaseResponse:
    """Trigger VirusTotal enrichment for a case that has completed plugins."""
    case = await _get_case_or_404(db, case_id)

    if case.status not in {CaseStatus.triage_complete, CaseStatus.complete, CaseStatus.failed}:
        raise HTTPException(409, f"Cannot enrich a case with status '{case.status}'.")

    task_id = dispatch_enrich(str(case_id), priority=case.priority)
    case.celery_task_id = task_id
    case.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)

    return CaseResponse.model_validate(case)


@router.post("/{case_id}/analyze", response_model=CaseResponse)
async def run_ai_analysis(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> CaseResponse:
    """Trigger AI analysis for a case that has one or more completed plugin runs."""
    from sqlalchemy import select, func

    case = await _get_case_or_404(db, case_id)

    if case.status not in {CaseStatus.triage_complete, CaseStatus.complete, CaseStatus.failed}:
        raise HTTPException(409, f"Cannot run AI analysis on a case with status '{case.status}'.")

    if case.dump_purged_at:
        raise HTTPException(410, "The dump file has been purged.")

    # Require at least one completed plugin run
    completed_count = (await db.execute(
        select(func.count()).select_from(PluginRun).where(
            PluginRun.case_id == case_id,
            PluginRun.status == "complete",
        )
    )).scalar_one()

    if completed_count == 0:
        raise HTTPException(422, "No completed plugin runs found. Run at least one plugin before AI analysis.")

    task_id = dispatch_ai_analysis(str(case_id), priority=case.priority)
    case.celery_task_id = task_id
    case.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(case)

    return CaseResponse.model_validate(case)


# ── KB Articles for case ──────────────────────────────────────────────────────

@router.get("/{case_id}/kb")
async def list_case_kb_articles(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Return KB articles attached to a case."""
    await _get_case_or_404(db, case_id)
    from backend.api.routers.kb import get_articles_for_case
    return await get_articles_for_case(db, case_id)


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    _admin = Depends(get_current_admin),
):
    """
    Permanently delete a case and all associated data.
    Removes all files from object storage (dump + companions) and hard-deletes
    the database row (cascades to plugin_runs, report, iocs, events, kb_links).
    """
    case = await _get_case_or_404(db, case_id)
    short_id = case.short_id

    # Delete all files from object storage first
    try:
        deleted = delete_case_files(short_id)
        if deleted:
            import logging as _log
            _log.getLogger(__name__).info("Deleted %d MinIO object(s) for case %s", deleted, short_id)
    except Exception:
        import logging as _log
        _log.getLogger(__name__).warning("Failed to delete MinIO objects for case %s — proceeding with DB delete", short_id, exc_info=True)

    # Hard delete — ORM cascades remove plugin_runs, report, iocs, events, kb_links
    await db.delete(case)
    await db.commit()


# ── Strings endpoints ─────────────────────────────────────────────────────────

@router.get("/{case_id}/strings", response_model=StringsRunSchema)
async def get_strings_status(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> StringsRunSchema:
    """Return the current strings extraction status and metadata for a case."""
    from sqlalchemy import select
    await _get_case_or_404(db, case_id)
    sr = (await db.execute(
        select(StringsRun).where(StringsRun.case_id == case_id)
    )).scalar_one_or_none()
    if not sr:
        raise HTTPException(404, "Strings extraction record not found")
    return StringsRunSchema.model_validate(sr).model_copy(
        update={"strings_plugin_threshold": settings.STRINGS_PLUGIN_THRESHOLD}
    )


@router.post("/{case_id}/strings/run-plugin", response_model=RunStringsPluginResponse, status_code=202)
async def run_strings_plugin(
    case_id: UUID,
    body: RunStringsPluginRequest,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> RunStringsPluginResponse:
    """
    Queue a run of the OS-appropriate strings plugin (e.g. windows.strings)
    using the analyst's current filter as input.

    The plugin output is appended to any existing PluginRun record for this
    plugin, deduplicating rows across runs.  Poll
    ``GET /cases/{case_id}/plugins/windows.strings`` (or the OS equivalent)
    to track progress.
    """
    from sqlalchemy import select

    case = await _get_case_or_404(db, case_id)
    os_type = case.detected_os.value if hasattr(case.detected_os, "value") else str(case.detected_os)

    if os_type not in STRINGS_PLUGIN_FOR_OS:
        raise HTTPException(400, f"No strings plugin available for OS: {os_type}")

    sr = (await db.execute(
        select(StringsRun).where(StringsRun.case_id == case_id)
    )).scalar_one_or_none()
    if not sr or (sr.status.value if hasattr(sr.status, "value") else str(sr.status)) != "complete":
        raise HTTPException(400, "Strings extraction must be complete before running the strings plugin")

    priority = getattr(case, "priority", 2)
    task_id = dispatch_run_strings_plugin(str(case_id), body.filter_query, priority=priority)

    return RunStringsPluginResponse(status="queued", task_id=task_id)


@router.get("/{case_id}/strings/search", response_model=StringsSearchResponse)
async def search_strings(
    case_id: UUID,
    q: str = Query(default="", max_length=1024, description="Logical filter expression (AND/OR/NOT + regex)"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=200, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> StringsSearchResponse:
    """
    Search strings output with a logical regex expression.

    Returns a paginated slice of matching lines.  Results are capped at
    ``settings.STRINGS_SEARCH_CAP`` matches per query; ``is_capped=true``
    in the response indicates the cap was reached.

    Returns HTTP 202 while extraction is still running.
    """
    from sqlalchemy import select
    from backend.core.strings_filter import build_filter, search_strings as _search

    await _get_case_or_404(db, case_id)
    sr = (await db.execute(
        select(StringsRun).where(StringsRun.case_id == case_id)
    )).scalar_one_or_none()
    if not sr:
        raise HTTPException(404, "Strings extraction record not found")
    if sr.status.value not in ("complete",):
        raise HTTPException(
            202,
            detail={"status": sr.status.value if hasattr(sr.status, "value") else str(sr.status)},
        )
    if not sr.storage_key:
        raise HTTPException(500, "Strings file reference missing")

    try:
        filter_fn = build_filter(q)
    except ValueError as exc:
        raise HTTPException(422, f"Invalid filter expression: {exc}")

    import asyncio
    from functools import partial
    gz_data = await asyncio.get_event_loop().run_in_executor(
        None,
        partial(download_object_bytes, sr.storage_key, settings.S3_BUCKET_DUMPS),
    )

    result = _search(
        gz_data=gz_data,
        filter_fn=filter_fn,
        page=page,
        page_size=page_size,
        max_matches=settings.STRINGS_SEARCH_CAP,
    )
    return StringsSearchResponse(**result)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_case_or_404(db: AsyncSession, case_id: UUID) -> Case:
    from sqlalchemy import select
    case = (await db.execute(
        select(Case).where(Case.id == case_id, Case.deleted_at.is_(None))
    )).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")
    return case


def _generate_short_id() -> str:
    alphabet = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(8))
