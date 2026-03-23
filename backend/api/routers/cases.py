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
from backend.db.models.models import Case, CaseStatus, PluginRun, Report, IOC
from backend.core.storage import upload_dump_stream
from backend.workers.analysis import dispatch_analysis
from backend.schemas.case import (
    CaseCreate, CaseResponse, CaseListResponse,
    PluginRunResponse, ReportResponse,
)
from backend.api.dependencies import get_current_user
from backend.config import settings

router = APIRouter(prefix="/cases", tags=["cases"])


# ── Submit a new case ─────────────────────────────────────────────────────────

@router.post("", response_model=CaseResponse, status_code=201)
async def submit_case(
    # File + form fields (multipart)
    dump_file: UploadFile = File(..., description="Memory dump file"),
    name: str = Form(..., max_length=255),
    description: str = Form(default="", max_length=4096),
    priority: int = Form(default=2, ge=1, le=4),
    os_hint: str | None = Form(default=None, pattern="^(windows|linux|macos)$"),
    tags: str = Form(default=""),   # comma-separated
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> CaseResponse:
    """
    Upload a memory dump and queue it for analysis.

    The dump is streamed directly to object storage — it is never
    written to the API server's disk. SHA-256 is computed on-the-fly.
    """
    # Validate file size before reading
    if dump_file.size and dump_file.size > settings.MAX_DUMP_SIZE_BYTES:
        raise HTTPException(413, f"File too large. Max {settings.MAX_DUMP_SIZE_BYTES // 1024**3} GB")

    # Generate case short_id
    short_id = _generate_short_id()
    storage_key = f"cases/{short_id}/{dump_file.filename}"

    # Stream to object storage while computing hash
    hasher = hashlib.sha256()
    total_bytes = 0

    async def _hashing_stream():
        nonlocal total_bytes
        while chunk := await dump_file.read(1024 * 1024):  # 1 MB chunks
            hasher.update(chunk)
            total_bytes += len(chunk)
            yield chunk

    await upload_dump_stream(_hashing_stream(), storage_key, settings.S3_BUCKET_DUMPS)
    sha256 = hasher.hexdigest()

    # Create case record
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    case = Case(
        short_id=short_id,
        name=name,
        description=description or None,
        priority=priority,
        submitted_by=current_user.id,
        tags=tag_list,
        original_filename=dump_file.filename,
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

    # Dispatch Celery pipeline
    task_id = dispatch_analysis(str(case.id))
    case.celery_task_id = task_id
    await db.commit()

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

    return CaseListResponse(items=[CaseResponse.model_validate(c) for c in cases], total=total, page=page, page_size=page_size)


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

@router.get("/{case_id}/plugins", response_model=list[PluginRunResponse])
async def list_plugin_runs(
    case_id: UUID,
    domain: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> list[PluginRunResponse]:
    from sqlalchemy import select
    await _get_case_or_404(db, case_id)

    q = select(PluginRun).where(PluginRun.case_id == case_id)
    if domain:
        q = q.where(PluginRun.plugin_domain == domain)
    q = q.order_by(PluginRun.plugin_domain, PluginRun.plugin_name)

    runs = (await db.execute(q)).scalars().all()
    return [PluginRunResponse.model_validate(r) for r in runs]


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
    q = select(Report).where(Report.case_id == case_id)
    report = (await db.execute(q)).scalar_one_or_none()
    if not report:
        raise HTTPException(404, "Report not yet available")
    return ReportResponse.model_validate(report)


@router.get("/{case_id}/report/pdf")
async def download_report_pdf(
    case_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Generate and stream a PDF report."""
    from sqlalchemy import select
    report = (await db.execute(select(Report).where(Report.case_id == case_id))).scalar_one_or_none()
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
    return [{"id": str(i.id), "type": i.ioc_type, "value": i.value,
             "severity": i.severity, "vt_positives": i.vt_positives,
             "description": i.description} for i in iocs]


# ── Delete ────────────────────────────────────────────────────────────────────

@router.delete("/{case_id}", status_code=204)
async def delete_case(
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
):
    case = await _get_case_or_404(db, case_id)
    case.deleted_at = datetime.now(timezone.utc)
    await db.commit()


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
