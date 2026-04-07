# backend/api/routers/kb.py
"""
Knowledge base article management.
Articles are free-form analyst notes that can be attached to one or more cases
to provide extra context for AI analysis or team collaboration.
"""
from __future__ import annotations
from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from backend.db.session import get_db
from backend.db.models.models import KBArticle, CaseKBArticle, Case
from backend.api.dependencies import get_current_user, require_not_viewer

router = APIRouter(prefix="/kb", tags=["knowledge-base"])


# ── Schemas ───────────────────────────────────────────────────────────────────

class KBArticleCreate(BaseModel):
    title: str
    content: str
    tags: list[str] = []


class KBArticleUpdate(BaseModel):
    title: str | None = None
    content: str | None = None
    tags: list[str] | None = None


class KBArticleResponse(BaseModel):
    id: str
    title: str
    content: str
    tags: list[str]
    created_by: str
    created_at: str
    updated_at: str

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_obj(cls, a: KBArticle) -> "KBArticleResponse":
        return cls(
            id=str(a.id),
            title=a.title,
            content=a.content,
            tags=a.tags or [],
            created_by=str(a.created_by),
            created_at=a.created_at.isoformat(),
            updated_at=a.updated_at.isoformat(),
        )


# ── CRUD ──────────────────────────────────────────────────────────────────────

@router.post("", response_model=KBArticleResponse, status_code=201)
async def create_article(
    body: KBArticleCreate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> KBArticleResponse:
    article = KBArticle(
        title=body.title,
        content=body.content,
        tags=body.tags,
        created_by=current_user.id,
    )
    db.add(article)
    await db.commit()
    await db.refresh(article)
    return KBArticleResponse.from_orm_obj(article)


@router.get("", response_model=list[KBArticleResponse])
async def list_articles(
    search: str | None = Query(default=None, max_length=128),
    tag: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> list[KBArticleResponse]:
    q = select(KBArticle).order_by(KBArticle.updated_at.desc())
    if search:
        q = q.where(KBArticle.title.ilike(f"%{search}%"))
    if tag:
        q = q.where(KBArticle.tags.any(tag))
    articles = (await db.execute(q)).scalars().all()
    return [KBArticleResponse.from_orm_obj(a) for a in articles]


@router.get("/{article_id}", response_model=KBArticleResponse)
async def get_article(
    article_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(get_current_user),
) -> KBArticleResponse:
    article = await _get_article_or_404(db, article_id)
    return KBArticleResponse.from_orm_obj(article)


@router.put("/{article_id}", response_model=KBArticleResponse)
async def update_article(
    article_id: UUID,
    body: KBArticleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
) -> KBArticleResponse:
    article = await _get_article_or_404(db, article_id)
    if body.title is not None:
        article.title = body.title
    if body.content is not None:
        article.content = body.content
    if body.tags is not None:
        article.tags = body.tags
    article.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(article)
    return KBArticleResponse.from_orm_obj(article)


@router.delete("/{article_id}", status_code=204)
async def delete_article(
    article_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
):
    article = await _get_article_or_404(db, article_id)
    await db.delete(article)
    await db.commit()


# ── Case attachment ────────────────────────────────────────────────────────────

@router.post("/{article_id}/cases/{case_id}", status_code=204)
async def attach_to_case(
    article_id: UUID,
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
):
    """Attach a KB article to a case."""
    await _get_article_or_404(db, article_id)
    # Verify case exists
    case = (await db.execute(select(Case).where(Case.id == case_id, Case.deleted_at.is_(None)))).scalar_one_or_none()
    if not case:
        raise HTTPException(404, "Case not found")

    existing = (await db.execute(
        select(CaseKBArticle).where(CaseKBArticle.case_id == case_id, CaseKBArticle.article_id == article_id)
    )).scalar_one_or_none()
    if not existing:
        db.add(CaseKBArticle(case_id=case_id, article_id=article_id))
        await db.commit()


@router.delete("/{article_id}/cases/{case_id}", status_code=204)
async def detach_from_case(
    article_id: UUID,
    case_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user = Depends(require_not_viewer),
):
    """Detach a KB article from a case."""
    link = (await db.execute(
        select(CaseKBArticle).where(CaseKBArticle.case_id == case_id, CaseKBArticle.article_id == article_id)
    )).scalar_one_or_none()
    if link:
        await db.delete(link)
        await db.commit()


# ── Case KB list (also exposed via /cases/{id}/kb) ────────────────────────────

async def get_articles_for_case(db: AsyncSession, case_id: UUID) -> list[KBArticleResponse]:
    """Return all KB articles attached to a case."""
    q = (
        select(KBArticle)
        .join(CaseKBArticle, CaseKBArticle.article_id == KBArticle.id)
        .where(CaseKBArticle.case_id == case_id)
        .order_by(KBArticle.updated_at.desc())
    )
    articles = (await db.execute(q)).scalars().all()
    return [KBArticleResponse.from_orm_obj(a) for a in articles]


# ── Helper ────────────────────────────────────────────────────────────────────

async def _get_article_or_404(db: AsyncSession, article_id: UUID) -> KBArticle:
    article = (await db.execute(select(KBArticle).where(KBArticle.id == article_id))).scalar_one_or_none()
    if not article:
        raise HTTPException(404, "KB article not found")
    return article
