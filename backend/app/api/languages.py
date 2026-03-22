from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.supported_language import SupportedLanguage
from app.schemas.language import LanguageResponse
from app.utils.database import get_db

router = APIRouter(tags=["languages"])


@router.get("/languages", response_model=list[LanguageResponse])
async def list_languages(db: AsyncSession = Depends(get_db)):
    """Return all supported languages, ordered by sort_order."""
    result = await db.execute(
        select(SupportedLanguage).order_by(SupportedLanguage.SortOrder)
    )
    languages = result.scalars().all()
    return [LanguageResponse.from_model(lang) for lang in languages]
