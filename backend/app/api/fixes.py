from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Fix
from app.schemas.fix import FixResponse
from app.utils.database import get_db

router = APIRouter(tags=["fixes"])


@router.get("/fixes/{fix_id}", response_model=FixResponse)
async def get_fix(fix_id: str, db: AsyncSession = Depends(get_db)):
    """Get fix detail including diff, build output, and PR info."""
    result = await db.execute(select(Fix).where(Fix.Id == fix_id))
    fix = result.scalar_one_or_none()
    if not fix:
        raise HTTPException(404, "Fix not found")
    return FixResponse.from_model(fix)


@router.post("/fixes/{fix_id}/create-pr")
async def create_pr_for_fix(fix_id: str, db: AsyncSession = Depends(get_db)):
    """Create a GitHub PR for a validated fix."""
    result = await db.execute(select(Fix).where(Fix.Id == fix_id))
    fix = result.scalar_one_or_none()
    if not fix:
        raise HTTPException(404, "Fix not found")
    if fix.Status != "build_passed":
        raise HTTPException(400, "Fix must pass build validation before creating a PR")

    from app.workers.scan_tasks import create_pr_task

    create_pr_task.delay(fix_id)
    return {"message": "PR creation started", "fix_id": fix_id}


@router.post("/fixes/{fix_id}/retry")
async def retry_fix(fix_id: str, db: AsyncSession = Depends(get_db)):
    """Retry fix generation with error context from previous attempt."""
    result = await db.execute(select(Fix).where(Fix.Id == fix_id))
    fix = result.scalar_one_or_none()
    if not fix:
        raise HTTPException(404, "Fix not found")
    if fix.RetryCount >= 3:
        raise HTTPException(400, "Maximum retry count exceeded")

    from app.workers.scan_tasks import fix_vulnerability

    fix_vulnerability.delay(fix.VulnerabilityId, retry=True)
    return {"message": "Fix retry started", "fix_id": fix_id}
