from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Vulnerability
from app.schemas.vulnerability import VulnerabilityResponse
from app.utils.constants import VulnerabilityStatus
from app.utils.database import get_db

router = APIRouter(tags=["vulnerabilities"])


@router.get(
    "/vulnerabilities/{vuln_id}", response_model=VulnerabilityResponse
)
async def get_vulnerability(
    vuln_id: str, db: AsyncSession = Depends(get_db)
):
    """Get a single vulnerability detail."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.Id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    return VulnerabilityResponse.from_model(vuln)


@router.post("/vulnerabilities/{vuln_id}/fix")
async def fix_vulnerability(
    vuln_id: str, db: AsyncSession = Depends(get_db)
):
    """Trigger AI fix generation for a single vulnerability."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.Id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")
    if not vuln.IsAutoFixable:
        raise HTTPException(400, "This vulnerability is not auto-fixable")

    from app.workers.scan_tasks import fix_vulnerability as fix_task

    fix_task.delay(vuln_id)
    return {"message": "Fix generation started", "vulnerability_id": vuln_id}


@router.post("/vulnerabilities/{vuln_id}/dismiss")
async def dismiss_vulnerability(
    vuln_id: str, db: AsyncSession = Depends(get_db)
):
    """Dismiss a vulnerability."""
    result = await db.execute(
        select(Vulnerability).where(Vulnerability.Id == vuln_id)
    )
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(404, "Vulnerability not found")

    vuln.Status = VulnerabilityStatus.DISMISSED
    return {"message": "Vulnerability dismissed", "vulnerability_id": vuln_id}
