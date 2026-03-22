from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Fix, Scan, Vulnerability
from app.schemas.scan import DashboardStats, ScanResponse
from app.utils.database import get_db

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    """Get aggregate stats for the dashboard."""
    # Total scans
    result = await db.execute(select(func.count(Scan.Id)))
    total_scans = result.scalar() or 0

    # Total vulnerabilities
    result = await db.execute(select(func.count(Vulnerability.Id)))
    total_vulns = result.scalar() or 0

    # Fixed vulnerabilities
    result = await db.execute(
        select(func.count(Vulnerability.Id)).where(
            Vulnerability.Status.in_(["fix_validated", "pr_created", "pr_merged"])
        )
    )
    fixed_vulns = result.scalar() or 0

    # By severity
    by_severity = {}
    for sev in ["critical", "high", "medium", "low"]:
        result = await db.execute(
            select(func.count(Vulnerability.Id)).where(
                Vulnerability.Severity == sev
            )
        )
        by_severity[sev] = result.scalar() or 0

    fix_rate = (fixed_vulns / total_vulns * 100) if total_vulns > 0 else 0.0

    # Recent scans
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.repository))
        .order_by(Scan.CreatedAt.desc())
        .limit(10)
    )
    recent = result.scalars().all()

    return DashboardStats(
        total_scans=total_scans,
        total_vulnerabilities=total_vulns,
        fixed_vulnerabilities=fixed_vulns,
        fix_rate=round(fix_rate, 1),
        by_severity=by_severity,
        recent_scans=[ScanResponse.from_model(s) for s in recent],
    )
