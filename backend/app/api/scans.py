import json
import re
import uuid
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models import Fix, Repository, Scan, ScanEvent, User, Vulnerability
from app.schemas.scan import ScanCreate, ScanEventResponse, ScanResponse
from app.schemas.vulnerability import VulnerabilityResponse
from app.utils.constants import ScanStatus
from app.utils.database import get_db
from app.utils.encryption import encrypt_token

router = APIRouter(tags=["scans"])

GITHUB_REPO_RE = re.compile(
    r"https?://github\.com/(?P<owner>[\w.\-]+)/(?P<repo>[\w.\-]+)"
)


@router.post("/scans", response_model=ScanResponse, status_code=201)
async def create_scan(req: ScanCreate, background_tasks: BackgroundTasks, db: AsyncSession = Depends(get_db)):
    """Create and start a new security scan."""
    match = GITHUB_REPO_RE.match(req.repo_url)
    if not match:
        raise HTTPException(400, "Invalid GitHub repository URL")

    owner = match.group("owner")
    repo_name = match.group("repo").removesuffix(".git")

    # Find or create user
    result = await db.execute(
        select(User).where(User.GitHubUsername == owner)
    )
    user = result.scalar_one_or_none()
    if not user:
        user = User(
            Id=str(uuid.uuid4()),
            Email=f"{owner}@github.com",
            GitHubUsername=owner,
            GitHubTokenEncrypted=encrypt_token(req.github_token),
        )
        db.add(user)
        await db.flush()

    # Find or create repository
    result = await db.execute(
        select(Repository).where(
            Repository.UserId == user.Id,
            Repository.GitHubUrl == req.repo_url,
        )
    )
    repo = result.scalar_one_or_none()
    if not repo:
        repo = Repository(
            Id=str(uuid.uuid4()),
            UserId=user.Id,
            GitHubUrl=req.repo_url,
            Owner=owner,
            Name=repo_name,
        )
        db.add(repo)
        await db.flush()

    # Create scan record
    scan = Scan(
        Id=str(uuid.uuid4()),
        RepositoryId=repo.Id,
        UserId=user.Id,
        Status=ScanStatus.QUEUED,
        Language=req.language or "auto",
        Framework=req.framework,
        Branch=req.branch or "main",
    )
    db.add(scan)
    await db.commit()  # commit before dispatch so task's session can see the scan
    scan.repository = repo  # avoid lazy-load in from_model

    repo_info = {
        "owner": owner,
        "name": repo_name,
        "branch": scan.Branch,
        "language": req.language,
        "framework": req.framework,
    }

    if settings.DEV_MODE:
        # Run in background so HTTP response returns immediately
        from app.workers.scan_tasks import run_scan_async
        background_tasks.add_task(run_scan_async, scan.Id, user.Id, repo_info, req.github_token)
    else:
        from app.workers.scan_tasks import scan_repository
        scan_repository.delay(scan.Id, user.Id, repo_info, req.github_token)

    return ScanResponse.from_model(scan)


@router.get("/scans", response_model=list[ScanResponse])
async def list_scans(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
):
    """List scans with pagination."""
    offset = (page - 1) * page_size
    result = await db.execute(
        select(Scan)
        .options(selectinload(Scan.repository))
        .order_by(Scan.CreatedAt.desc())
        .offset(offset)
        .limit(page_size)
    )
    scans = result.scalars().all()
    return [ScanResponse.from_model(s) for s in scans]


@router.get("/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get scan detail."""
    result = await db.execute(
        select(Scan).options(selectinload(Scan.repository)).where(Scan.Id == scan_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return ScanResponse.from_model(scan)


@router.get(
    "/scans/{scan_id}/vulnerabilities",
    response_model=list[VulnerabilityResponse],
)
async def get_scan_vulnerabilities(
    scan_id: str,
    severity: str | None = Query(None),
    category: str | None = Query(None),
    status: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerabilities for a scan, with optional filters."""
    query = select(Vulnerability).where(Vulnerability.ScanId == scan_id)
    if severity:
        query = query.where(Vulnerability.Severity == severity)
    if category:
        query = query.where(Vulnerability.Category == category)
    if status:
        query = query.where(Vulnerability.Status == status)
    query = query.order_by(Vulnerability.CreatedAt)

    result = await db.execute(query)
    vulns = result.scalars().all()
    return [VulnerabilityResponse.from_model(v) for v in vulns]


@router.get("/scans/{scan_id}/events", response_model=list[ScanEventResponse])
async def get_scan_events(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Return all persisted events for a scan in chronological order."""
    result = await db.execute(
        select(ScanEvent)
        .where(ScanEvent.ScanId == scan_id)
        .order_by(ScanEvent.CreatedAt)
    )
    events = result.scalars().all()
    return [
        ScanEventResponse(
            event_type=e.EventType,
            message=e.Message or "",
            metadata=json.loads(e.Metadata) if e.Metadata else None,
            timestamp=e.CreatedAt.isoformat(),
        )
        for e in events
    ]


@router.post("/scans/{scan_id}/fix-all")
async def fix_all_vulnerabilities(
    scan_id: str, db: AsyncSession = Depends(get_db)
):
    """Generate fixes for all auto-fixable vulnerabilities in a scan."""
    result = await db.execute(select(Scan).where(Scan.Id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(404, "Scan not found")

    from app.workers.scan_tasks import fix_vulnerability

    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.ScanId == scan_id,
            Vulnerability.IsAutoFixable == True,
            Vulnerability.Status == "open",
        )
    )
    vulns = result.scalars().all()
    for vuln in vulns:
        fix_vulnerability.delay(vuln.Id)

    return {"message": "Fix generation started", "count": len(vulns)}
