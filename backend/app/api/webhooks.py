import hashlib
import hmac

from fastapi import APIRouter, Header, HTTPException, Request, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import Fix
from app.utils.constants import FixStatus
from app.utils.database import get_db

router = APIRouter(tags=["webhooks"])


def verify_github_signature(payload: bytes, signature: str) -> bool:
    """Verify the GitHub webhook signature."""
    if not settings.GITHUB_WEBHOOK_SECRET:
        return True  # Skip verification in dev
    expected = hmac.new(
        settings.GITHUB_WEBHOOK_SECRET.encode(),
        payload,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


@router.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
    x_github_event: str = Header(None),
    db: AsyncSession = Depends(get_db),
):
    """Handle GitHub webhook events (PR merged/closed)."""
    body = await request.body()
    if x_hub_signature_256 and not verify_github_signature(
        body, x_hub_signature_256
    ):
        raise HTTPException(403, "Invalid signature")

    payload = await request.json()

    if x_github_event == "pull_request":
        action = payload.get("action")
        pr = payload.get("pull_request", {})
        pr_number = pr.get("number")

        if action == "closed" and pr.get("merged"):
            # PR was merged — update fix status
            result = await db.execute(
                select(Fix).where(Fix.PRNumber == pr_number)
            )
            fix = result.scalar_one_or_none()
            if fix:
                fix.Status = FixStatus.PR_MERGED

    return {"status": "ok"}
