from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Repository, User
from app.schemas.repository import RepositoryResponse
from app.utils.database import get_db

router = APIRouter(tags=["repositories"])


@router.get("/repositories", response_model=list[RepositoryResponse])
async def list_repositories(
    x_github_token: str = Header(..., alias="X-GitHub-Token"),
    db: AsyncSession = Depends(get_db),
):
    """List all scanned repositories for the authenticated user."""
    # Look up user by their encrypted token's associated record
    result = await db.execute(
        select(User).where(User.GitHubUsername.isnot(None))
    )
    users = result.scalars().all()

    # Find the user matching the provided token by validating against GitHub
    import httpx

    async with httpx.AsyncClient() as client:
        resp = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {x_github_token}"},
        )
        if resp.status_code != 200:
            raise HTTPException(401, "Invalid GitHub token")
        github_user = resp.json()

    # Find or match user
    user_result = await db.execute(
        select(User).where(User.GitHubUsername == github_user["login"])
    )
    user = user_result.scalar_one_or_none()
    if not user:
        raise HTTPException(404, "User not found")

    # Get repositories for this user
    repo_result = await db.execute(
        select(Repository)
        .where(Repository.UserId == user.Id)
        .order_by(Repository.CreatedAt.desc())
    )
    repos = repo_result.scalars().all()

    return [RepositoryResponse.from_model(r) for r in repos]
