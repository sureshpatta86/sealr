from fastapi import APIRouter, HTTPException
import httpx

from app.config import settings
from app.schemas.auth import TokenValidationRequest, TokenValidationResponse, GitHubUser

router = APIRouter(tags=["auth"])


@router.post("/auth/validate-token", response_model=TokenValidationResponse)
async def validate_token(req: TokenValidationRequest):
    """Validate a GitHub Personal Access Token and return user info."""
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(
                f"{settings.GITHUB_API_BASE}/user",
                headers={
                    "Authorization": f"Bearer {req.github_token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=10.0,
            )
            resp.raise_for_status()
            user_data = resp.json()
            scopes = resp.headers.get("X-OAuth-Scopes", "")

            return TokenValidationResponse(
                valid=True,
                user=GitHubUser(
                    login=user_data["login"],
                    avatar_url=user_data["avatar_url"],
                ),
                scopes=scopes,
            )
        except httpx.HTTPStatusError:
            raise HTTPException(status_code=401, detail="Invalid GitHub token")
