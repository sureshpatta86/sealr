import logging
import shutil
import subprocess
import tempfile

import httpx

logger = logging.getLogger(__name__)


class GitHubService:
    """Handles all GitHub operations using the user's PAT."""

    def __init__(self, token: str):
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.client = httpx.AsyncClient(
            base_url="https://api.github.com",
            headers=self.headers,
            timeout=30.0,
        )

    async def validate_token(self) -> dict:
        resp = await self.client.get("/user")
        resp.raise_for_status()
        scopes = resp.headers.get("X-OAuth-Scopes", "")
        return {"user": resp.json(), "scopes": scopes}

    async def get_repo_info(self, owner: str, repo: str) -> dict:
        resp = await self.client.get(f"/repos/{owner}/{repo}")
        resp.raise_for_status()
        return resp.json()

    def clone_repo(self, owner: str, repo: str, branch: str = "main") -> str:
        """Clone repository to a temp directory. Returns the path."""
        clone_url = (
            f"https://x-access-token:{self.token}@github.com/{owner}/{repo}.git"
        )

        clone_dir = tempfile.mkdtemp(prefix="sealr-")
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", branch, clone_url, clone_dir],
                check=True,
                capture_output=True,
                timeout=300,
            )
        except subprocess.CalledProcessError:
            # Specified branch not found — retry using the remote's default branch
            shutil.rmtree(clone_dir, ignore_errors=True)
            clone_dir = tempfile.mkdtemp(prefix="sealr-")
            subprocess.run(
                ["git", "clone", "--depth", "1", clone_url, clone_dir],
                check=True,
                capture_output=True,
                timeout=300,
            )
        return clone_dir

    async def get_file_content(self, owner: str, repo: str, path: str, ref: str = "main") -> str:
        """Fetch a file's decoded text content from GitHub Contents API."""
        import base64
        resp = await self.client.get(
            f"/repos/{owner}/{repo}/contents/{path}",
            params={"ref": ref},
        )
        resp.raise_for_status()
        data = resp.json()
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")

    async def get_branch_sha(self, owner: str, repo: str, branch: str) -> str:
        """Get the HEAD commit SHA for a branch."""
        resp = await self.client.get(f"/repos/{owner}/{repo}/branches/{branch}")
        resp.raise_for_status()
        return resp.json()["commit"]["sha"]

    async def create_branch(
        self, owner: str, repo: str, branch_name: str, base_sha: str
    ) -> dict:
        resp = await self.client.post(
            f"/repos/{owner}/{repo}/git/refs",
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )
        resp.raise_for_status()
        return resp.json()

    async def commit_file(
        self,
        owner: str,
        repo: str,
        branch: str,
        path: str,
        content: str,
        message: str,
    ) -> dict:
        """Create or update a file via the Contents API."""
        import base64

        # Get current file SHA if it exists
        sha = None
        try:
            resp = await self.client.get(
                f"/repos/{owner}/{repo}/contents/{path}",
                params={"ref": branch},
            )
            if resp.status_code == 200:
                sha = resp.json()["sha"]
        except Exception:
            pass

        payload = {
            "message": message,
            "content": base64.b64encode(content.encode()).decode(),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha

        resp = await self.client.put(
            f"/repos/{owner}/{repo}/contents/{path}",
            json=payload,
        )
        resp.raise_for_status()
        return resp.json()

    async def create_pull_request(
        self,
        owner: str,
        repo: str,
        title: str,
        body: str,
        head_branch: str,
        base_branch: str = "main",
    ) -> dict:
        resp = await self.client.post(
            f"/repos/{owner}/{repo}/pulls",
            json={
                "title": title,
                "body": body,
                "head": head_branch,
                "base": base_branch,
            },
        )
        resp.raise_for_status()
        pr = resp.json()

        # Add labels
        await self.client.post(
            f"/repos/{owner}/{repo}/issues/{pr['number']}/labels",
            json={"labels": ["security", "sealr", "automated-fix"]},
        )

        return pr

    def cleanup(self, clone_dir: str):
        shutil.rmtree(clone_dir, ignore_errors=True)

    async def close(self):
        await self.client.aclose()
