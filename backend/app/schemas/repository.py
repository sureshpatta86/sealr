from datetime import datetime

from pydantic import BaseModel


class RepositoryResponse(BaseModel):
    id: str
    github_url: str
    owner: str
    name: str
    default_branch: str
    language: str | None
    framework: str | None
    last_scanned_at: datetime | None
    created_at: datetime

    @classmethod
    def from_model(cls, repo) -> "RepositoryResponse":
        return cls(
            id=repo.Id,
            github_url=repo.GitHubUrl,
            owner=repo.Owner,
            name=repo.Name,
            default_branch=repo.DefaultBranch,
            language=repo.Language,
            framework=repo.Framework,
            last_scanned_at=repo.LastScannedAt,
            created_at=repo.CreatedAt,
        )
