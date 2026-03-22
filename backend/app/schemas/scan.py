from datetime import datetime

from pydantic import BaseModel, HttpUrl


class ScanCreate(BaseModel):
    repo_url: str
    github_token: str
    language: str | None = None
    framework: str | None = None
    branch: str | None = None


class ScanResponse(BaseModel):
    id: str
    repository_id: str
    repository_name: str | None = None
    status: str
    language: str
    framework: str | None
    branch: str
    commit_sha: str | None
    total_vulnerabilities: int
    fixed_count: int
    started_at: datetime | None
    completed_at: datetime | None
    error_message: str | None
    scan_duration_sec: int | None
    created_at: datetime

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, scan) -> "ScanResponse":
        repo_name = None
        if hasattr(scan, "repository") and scan.repository:
            repo_name = scan.repository.Name
        return cls(
            id=scan.Id,
            repository_id=scan.RepositoryId,
            repository_name=repo_name,
            status=scan.Status,
            language=scan.Language,
            framework=scan.Framework,
            branch=scan.Branch,
            commit_sha=scan.CommitSha,
            total_vulnerabilities=scan.TotalVulnerabilities,
            fixed_count=scan.FixedCount,
            started_at=scan.StartedAt,
            completed_at=scan.CompletedAt,
            error_message=scan.ErrorMessage,
            scan_duration_sec=scan.ScanDurationSec,
            created_at=scan.CreatedAt,
        )


class ScanEventResponse(BaseModel):
    event_type: str
    message: str
    metadata: dict | None = None
    timestamp: str


class DashboardStats(BaseModel):
    total_scans: int
    total_vulnerabilities: int
    fixed_vulnerabilities: int
    fix_rate: float
    by_severity: dict[str, int]
    recent_scans: list[ScanResponse] = []
