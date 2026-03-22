from datetime import datetime

from pydantic import BaseModel


class FixResponse(BaseModel):
    id: str
    vulnerability_id: str
    status: str
    diff_content: str | None
    confidence_score: float | None
    ai_model: str
    ai_prompt_tokens: int | None
    ai_completion_tokens: int | None
    build_output: str | None
    test_output: str | None
    retry_count: int
    pr_url: str | None
    pr_number: int | None
    branch_name: str | None
    created_at: datetime
    validated_at: datetime | None

    model_config = {"from_attributes": True}

    @classmethod
    def from_model(cls, fix) -> "FixResponse":
        return cls(
            id=fix.Id,
            vulnerability_id=fix.VulnerabilityId,
            status=fix.Status,
            diff_content=fix.DiffContent,
            confidence_score=float(fix.ConfidenceScore) if fix.ConfidenceScore else None,
            ai_model=fix.AIModel,
            ai_prompt_tokens=fix.AIPromptTokens,
            ai_completion_tokens=fix.AICompletionTokens,
            build_output=fix.BuildOutput,
            test_output=fix.TestOutput,
            retry_count=fix.RetryCount,
            pr_url=fix.PRUrl,
            pr_number=fix.PRNumber,
            branch_name=fix.BranchName,
            created_at=fix.CreatedAt,
            validated_at=fix.ValidatedAt,
        )
