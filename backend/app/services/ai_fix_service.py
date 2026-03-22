"""
AI Fix Service — thin wrapper around the LangGraph fix engine.

The actual fix logic (template check → GPT → Claude → build → retry loop)
lives in fix_graph.py as a proper state machine.  This service provides the
public interface used by API routes and Celery tasks.
"""

import logging
from typing import Any

from app.services.fix_graph import run_fix_graph

logger = logging.getLogger(__name__)


class AIFixService:
    """Generates vulnerability fixes via the LangGraph state machine."""

    async def generate_fix(
        self,
        vulnerability: dict,
        file_content: str,
        project_context: dict,
        language: str,
        framework: str,
        repo_path: str = "",
        max_retries: int = 3,
    ) -> dict[str, Any]:
        """
        Run the full fix pipeline:
          1. Check fix templates (free, instant)
          2. GPT-5.4 Thinking (primary)
          3. Claude Opus 4.6 (fallback)
          4. Docker build validation
          5. Retry loop with error context (up to max_retries)

        Returns dict with diff, explanation, confidence, model, build output,
        status ("validated" | "flagged" | "failed"), and token usage.
        """
        final_state = await run_fix_graph(
            vulnerability=vulnerability,
            file_content=file_content,
            language=language,
            framework=framework,
            repo_path=repo_path,
            project_context=project_context,
            max_retries=max_retries,
        )

        return {
            "status": final_state.get("status", "failed"),
            "model": final_state.get("model_used", "unknown"),
            "diff": final_state.get("diff_content", ""),
            "explanation": final_state.get("fix_explanation", ""),
            "confidence": final_state.get("confidence_score", 0.0),
            "build_passed": final_state.get("build_passed"),
            "build_output": final_state.get("build_output", ""),
            "retry_count": final_state.get("retry_count", 0),
            "prompt_tokens": final_state.get("prompt_tokens", 0),
            "completion_tokens": final_state.get("completion_tokens", 0),
        }
