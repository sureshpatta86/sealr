"""
LangGraph state machine for vulnerability fix generation.

Flow:
  CheckTemplates → (match) → ApplyAndBuild
                 → (no match) → CallGPT54
  CallGPT54 → (success) → ParseDiff → ApplyAndBuild
            → (fail) → CallClaude
  CallClaude → (success) → ParseDiff → ApplyAndBuild
             → (fail) → FlagForReview
  ApplyAndBuild → (pass) → CreatePR
                → (fail, retries < 3) → CallGPT54 (with error context)
                → (fail, retries >= 3) → FlagForReview
"""

import logging
from typing import Optional, TypedDict

import anthropic
import openai
from langgraph.graph import END, StateGraph

from app.config import settings
from app.services.build_validator import BuildValidator
from app.services.fix_templates import FixTemplates

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------

class FixState(TypedDict):
    # Input (immutable across nodes)
    vulnerability: dict
    file_content: str
    language: str
    framework: str
    repo_path: str
    project_context: dict

    # Evolving state (updated by nodes)
    diff_content: Optional[str]
    fix_explanation: Optional[str]
    confidence_score: float
    model_used: str

    # Build validation
    build_passed: Optional[bool]
    build_output: Optional[str]

    # Retry tracking
    retry_count: int
    max_retries: int
    last_error: Optional[str]

    # Outcome
    status: str  # "validated", "pr_created", "failed", "flagged"
    pr_url: Optional[str]

    # Token usage
    prompt_tokens: int
    completion_tokens: int


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are Sealr, an expert security engineer that fixes vulnerabilities in code.

Given a vulnerability description and the affected code, generate a fix as a unified diff.

Rules:
1. Output ONLY a valid unified diff that can be applied with `git apply`
2. The fix must be minimal — change only what's necessary
3. The fix must not break existing functionality
4. Include a brief explanation of what was changed and why
5. Assign a confidence score (0.0 to 1.0)

Format your response EXACTLY as:

<explanation>
Brief explanation of the fix
</explanation>

<confidence>
0.95
</confidence>

<diff>
--- a/path/to/file
+++ b/path/to/file
@@ ... @@
 context line
-removed line
+added line
 context line
</diff>"""


def _build_prompt(state: FixState) -> str:
    vuln = state["vulnerability"]
    prompt = f"""## Vulnerability Details
- **Category:** {vuln['category']}
- **Severity:** {vuln['severity']}
- **CWE:** {vuln.get('cwe_id', 'N/A')}
- **CVE:** {vuln.get('cve_id', 'N/A')}
- **Description:** {vuln['description']}
- **File:** {vuln.get('file_path', 'N/A')}
- **Lines:** {vuln.get('line_start', '?')} - {vuln.get('line_end', '?')}
- **Language:** {state['language']}
- **Framework:** {state['framework']}

## Affected Code
```
{state['file_content']}
```

## Project Context
- Dependencies: {state['project_context'].get('dependencies', [])}
- Has Tests: {state['project_context'].get('has_tests', False)}

Generate a fix for this vulnerability."""

    # On retry, include the previous build error for context
    if state.get("last_error"):
        prompt += f"""

## Previous Attempt Failed
The previous fix attempt failed during build/test with this error:
```
{state['last_error']}
```
Please generate a corrected fix that addresses this build error."""

    return prompt


def _extract_diff(content: str) -> str:
    if "<diff>" in content and "</diff>" in content:
        return content.split("<diff>")[1].split("</diff>")[0].strip()
    return content


def _extract_explanation(content: str) -> str:
    if "<explanation>" in content and "</explanation>" in content:
        return content.split("<explanation>")[1].split("</explanation>")[0].strip()
    return ""


def _extract_confidence(content: str) -> float:
    try:
        if "<confidence>" in content and "</confidence>" in content:
            score = content.split("<confidence>")[1].split("</confidence>")[0].strip()
            return float(score)
    except ValueError:
        pass
    return 0.5


# ---------------------------------------------------------------------------
# Node 1: Check Templates
# ---------------------------------------------------------------------------

def check_templates(state: FixState) -> dict:
    """Pre-built fixes for common patterns. No AI cost, instant."""
    templates = FixTemplates()
    match = templates.match(
        state["vulnerability"], state["file_content"], state["language"]
    )
    if match:
        logger.info("Template match found — skipping LLM call")
        return {
            "diff_content": match["diff"],
            "fix_explanation": match["explanation"],
            "confidence_score": 0.99,
            "model_used": "template",
        }
    return {}


# ---------------------------------------------------------------------------
# Node 2: Call GPT-5.4 Thinking (primary LLM)
# ---------------------------------------------------------------------------

async def call_primary_llm(state: FixState) -> dict:
    """GPT-5.4 Thinking — primary model for fix generation."""
    if not settings.OPENAI_API_KEY:
        logger.warning("No OpenAI API key configured, skipping primary LLM")
        return {"model_used": "skipped"}

    try:
        client = openai.AsyncOpenAI(api_key=settings.OPENAI_API_KEY)
        prompt = _build_prompt(state)

        # Newer models (o-series, gpt-5.x) use max_completion_tokens and don't support temperature.
        # gpt-4o supports both. We detect by model name prefix.
        model_name = settings.OPENAI_THINKING_MODEL
        supports_temperature = model_name.startswith("gpt-4")
        create_kwargs: dict = {
            "model": model_name,
            "messages": [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            "max_completion_tokens": 4096,
        }
        if supports_temperature:
            create_kwargs["temperature"] = 0.1

        response = await client.chat.completions.create(**create_kwargs)
        content = response.choices[0].message.content or ""

        logger.info(f"{model_name} responded ({response.usage.prompt_tokens}+{response.usage.completion_tokens} tokens)")
        return {
            "diff_content": _extract_diff(content),
            "fix_explanation": _extract_explanation(content),
            "confidence_score": _extract_confidence(content),
            "model_used": settings.OPENAI_THINKING_MODEL,
            "prompt_tokens": response.usage.prompt_tokens,
            "completion_tokens": response.usage.completion_tokens,
        }
    except Exception as e:
        logger.warning(f"{model_name} failed: {e}")
        return {"model_used": "gpt_failed", "last_error": str(e)}


# ---------------------------------------------------------------------------
# Node 3: Call Claude (backup LLM)
# ---------------------------------------------------------------------------

async def call_backup_llm(state: FixState) -> dict:
    """Claude Opus 4.6 — backup model when primary LLM fails."""
    key = settings.ANTHROPIC_API_KEY or ""
    if not key or key.startswith("sk-ant-...") or len(key) < 20:
        logger.warning("No valid Anthropic API key configured, skipping backup LLM")
        return {"model_used": "backup_skipped"}

    try:
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        prompt = _build_prompt(state)

        response = await client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=4096,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        content = response.content[0].text

        logger.info(f"Claude responded ({response.usage.input_tokens}+{response.usage.output_tokens} tokens)")
        return {
            "diff_content": _extract_diff(content),
            "fix_explanation": _extract_explanation(content),
            "confidence_score": _extract_confidence(content),
            "model_used": settings.ANTHROPIC_MODEL,
            "prompt_tokens": response.usage.input_tokens,
            "completion_tokens": response.usage.output_tokens,
        }
    except Exception as e:
        logger.error(f"Claude also failed: {e}")
        return {"model_used": "claude_failed", "last_error": str(e)}


# ---------------------------------------------------------------------------
# Node 4: Parse and validate diff
# ---------------------------------------------------------------------------

def parse_diff(state: FixState) -> dict:
    """Validate that we have a usable diff."""
    diff = state.get("diff_content")
    if not diff or len(diff.strip()) < 10:
        logger.warning("Diff content is empty or too short")
        return {"status": "flagged", "last_error": "Empty or invalid diff"}
    # Basic validation: should contain +/- lines
    has_additions = any(line.startswith("+") for line in diff.splitlines() if not line.startswith("+++"))
    has_removals = any(line.startswith("-") for line in diff.splitlines() if not line.startswith("---"))
    if not has_additions and not has_removals:
        return {"status": "flagged", "last_error": "Diff has no changes"}
    return {}


# ---------------------------------------------------------------------------
# Node 5: Apply diff and build in Docker sandbox
# ---------------------------------------------------------------------------

async def apply_and_build(state: FixState) -> dict:
    """Apply diff, build, and test in an isolated Docker container."""
    repo_path = state.get("repo_path")
    diff_content = state.get("diff_content")

    if not repo_path or not diff_content:
        return {
            "build_passed": False,
            "build_output": "Missing repo_path or diff_content",
            "retry_count": state.get("retry_count", 0) + 1,
            "last_error": "Missing repo_path or diff_content",
        }

    if settings.DEV_MODE:
        logger.info("DEV_MODE: skipping Docker build validation, marking fix as generated")
        return {
            "build_passed": True,
            "build_output": "Skipped in DEV_MODE",
            "status": "validated",
        }

    try:
        validator = BuildValidator()
        language_config = {
            "docker_image": _get_docker_image(state["language"], state["framework"]),
            "build_command": _get_build_command(state["language"]),
            "test_command": _get_test_command(state["language"]),
        }

        result = await validator.validate_fix(repo_path, diff_content, language_config)

        if result["success"]:
            logger.info("Build + tests passed")
            return {
                "build_passed": True,
                "build_output": result["build_output"],
                "status": "validated",
            }
        else:
            retry_count = state.get("retry_count", 0) + 1
            logger.warning(f"Build failed (attempt {retry_count}): {result['build_output'][:200]}")
            return {
                "build_passed": False,
                "build_output": result["build_output"],
                "retry_count": retry_count,
                "last_error": result["build_output"][-2000:],  # Feed error back to LLM
            }
    except Exception as e:
        retry_count = state.get("retry_count", 0) + 1
        logger.error(f"Build validation error: {e}")
        return {
            "build_passed": False,
            "build_output": str(e),
            "retry_count": retry_count,
            "last_error": str(e),
        }


# ---------------------------------------------------------------------------
# Node 6: Flag for manual review
# ---------------------------------------------------------------------------

def flag_for_review(state: FixState) -> dict:
    """Mark as needing human review when all automated approaches fail."""
    logger.warning(
        f"Flagging vulnerability for review: {state['vulnerability'].get('title', 'unknown')}"
    )
    return {"status": "flagged"}


# ---------------------------------------------------------------------------
# Conditional edge routers
# ---------------------------------------------------------------------------

def route_after_template_check(state: FixState) -> str:
    """Template match → apply_and_build, else → call_primary_llm."""
    if state.get("model_used") == "template" and state.get("diff_content"):
        return "apply_and_build"
    return "call_primary_llm"


def route_after_primary_llm(state: FixState) -> str:
    """Success → parse_diff, fail → call_backup_llm."""
    if state.get("diff_content") and state.get("model_used") not in (
        "gpt_failed", "skipped",
    ):
        return "parse_diff"
    return "call_backup_llm"


def route_after_backup_llm(state: FixState) -> str:
    """Success → parse_diff, fail → flag_for_review."""
    if state.get("diff_content") and state.get("model_used") not in (
        "claude_failed", "backup_skipped",
    ):
        return "parse_diff"
    return "flag_for_review"


def route_after_parse(state: FixState) -> str:
    """Valid diff → apply_and_build, invalid → flag_for_review."""
    if state.get("status") == "flagged":
        return "flag_for_review"
    return "apply_and_build"


def route_after_build(state: FixState) -> str:
    """Pass → END, fail + retries left → call_primary_llm, exhausted → flag_for_review."""
    if state.get("build_passed"):
        return END
    if state.get("retry_count", 0) < state.get("max_retries", 3):
        return "call_primary_llm"
    return "flag_for_review"


# ---------------------------------------------------------------------------
# Docker image / build command helpers
# ---------------------------------------------------------------------------

def _get_docker_image(language: str, framework: str) -> str:
    images = {
        "csharp": "mcr.microsoft.com/dotnet/sdk:8.0",
        "typescript": "node:22-slim",
        "javascript": "node:22-slim",
        "python": "python:3.12-slim",
        "java": "eclipse-temurin:21-jdk",
        "go": "golang:1.22",
        "rust": "rust:1.77",
        "php": "php:8.3-cli",
        "ruby": "ruby:3.3",
    }
    return images.get(language, "ubuntu:24.04")


def _get_build_command(language: str) -> str:
    commands = {
        "csharp": "dotnet restore && dotnet build --no-restore",
        "typescript": "npm ci && npm run build",
        "javascript": "npm ci && npm run build",
        "python": "pip install -r requirements.txt",
        "java": "mvn compile -q",
        "go": "go build ./...",
        "rust": "cargo build",
        "php": "composer install --no-dev",
        "ruby": "bundle install",
    }
    return commands.get(language, "echo 'no build command'")


def _get_test_command(language: str) -> str:
    commands = {
        "csharp": "dotnet test --no-build",
        "typescript": "npm test",
        "javascript": "npm test",
        "python": "pytest --tb=short -q",
        "java": "mvn test -q",
        "go": "go test ./...",
        "rust": "cargo test",
        "php": "vendor/bin/phpunit",
        "ruby": "bundle exec rspec",
    }
    return commands.get(language, "")


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_fix_graph() -> StateGraph:
    """
    Construct the LangGraph state machine for fix generation.

    Graph:
      check_templates → [apply_and_build | call_primary_llm]
      call_primary_llm → [parse_diff | call_backup_llm]
      call_backup_llm → [parse_diff | flag_for_review]
      parse_diff → [apply_and_build | flag_for_review]
      apply_and_build → [END | call_primary_llm (retry) | flag_for_review]
      flag_for_review → END
    """
    graph = StateGraph(FixState)

    # Add nodes
    graph.add_node("check_templates", check_templates)
    graph.add_node("call_primary_llm", call_primary_llm)
    graph.add_node("call_backup_llm", call_backup_llm)
    graph.add_node("parse_diff", parse_diff)
    graph.add_node("apply_and_build", apply_and_build)
    graph.add_node("flag_for_review", flag_for_review)

    # Entry point
    graph.set_entry_point("check_templates")

    # Conditional edges
    graph.add_conditional_edges(
        "check_templates",
        route_after_template_check,
        {"apply_and_build": "apply_and_build", "call_primary_llm": "call_primary_llm"},
    )

    graph.add_conditional_edges(
        "call_primary_llm",
        route_after_primary_llm,
        {"parse_diff": "parse_diff", "call_backup_llm": "call_backup_llm"},
    )

    graph.add_conditional_edges(
        "call_backup_llm",
        route_after_backup_llm,
        {"parse_diff": "parse_diff", "flag_for_review": "flag_for_review"},
    )

    graph.add_conditional_edges(
        "parse_diff",
        route_after_parse,
        {"apply_and_build": "apply_and_build", "flag_for_review": "flag_for_review"},
    )

    graph.add_conditional_edges(
        "apply_and_build",
        route_after_build,
        {END: END, "call_primary_llm": "call_primary_llm", "flag_for_review": "flag_for_review"},
    )

    # Terminal node
    graph.add_edge("flag_for_review", END)

    return graph


# Compiled graph — singleton, reused across invocations
fix_graph = build_fix_graph().compile()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

async def run_fix_graph(
    vulnerability: dict,
    file_content: str,
    language: str,
    framework: str,
    repo_path: str,
    project_context: dict | None = None,
    max_retries: int = 3,
) -> FixState:
    """
    Run the full fix state machine for a single vulnerability.

    Returns the final FixState with status, diff, build output, etc.
    """
    initial_state: FixState = {
        "vulnerability": vulnerability,
        "file_content": file_content,
        "language": language,
        "framework": framework,
        "repo_path": repo_path,
        "project_context": project_context or {},
        "diff_content": None,
        "fix_explanation": None,
        "confidence_score": 0.0,
        "model_used": "",
        "build_passed": None,
        "build_output": None,
        "retry_count": 0,
        "max_retries": max_retries,
        "last_error": None,
        "status": "pending",
        "pr_url": None,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }

    final_state = await fix_graph.ainvoke(initial_state)
    return final_state
