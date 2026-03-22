"""Tests for LangGraph fix engine — individual nodes and routing logic."""

from app.services.fix_graph import (
    check_templates,
    parse_diff,
    flag_for_review,
    route_after_template_check,
    route_after_primary_llm,
    route_after_backup_llm,
    route_after_build,
    route_after_parse,
    FixState,
)


def _base_state(**overrides) -> FixState:
    state: FixState = {
        "vulnerability": {"category": "crypto", "severity": "high", "description": "MD5 usage"},
        "file_content": "var h = MD5.Create();",
        "language": "csharp",
        "framework": ".NET Core",
        "repo_path": "/tmp/test",
        "project_context": {},
        "diff_content": None,
        "fix_explanation": None,
        "confidence_score": 0.0,
        "model_used": "",
        "build_passed": None,
        "build_output": None,
        "retry_count": 0,
        "max_retries": 3,
        "last_error": None,
        "status": "pending",
        "pr_url": None,
        "prompt_tokens": 0,
        "completion_tokens": 0,
    }
    state.update(overrides)
    return state


class TestCheckTemplates:
    def test_template_match(self):
        state = _base_state()
        result = check_templates(state)
        assert result.get("model_used") == "template"
        assert result.get("diff_content") is not None
        assert result.get("confidence_score") == 0.99

    def test_no_template_match(self):
        state = _base_state(
            vulnerability={"category": "xss", "severity": "medium", "description": "XSS"},
            file_content="some safe code",
        )
        result = check_templates(state)
        assert result.get("model_used") is None


class TestParseDiff:
    def test_valid_diff(self):
        state = _base_state(diff_content="--- a/f\n+++ b/f\n-old\n+new")
        result = parse_diff(state)
        assert result.get("status") != "flagged"

    def test_empty_diff(self):
        state = _base_state(diff_content="")
        result = parse_diff(state)
        assert result.get("status") == "flagged"

    def test_no_changes_diff(self):
        state = _base_state(diff_content="--- a/f\n+++ b/f\n same line")
        result = parse_diff(state)
        assert result.get("status") == "flagged"


class TestFlagForReview:
    def test_sets_flagged_status(self):
        state = _base_state()
        result = flag_for_review(state)
        assert result["status"] == "flagged"


class TestRouting:
    def test_route_after_template_match(self):
        state = _base_state(model_used="template", diff_content="some diff")
        assert route_after_template_check(state) == "apply_and_build"

    def test_route_after_template_no_match(self):
        state = _base_state(model_used="", diff_content=None)
        assert route_after_template_check(state) == "call_primary_llm"

    def test_route_after_primary_success(self):
        state = _base_state(model_used="gpt-5.4", diff_content="diff")
        assert route_after_primary_llm(state) == "parse_diff"

    def test_route_after_primary_fail(self):
        state = _base_state(model_used="gpt_failed")
        assert route_after_primary_llm(state) == "call_backup_llm"

    def test_route_after_backup_success(self):
        state = _base_state(model_used="claude-opus-4-6", diff_content="diff")
        assert route_after_backup_llm(state) == "parse_diff"

    def test_route_after_backup_fail(self):
        state = _base_state(model_used="claude_failed")
        assert route_after_backup_llm(state) == "flag_for_review"

    def test_route_after_parse_valid(self):
        state = _base_state(status="pending")
        assert route_after_parse(state) == "apply_and_build"

    def test_route_after_parse_flagged(self):
        state = _base_state(status="flagged")
        assert route_after_parse(state) == "flag_for_review"

    def test_route_after_build_pass(self):
        state = _base_state(build_passed=True)
        # END is a string constant
        assert route_after_build(state) == "__end__"

    def test_route_after_build_fail_retry(self):
        state = _base_state(build_passed=False, retry_count=1, max_retries=3)
        assert route_after_build(state) == "call_primary_llm"

    def test_route_after_build_fail_exhausted(self):
        state = _base_state(build_passed=False, retry_count=3, max_retries=3)
        assert route_after_build(state) == "flag_for_review"
