from password_strength.models import PasswordCandidate, PasswordPolicyResult
from password_strength.passwords import PIPELINE_STAGES, PasswordPipeline, run_password_pipeline


def test_pipeline_exposes_expected_stage_order() -> None:
    assert PIPELINE_STAGES == (
        "read_input",
        "sanitize_input",
        "parse_passwords",
        "validate_policy",
        "detect_patterns",
        "check_dictionary",
        "score_passwords",
        "classify_results",
        "export_results",
        "build_report",
    )


def test_pipeline_runs_all_stages_for_single_password() -> None:
    result = run_password_pipeline("Example123!", source="cli")

    assert result.source == "cli"
    assert result.raw_input == "Example123!"
    assert result.sanitized_input == "Example123!"
    assert len(result.parsed_passwords) == 1
    assert result.parsed_passwords[0].cleaned_password == "Example123!"
    assert result.completed_stages == list(PIPELINE_STAGES)


def test_pipeline_handles_list_input() -> None:
    pipeline = PasswordPipeline()
    result = pipeline.run(["one", "two"], source="file")

    assert result.source == "file"
    assert len(result.parsed_passwords) == 2
    assert result.parsed_passwords[0].cleaned_password == "one"
    assert result.parsed_passwords[1].cleaned_password == "two"
    assert result.report["total_passwords"] == 2


def test_pipeline_builds_summary_report() -> None:
    result = run_password_pipeline("Password1!", source="stdin")

    assert result.report["source"] == "stdin"
    assert result.report["total_passwords"] == 1
    assert "build_report" in result.completed_stages


def test_pipeline_context_keeps_stage_history_order() -> None:
    result = run_password_pipeline("AnotherPassword1!", source="cli")
    assert result.completed_stages == list(PIPELINE_STAGES)


def test_pipeline_parses_password_candidates() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert isinstance(result.parsed_passwords[0], PasswordCandidate)
    assert result.parsed_passwords[0].source == "cli"
    assert result.parsed_passwords[0].raw_password == "Password1!"


def test_pipeline_creates_policy_results() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert len(result.policy_results) == 1
    assert isinstance(result.policy_results[0], PasswordPolicyResult)
    assert result.policy_results[0].candidate.cleaned_password == "Password1!"


def test_pipeline_report_includes_policy_result_count() -> None:
    result = run_password_pipeline(["one", "two"], source="file")

    assert result.report["policy_results_count"] == 2