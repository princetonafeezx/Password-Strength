from password_strength.models import (
    PasswordAuditRecord,
    PasswordCandidate,
    PasswordPatternResult,
    PasswordPolicyResult,
    PasswordRunReport,
    PasswordScoreResult,
)
from password_strength.passwords import (
    PIPELINE_STAGES,
    PasswordPipeline,
    mask_password,
    run_password_pipeline,
)


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


def test_mask_password_handles_common_lengths() -> None:
    assert mask_password("") == ""
    assert mask_password("a") == "*"
    assert mask_password("ab") == "**"
    assert mask_password("abcd") == "a***"
    assert mask_password("Example123!") == "Ex*******3!"


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
    assert result.report is not None
    assert result.report.total_passwords == 2


def test_pipeline_builds_summary_report() -> None:
    result = run_password_pipeline("Password1!", source="stdin")

    assert result.report is not None
    assert result.report.source == "stdin"
    assert result.report.total_passwords == 1
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


def test_pipeline_creates_pattern_results() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert len(result.pattern_results) == 1
    assert isinstance(result.pattern_results[0], PasswordPatternResult)
    assert result.pattern_results[0].candidate.cleaned_password == "Password1!"


def test_pipeline_creates_score_results() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert len(result.score_results) == 1
    assert isinstance(result.score_results[0], PasswordScoreResult)
    assert result.score_results[0].candidate.cleaned_password == "Password1!"


def test_pipeline_creates_classified_audit_records() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert len(result.classified_results) == 1
    assert isinstance(result.classified_results[0], PasswordAuditRecord)
    assert result.classified_results[0].candidate.cleaned_password == "Password1!"
    assert result.classified_results[0].masked_password == "Pa******1!"


def test_pipeline_builds_password_run_report() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert result.report is not None
    assert isinstance(result.report, PasswordRunReport)
    assert result.report.source == "cli"


def test_pipeline_report_includes_policy_result_count() -> None:
    result = run_password_pipeline(["one", "two"], source="file")

    assert result.report is not None
    assert result.report.policy_results_count == 2


def test_pipeline_report_includes_pattern_result_count() -> None:
    result = run_password_pipeline(["one", "two"], source="file")

    assert result.report is not None
    assert result.report.pattern_results_count == 2


def test_pipeline_report_includes_score_result_count() -> None:
    result = run_password_pipeline(["one", "two"], source="file")

    assert result.report is not None
    assert result.report.score_results_count == 2


def test_pipeline_report_includes_classified_result_count() -> None:
    result = run_password_pipeline(["one", "two"], source="file")

    assert result.report is not None
    assert result.report.classified_results_count == 2


def test_pipeline_run_report_to_dict_is_serializable() -> None:
    result = run_password_pipeline("Password1!", source="cli")

    assert result.report is not None
    serialized = result.report.to_dict()

    assert serialized["source"] == "cli"
    assert serialized["total_passwords"] == 1
    assert serialized["classified_results_count"] == 1
