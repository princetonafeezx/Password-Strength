from password_strength.passwords import PIPELINE_STAGES
from password_strength.passwords import PasswordPipeline
from password_strength.passwords import run_password_pipeline


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
    assert result.parsed_passwords == ["Example123!"]
    assert result.completed_stages == list(PIPELINE_STAGES)


def test_pipeline_handles_list_input() -> None:
    pipeline = PasswordPipeline()
    result = pipeline.run(["one", "two"], source="file")

    assert result.source == "file"
    assert result.parsed_passwords == ["one", "two"]
    assert result.report["total_passwords"] == 2


def test_pipeline_builds_summary_report() -> None:
    result = run_password_pipeline("Password1!", source="stdin")

    assert result.report["source"] == "stdin"
    assert result.report["total_passwords"] == 1
    assert "build_report" in result.report["completed_stages"]