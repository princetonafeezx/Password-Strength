import json

from password_strength.passwords import run_password_pipeline


def test_common_password_is_flagged_by_dictionary_and_scoring() -> None:
    result = run_password_pipeline("password", source="cli", export_format="json")

    assert result.dictionary_results[0].matches_common_password is True
    assert result.classified_results[0].score < 40
    assert "common password" in " ".join(result.classified_results[0].findings).lower()


def test_pipeline_trims_outer_whitespace_and_tracks_sanitizer_actions() -> None:
    result = run_password_pipeline("  BetterPass123!  ", source="cli")

    candidate = result.parsed_passwords[0]
    record = result.classified_results[0]

    assert candidate.raw_password == "  BetterPass123!  "
    assert candidate.cleaned_password == "BetterPass123!"
    assert "trimmed_outer_whitespace" in candidate.sanitizer_actions
    assert any("sanitized" in warning.lower() for warning in record.warnings)


def test_duplicate_passwords_are_reported_in_batch_mode() -> None:
    result = run_password_pipeline(
        ["DuplicatePass123!", "DuplicatePass123!"],
        source="batch.txt",
    )

    assert result.report is not None
    assert result.report.duplicate_passwords == 1
    assert any(
        "duplicated" in finding.lower()
        for finding in result.classified_results[0].findings
    )


def test_json_export_contains_report_and_records() -> None:
    result = run_password_pipeline(
        "LongerExamplePass123!",
        source="cli",
        export_format="json",
    )
    payload = json.loads(result.exported_output)

    assert "report" in payload
    assert "records" in payload
    assert payload["records"][0]["masked_password"].startswith("Lo")


def test_json_safe_export_omits_raw_and_cleaned_passwords() -> None:
    result = run_password_pipeline(
        "LongerExamplePass123!",
        source="cli",
        export_format="json-safe",
    )
    payload = json.loads(result.exported_output)
    rec0 = payload["records"][0]

    assert "cleaned_password" not in rec0
    assert "raw_password_optional" not in rec0
    assert "raw_password" not in rec0["candidate"]
    assert "cleaned_password" not in rec0["candidate"]
