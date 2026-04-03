from password_strength.models import PasswordCandidate, PasswordPolicyResult


def test_password_candidate_stores_values() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
        source="cli",
    )

    assert candidate.raw_password == "Example123!"
    assert candidate.cleaned_password == "Example123!"
    assert candidate.source == "cli"


def test_password_candidate_length_properties() -> None:
    candidate = PasswordCandidate(
        raw_password=" abc ",
        cleaned_password="abc",
    )

    assert candidate.original_length == 5
    assert candidate.cleaned_length == 3


def test_password_candidate_detects_sanitizer_change_by_value() -> None:
    candidate = PasswordCandidate(
        raw_password=" abc ",
        cleaned_password="abc",
    )

    assert candidate.was_modified_by_sanitizer is True


def test_password_candidate_detects_sanitizer_change_by_action() -> None:
    candidate = PasswordCandidate(
        raw_password="abc",
        cleaned_password="abc",
        sanitizer_actions=["normalized_whitespace"],
    )

    assert candidate.was_modified_by_sanitizer is True


def test_password_candidate_can_store_source_metadata() -> None:
    candidate = PasswordCandidate(
        raw_password="Password1!",
        cleaned_password="Password1!",
        source="file",
        source_file="passwords.txt",
        line_number=7,
        source_line="Password1!",
    )

    assert candidate.source_file == "passwords.txt"
    assert candidate.line_number == 7
    assert candidate.source_line == "Password1!"


def test_password_policy_result_defaults() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
    )
    result = PasswordPolicyResult(candidate=candidate)

    assert result.candidate is candidate
    assert result.min_length_passed is False
    assert result.max_length_passed is True
    assert result.policy_passed is True


def test_password_policy_result_tracks_rules() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
    )
    result = PasswordPolicyResult(candidate=candidate)

    result.add_passed_rule("min_length")
    result.add_failed_rule("require_special")

    assert result.passed_rules == ["min_length"]
    assert result.failed_rules == ["require_special"]
    assert result.policy_passed is False


def test_password_policy_result_unique_count_can_be_set() -> None:
    candidate = PasswordCandidate(
        raw_password="aaBB11!!",
        cleaned_password="aaBB11!!",
    )
    result = PasswordPolicyResult(
        candidate=candidate,
        unique_character_count=4,
        character_class_count=4,
    )

    assert result.unique_character_count == 4
    assert result.character_class_count == 4