from password_strength.models import PasswordCandidate


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
