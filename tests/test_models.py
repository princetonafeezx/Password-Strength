from password_strength.models import PasswordAuditRecord
from password_strength.models import PasswordCandidate
from password_strength.models import PasswordPatternResult
from password_strength.models import PasswordPolicyResult
from password_strength.models import PasswordScoreResult


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


def test_password_pattern_result_defaults() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
    )
    result = PasswordPatternResult(candidate=candidate)

    assert result.candidate is candidate
    assert result.has_pattern_findings is False
    assert result.pattern_hits == []
    assert result.warnings == []


def test_password_pattern_result_tracks_hits_and_warnings() -> None:
    candidate = PasswordCandidate(
        raw_password="abc123",
        cleaned_password="abc123",
    )
    result = PasswordPatternResult(candidate=candidate)

    result.sequential_characters_detected = True
    result.add_pattern_hit("SEQUENTIAL_CHARACTERS")
    result.add_warning("Detected predictable ascending sequence.")

    assert result.has_pattern_findings is True
    assert result.pattern_hits == ["SEQUENTIAL_CHARACTERS"]
    assert result.warnings == ["Detected predictable ascending sequence."]


def test_password_pattern_result_tracks_weak_tokens() -> None:
    candidate = PasswordCandidate(
        raw_password="Summer2025!",
        cleaned_password="Summer2025!",
    )
    result = PasswordPatternResult(candidate=candidate)

    result.add_weak_token("summer")
    assert result.weak_tokens_detected == ["summer"]
    assert result.has_pattern_findings is True


def test_password_score_result_defaults() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
    )
    result = PasswordScoreResult(candidate=candidate)

    assert result.candidate is candidate
    assert result.entropy_estimate == 0.0
    assert result.final_score == 0
    assert result.strength_label == "Unrated"
    assert result.total_penalty == 0
    assert result.total_bonus == 0


def test_password_score_result_tracks_notes() -> None:
    candidate = PasswordCandidate(
        raw_password="LongerPassword123!",
        cleaned_password="LongerPassword123!",
    )
    result = PasswordScoreResult(candidate=candidate)

    result.add_note("Good length contribution.")
    result.add_note("No final score calculated yet.")

    assert result.scoring_notes == [
        "Good length contribution.",
        "No final score calculated yet.",
    ]


def test_password_score_result_totals() -> None:
    candidate = PasswordCandidate(
        raw_password="abc123",
        cleaned_password="abc123",
    )
    result = PasswordScoreResult(
        candidate=candidate,
        pattern_penalty=10,
        dictionary_penalty=15,
        repetition_penalty=5,
        predictability_penalty=20,
        randomness_bonus=8,
        passphrase_bonus=4,
    )

    assert result.total_penalty == 50
    assert result.total_bonus == 12


def test_password_audit_record_defaults_and_properties() -> None:
    candidate = PasswordCandidate(
        raw_password="Example123!",
        cleaned_password="Example123!",
        source="cli",
    )
    policy_result = PasswordPolicyResult(candidate=candidate)
    pattern_result = PasswordPatternResult(candidate=candidate)
    score_result = PasswordScoreResult(
        candidate=candidate,
        final_score=72,
        strength_label="Strong",
    )

    record = PasswordAuditRecord(
        candidate=candidate,
        policy_result=policy_result,
        pattern_result=pattern_result,
        score_result=score_result,
        masked_password="Ex*******!",
    )

    assert record.cleaned_password == "Example123!"
    assert record.raw_password_optional == "Example123!"
    assert record.policy_passed is True
    assert record.score == 72
    assert record.strength_rating == "Strong"


def test_password_audit_record_tracks_findings_warnings_and_suggestions() -> None:
    candidate = PasswordCandidate(
        raw_password="abc123",
        cleaned_password="abc123",
    )
    policy_result = PasswordPolicyResult(candidate=candidate)
    pattern_result = PasswordPatternResult(candidate=candidate)
    score_result = PasswordScoreResult(candidate=candidate)

    record = PasswordAuditRecord(
        candidate=candidate,
        policy_result=policy_result,
        pattern_result=pattern_result,
        score_result=score_result,
        masked_password="ab**23",
    )

    record.add_finding("Sequential pattern detected.")
    record.add_warning("Password is highly predictable.")
    record.add_remediation_suggestion("Increase length and avoid sequences.")

    assert record.findings == ["Sequential pattern detected."]
    assert record.warnings == ["Password is highly predictable."]
    assert record.remediation_suggestions == ["Increase length and avoid sequences."]