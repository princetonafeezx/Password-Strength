"""Password scoring and entropy estimation."""

from __future__ import annotations

import math

from password_strength.models import (
    DictionaryMatchResult,
    PasswordCandidate,
    PasswordPatternResult,
    PasswordPolicyResult,
    PasswordScoreResult,
)


def estimate_entropy(password: str) -> float:
    """Estimate password entropy using an approximate character-set size.

    ASCII class counts are a rough lower bound. For Unicode-heavy passwords,
    the estimate also considers distinct codepoints so scores are not stuck
    at a tiny alphabet when non-ASCII characters are present. This remains a
    heuristic, not a cryptographic strength guarantee.
    """
    if not password:
        return 0.0

    charset_size = 0
    if any(char.islower() for char in password):
        charset_size += 26
    if any(char.isupper() for char in password):
        charset_size += 26
    if any(char.isdigit() for char in password):
        charset_size += 10
    if any(not char.isalnum() and not char.isspace() for char in password):
        charset_size += 33
    if any(char.isspace() for char in password):
        charset_size += 1

    unique_chars = len(set(password))
    if charset_size <= 1 and unique_chars > 1:
        charset_size = max(charset_size, unique_chars)

    if any(ord(ch) > 127 for ch in password):
        charset_size = max(charset_size, min(65536, max(unique_chars * 4, 256)))

    if charset_size <= 1:
        return float(len(password))

    return round(len(password) * math.log2(charset_size), 2)


def _strength_label(score: int) -> str:
    """Map a normalized score to a human-readable strength label."""
    if score < 20:
        return "Very Weak"
    if score < 40:
        return "Weak"
    if score < 60:
        return "Fair"
    if score < 80:
        return "Strong"
    return "Excellent"


def score_password(
    candidate: PasswordCandidate,
    policy_result: PasswordPolicyResult,
    pattern_result: PasswordPatternResult,
    dictionary_result: DictionaryMatchResult,
) -> PasswordScoreResult:
    """Score a candidate using entropy, diversity, and risk penalties."""
    password = candidate.cleaned_password
    entropy_estimate = estimate_entropy(password)

    length_score = min(len(password) * 3, 30)
    diversity_score = min(
        (policy_result.unique_character_count * 2) + (policy_result.character_class_count * 4),
        25,
    )

    pattern_penalty = 0
    if pattern_result.keyboard_pattern_detected:
        pattern_penalty += 12
    if pattern_result.email_like_detected:
        pattern_penalty += 12
    if pattern_result.phone_like_detected:
        pattern_penalty += 12
    if pattern_result.year_pattern_detected:
        pattern_penalty += 6
    if pattern_result.date_pattern_detected:
        pattern_penalty += 6

    repetition_penalty = 0
    if pattern_result.repeated_characters_detected:
        repetition_penalty += 10
    if pattern_result.repeated_chunks_detected:
        repetition_penalty += 8

    predictability_penalty = 0
    if pattern_result.sequential_characters_detected:
        predictability_penalty += 10
    if pattern_result.reverse_sequence_detected:
        predictability_penalty += 10

    dictionary_penalty = 0
    if dictionary_result.matches_common_password:
        dictionary_penalty += 35
    if dictionary_result.near_common_password:
        dictionary_penalty += 20
    if dictionary_result.weak_family_detected:
        dictionary_penalty += 15
    dictionary_penalty += min(len(dictionary_result.banned_tokens_detected) * 6, 18)

    randomness_bonus = 0
    if entropy_estimate >= 60 and not pattern_result.has_pattern_findings:
        randomness_bonus += 10
    elif entropy_estimate >= 45:
        randomness_bonus += 5

    passphrase_bonus = 0
    if len(password) >= 16 and " " in password:
        passphrase_bonus += 8
    elif len(password) >= 18 and policy_result.policy_passed:
        passphrase_bonus += 4

    entropy_component = min(int(entropy_estimate / 4), 25)
    final_score = max(
        0,
        min(
            100,
            length_score
            + diversity_score
            + entropy_component
            + randomness_bonus
            + passphrase_bonus
            - pattern_penalty
            - dictionary_penalty
            - repetition_penalty
            - predictability_penalty,
        ),
    )
    strength_label = _strength_label(final_score)

    result = PasswordScoreResult(
        candidate=candidate,
        entropy_estimate=entropy_estimate,
        length_score=length_score,
        diversity_score=diversity_score,
        pattern_penalty=pattern_penalty,
        dictionary_penalty=dictionary_penalty,
        repetition_penalty=repetition_penalty,
        predictability_penalty=predictability_penalty,
        randomness_bonus=randomness_bonus,
        passphrase_bonus=passphrase_bonus,
        final_score=final_score,
        strength_label=strength_label,
    )

    result.add_note(f"Entropy estimate: {entropy_estimate:.2f} bits.")
    result.add_note(f"Length score contribution: {length_score}.")
    result.add_note(f"Diversity score contribution: {diversity_score}.")
    if result.total_penalty:
        result.add_note(f"Total penalty applied: {result.total_penalty}.")
    if result.total_bonus:
        result.add_note(f"Total bonus applied: {result.total_bonus}.")

    return result


__all__ = ["estimate_entropy", "score_password"]
