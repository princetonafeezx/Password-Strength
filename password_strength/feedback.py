"""Human-readable feedback generation."""

from __future__ import annotations

from password_strength.models import (
    DictionaryMatchResult,
    PasswordPatternResult,
    PasswordPolicyResult,
    PasswordScoreResult,
)


def _deduplicate(items: list[str]) -> list[str]:
    """Return items in order with duplicates removed."""
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def generate_feedback(
    policy_result: PasswordPolicyResult,
    pattern_result: PasswordPatternResult,
    dictionary_result: DictionaryMatchResult,
    score_result: PasswordScoreResult,
) -> tuple[list[str], list[str], list[str]]:
    """Generate findings, warnings, and remediation suggestions."""
    findings: list[str] = []
    warnings = list(pattern_result.warnings) + list(dictionary_result.warnings)
    suggestions: list[str] = []

    if not policy_result.policy_passed:
        findings.append("Password does not satisfy the active password policy.")
    if dictionary_result.matches_common_password:
        findings.append("Password matches a known common password.")
    if dictionary_result.near_common_password:
        findings.append("Password is too similar to a known common password.")
    if dictionary_result.banned_tokens_detected:
        findings.append("Password contains banned organizational tokens.")
    if dictionary_result.weak_family_detected:
        findings.append("Password follows a predictable word-plus-year family.")
    if pattern_result.sequential_characters_detected:
        findings.append("Password contains an ascending sequence.")
    if pattern_result.reverse_sequence_detected:
        findings.append("Password contains a reverse sequence.")
    if pattern_result.keyboard_pattern_detected:
        findings.append("Password contains a keyboard pattern.")
    if pattern_result.repeated_characters_detected or pattern_result.repeated_chunks_detected:
        findings.append("Password contains repeated characters or chunks.")
    if pattern_result.email_like_detected or pattern_result.phone_like_detected:
        findings.append("Password includes personal-identifier-style content.")
    if pattern_result.year_pattern_detected or pattern_result.date_pattern_detected:
        findings.append("Password contains a predictable year or date pattern.")

    failed_rule_suggestions = {
        "min_length": "Increase the password length to meet the minimum requirement.",
        "max_length": "Reduce the password length to fit within the maximum limit.",
        "require_lowercase": "Add at least one lowercase letter.",
        "require_uppercase": "Add at least one uppercase letter.",
        "require_digits": "Add at least one digit.",
        "require_special": "Add at least one special character.",
        "min_unique_characters": "Use more unique characters and reduce repetition.",
        "min_character_classes": "Mix more character types together.",
        "spaces_not_allowed": "Remove spaces from the password.",
    }
    suggestions.extend(
        failed_rule_suggestions[rule_name]
        for rule_name in policy_result.failed_rules
        if rule_name in failed_rule_suggestions
    )

    if pattern_result.sequential_characters_detected or pattern_result.reverse_sequence_detected:
        suggestions.append("Avoid alphabetic or numeric runs like abcd or 4321.")
    if pattern_result.keyboard_pattern_detected:
        suggestions.append("Avoid keyboard walks like qwerty or asdf.")
    if pattern_result.repeated_characters_detected or pattern_result.repeated_chunks_detected:
        suggestions.append("Remove repeated characters and repeated word chunks.")
    if dictionary_result.matches_common_password or dictionary_result.near_common_password:
        suggestions.append("Choose a password that is unrelated to common password lists.")
    if dictionary_result.banned_tokens_detected:
        suggestions.append("Avoid company names, admin terms, and other banned tokens.")
    if score_result.final_score < 60:
        suggestions.append("Use a longer, less predictable mix of words, numbers, and symbols.")
    if score_result.final_score >= 80 and not suggestions:
        suggestions.append("Current password looks strong; keep avoiding reuse across accounts.")

    return (
        _deduplicate(findings),
        _deduplicate(warnings),
        _deduplicate(suggestions),
    )
