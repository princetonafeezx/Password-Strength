"""Pattern detection logic for passwords."""

from __future__ import annotations

import re
from collections.abc import Iterable

from password_strength.models import PasswordCandidate, PasswordPatternResult
from password_strength.resources import load_keyboard_patterns

REPEATED_CHARACTER_RE = re.compile(r"(.)\1{2,}")
REPEATED_CHUNK_RE = re.compile(r"(.{2,}?)\1+")
YEAR_RE = re.compile(r"(?:19|20)\d{2}")
DATE_RE = re.compile(
    r"(?:(?:0?[1-9]|1[0-2])[-/._](?:0?[1-9]|[12]\d|3[01])(?:[-/._](?:19|20)?\d{2})?)"
)
EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?(?:\(\d{3}\)|\d{3})[-.\s]?\d{3}[-.\s]?\d{4}")


def _has_monotonic_sequence(password: str, step: int) -> bool:
    """Return True if the password contains a 4-character monotonic sequence."""
    lowered = password.casefold()
    for index in range(len(lowered) - 3):
        window = lowered[index : index + 4]
        if not (
            all(char.isalpha() for char in window)
            or all(char.isdigit() for char in window)
        ):
            continue

        differences = [
            ord(window[offset + 1]) - ord(window[offset])
            for offset in range(len(window) - 1)
        ]
        if all(difference == step for difference in differences):
            return True

    return False


def detect_patterns(
    candidate: PasswordCandidate,
    keyboard_patterns: Iterable[str] | None = None,
) -> PasswordPatternResult:
    """Detect weak structural patterns in a password candidate."""
    patterns = tuple(
        pattern.casefold()
        for pattern in (keyboard_patterns or load_keyboard_patterns())
    )
    password = candidate.cleaned_password
    lowered = password.casefold()
    result = PasswordPatternResult(candidate=candidate)

    if REPEATED_CHARACTER_RE.search(lowered):
        result.repeated_characters_detected = True
        result.add_pattern_hit("REPEATED_CHARACTERS")
        result.add_warning("Detected repeated-character runs.")

    if REPEATED_CHUNK_RE.search(lowered):
        result.repeated_chunks_detected = True
        result.add_pattern_hit("REPEATED_CHUNKS")
        result.add_warning("Detected repeated text chunks.")

    if _has_monotonic_sequence(password, step=1):
        result.sequential_characters_detected = True
        result.add_pattern_hit("SEQUENTIAL_CHARACTERS")
        result.add_warning("Detected predictable ascending sequence.")

    if _has_monotonic_sequence(password, step=-1):
        result.reverse_sequence_detected = True
        result.add_pattern_hit("REVERSE_SEQUENCE")
        result.add_warning("Detected predictable descending sequence.")

    if any(pattern in lowered for pattern in patterns if len(pattern) >= 4):
        result.keyboard_pattern_detected = True
        result.add_pattern_hit("KEYBOARD_PATTERN")
        result.add_warning("Detected keyboard-walk pattern.")

    if YEAR_RE.search(password):
        result.year_pattern_detected = True
        result.add_pattern_hit("YEAR_PATTERN")
        result.add_warning("Detected embedded year value.")

    if DATE_RE.search(password):
        result.date_pattern_detected = True
        result.add_pattern_hit("DATE_PATTERN")
        result.add_warning("Detected embedded date-like value.")

    if EMAIL_RE.search(password):
        result.email_like_detected = True
        result.add_pattern_hit("EMAIL_LIKE")
        result.add_warning("Detected email-like content.")

    if PHONE_RE.search(password):
        result.phone_like_detected = True
        result.add_pattern_hit("PHONE_LIKE")
        result.add_warning("Detected phone-number-like content.")

    return result


__all__ = ["detect_patterns"]
