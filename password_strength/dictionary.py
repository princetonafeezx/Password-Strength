"""Dictionary and banned-password checks."""

from __future__ import annotations

import re
from collections.abc import Iterable

from password_strength.models import DictionaryMatchResult, PasswordCandidate
from password_strength.resources import load_banned_tokens, load_common_passwords

LEETSPEAK_TRANSLATION = str.maketrans(
    {
        "@": "a",
        "4": "a",
        "0": "o",
        "1": "i",
        "3": "e",
        "$": "s",
        "5": "s",
        "7": "t",
        "+": "t",
    }
)
WEAK_FAMILY_RE = re.compile(
    r"(spring|summer|fall|autumn|winter)(?:19|20)?\d{2}",
    re.IGNORECASE,
)


def normalize_for_dictionary(value: str) -> str:
    """Normalize a password for weak-token and dictionary comparison."""
    normalized = value.casefold().translate(LEETSPEAK_TRANSLATION)
    return re.sub(r"[^a-z0-9]", "", normalized)


def _is_edit_distance_one(left: str, right: str) -> bool:
    """Return True when two strings are within one edit of each other."""
    if left == right:
        return False
    if abs(len(left) - len(right)) > 1:
        return False

    if len(left) > len(right):
        left, right = right, left

    index_left = 0
    index_right = 0
    edits = 0

    while index_left < len(left) and index_right < len(right):
        if left[index_left] == right[index_right]:
            index_left += 1
            index_right += 1
            continue

        edits += 1
        if edits > 1:
            return False

        if len(left) == len(right):
            index_left += 1
        index_right += 1

    if index_right < len(right) or index_left < len(left):
        edits += 1

    return edits == 1


def analyze_dictionary(
    candidate: PasswordCandidate,
    common_passwords: Iterable[str] | None = None,
    banned_tokens: Iterable[str] | None = None,
) -> DictionaryMatchResult:
    """Analyze a password against common-password and banned-token intelligence."""
    common_values = tuple(common_passwords or load_common_passwords())
    banned_values = tuple(banned_tokens or load_banned_tokens())
    normalized_password = normalize_for_dictionary(candidate.cleaned_password)

    result = DictionaryMatchResult(
        candidate=candidate,
        normalized_password=normalized_password,
    )

    common_lookup = {
        normalize_for_dictionary(password): password
        for password in common_values
        if password
    }

    if normalized_password and normalized_password in common_lookup:
        result.matches_common_password = True
        result.matched_common_password = common_lookup[normalized_password]
        result.add_warning("Password matches a known common password.")
    elif normalized_password:
        if any(
            len(common_password) >= 6
            and _is_edit_distance_one(normalized_password, common_password)
            for common_password in common_lookup
        ):
            result.near_common_password = True
            result.add_warning("Password is only one edit away from a common password.")

    for token in banned_values:
        normalized_token = normalize_for_dictionary(token)
        if normalized_token and normalized_token in normalized_password:
            result.add_banned_token(token)

    if result.banned_tokens_detected:
        result.add_warning("Password contains organization-banned words or tokens.")

    if normalized_password and (
        WEAK_FAMILY_RE.search(normalized_password)
        or re.fullmatch(r"[a-z]+(?:19|20)\d{2}", normalized_password) is not None
    ):
        result.weak_family_detected = True
        result.weak_family_label = "seasonal_or_word_year"
        result.add_warning("Password belongs to a common word-plus-year family.")

    return result


__all__ = ["analyze_dictionary", "normalize_for_dictionary"]
