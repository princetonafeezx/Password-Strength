"""Password policy validation logic."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from password_strength.exceptions import PolicyConfigurationError
from password_strength.models import PasswordCandidate, PasswordPolicyResult
from password_strength.resources import load_policy_preset

SPECIAL_CHARACTER_RE = re.compile(r"[^A-Za-z0-9\s]")


@dataclass(frozen=True, slots=True)
class PasswordPolicyConfig:
    """Structured configuration for deterministic password policy checks."""

    policy_name: str
    description: str
    min_length: int
    max_length: int
    require_lowercase: bool
    require_uppercase: bool
    require_digits: bool
    require_special: bool
    min_unique_characters: int
    min_character_classes: int
    allow_spaces: bool
    passphrase_mode: bool = False


def load_policy_config(policy_name: str = "default") -> PasswordPolicyConfig:
    """Load and validate a named policy preset."""
    return validate_policy_config(load_policy_preset(policy_name))


def validate_policy_config(config: Mapping[str, object]) -> PasswordPolicyConfig:
    """Validate a raw policy mapping and return a typed configuration."""
    required_fields = (
        "policy_name",
        "description",
        "min_length",
        "max_length",
        "require_lowercase",
        "require_uppercase",
        "require_digits",
        "require_special",
        "min_unique_characters",
        "min_character_classes",
        "allow_spaces",
    )
    missing_fields = [field for field in required_fields if field not in config]
    if missing_fields:
        missing = ", ".join(missing_fields)
        raise PolicyConfigurationError(f"Policy preset is missing required fields: {missing}")

    policy = PasswordPolicyConfig(
        policy_name=str(config["policy_name"]),
        description=str(config["description"]),
        min_length=_as_int(config["min_length"], "min_length"),
        max_length=_as_int(config["max_length"], "max_length"),
        require_lowercase=bool(config["require_lowercase"]),
        require_uppercase=bool(config["require_uppercase"]),
        require_digits=bool(config["require_digits"]),
        require_special=bool(config["require_special"]),
        min_unique_characters=_as_int(
            config["min_unique_characters"],
            "min_unique_characters",
        ),
        min_character_classes=_as_int(
            config["min_character_classes"],
            "min_character_classes",
        ),
        allow_spaces=bool(config["allow_spaces"]),
        passphrase_mode=bool(config.get("passphrase_mode", False)),
    )

    if policy.min_length < 1:
        raise PolicyConfigurationError("min_length must be at least 1.")
    if policy.max_length < policy.min_length:
        raise PolicyConfigurationError("max_length must be greater than or equal to min_length.")
    if policy.min_unique_characters < 1:
        raise PolicyConfigurationError("min_unique_characters must be at least 1.")
    if not 1 <= policy.min_character_classes <= 4:
        raise PolicyConfigurationError("min_character_classes must be between 1 and 4.")

    return policy


def _as_int(value: object, field_name: str) -> int:
    """Coerce an integer configuration field with a clear error message."""
    if isinstance(value, bool):
        raise PolicyConfigurationError(
            f"Policy field '{field_name}' must be an integer, not a boolean."
        )
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError as exc:
            raise PolicyConfigurationError(
                f"Policy field '{field_name}' must be an integer."
            ) from exc

    try:
        return int(str(value))
    except (TypeError, ValueError) as exc:
        raise PolicyConfigurationError(
            f"Policy field '{field_name}' must be an integer."
        ) from exc


def _count_character_classes(password: str) -> int:
    """Count how many core character classes are present in a password."""
    return sum(
        (
            any(char.islower() for char in password),
            any(char.isupper() for char in password),
            any(char.isdigit() for char in password),
            bool(SPECIAL_CHARACTER_RE.search(password)),
        )
    )


def _record_rule(result: PasswordPolicyResult, rule_name: str, passed: bool) -> None:
    """Record a rule outcome on the policy result."""
    if passed:
        result.add_passed_rule(rule_name)
    else:
        result.add_failed_rule(rule_name)


def evaluate_policy(
    candidate: PasswordCandidate,
    policy: PasswordPolicyConfig | None = None,
) -> PasswordPolicyResult:
    """Evaluate a password candidate against the active policy."""
    active_policy = policy or load_policy_config()
    password = candidate.cleaned_password

    unique_character_count = len(set(password))
    character_class_count = _count_character_classes(password)
    has_whitespace = any(char.isspace() for char in password)

    result = PasswordPolicyResult(
        candidate=candidate,
        unique_character_count=unique_character_count,
        character_class_count=character_class_count,
    )

    result.min_length_passed = len(password) >= active_policy.min_length
    result.max_length_passed = len(password) <= active_policy.max_length
    result.lowercase_passed = (
        not active_policy.require_lowercase
        or any(char.islower() for char in password)
    )
    result.uppercase_passed = (
        not active_policy.require_uppercase
        or any(char.isupper() for char in password)
    )
    result.digit_passed = (
        not active_policy.require_digits
        or any(char.isdigit() for char in password)
    )
    result.special_character_passed = (
        not active_policy.require_special
        or bool(SPECIAL_CHARACTER_RE.search(password))
    )
    result.min_unique_characters_passed = (
        unique_character_count >= active_policy.min_unique_characters
    )
    result.min_character_classes_passed = (
        character_class_count >= active_policy.min_character_classes
    )

    _record_rule(result, "min_length", result.min_length_passed)
    _record_rule(result, "max_length", result.max_length_passed)
    _record_rule(result, "require_lowercase", result.lowercase_passed)
    _record_rule(result, "require_uppercase", result.uppercase_passed)
    _record_rule(result, "require_digits", result.digit_passed)
    _record_rule(result, "require_special", result.special_character_passed)
    _record_rule(
        result,
        "min_unique_characters",
        result.min_unique_characters_passed,
    )
    _record_rule(
        result,
        "min_character_classes",
        result.min_character_classes_passed,
    )
    _record_rule(
        result,
        "spaces_allowed" if active_policy.allow_spaces else "spaces_not_allowed",
        active_policy.allow_spaces or not has_whitespace,
    )

    return result
