"""Data models for password analysis."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class PasswordCandidate:
    """Represents one password input moving through the audit pipeline."""

    raw_password: str
    cleaned_password: str
    source: str = "unknown"
    source_file: str | None = None
    line_number: int | None = None
    source_line: str | None = None
    sanitizer_actions: list[str] = field(default_factory=list)

    @property
    def original_length(self) -> int:
        """Return the length of the raw password."""
        return len(self.raw_password)

    @property
    def cleaned_length(self) -> int:
        """Return the length of the cleaned password."""
        return len(self.cleaned_password)

    @property
    def was_modified_by_sanitizer(self) -> bool:
        """Return True if sanitization changed the password or recorded actions."""
        return (
            self.raw_password != self.cleaned_password
            or len(self.sanitizer_actions) > 0
        )


@dataclass(slots=True)
class PasswordPolicyResult:
    """Stores deterministic policy rule outcomes for one password candidate."""

    candidate: PasswordCandidate
    min_length_passed: bool = False
    max_length_passed: bool = True
    lowercase_passed: bool = False
    uppercase_passed: bool = False
    digit_passed: bool = False
    special_character_passed: bool = False
    unique_character_count: int = 0
    min_unique_characters_passed: bool = False
    character_class_count: int = 0
    min_character_classes_passed: bool = False
    failed_rules: list[str] = field(default_factory=list)
    passed_rules: list[str] = field(default_factory=list)

    @property
    def policy_passed(self) -> bool:
        """Return True when the candidate passed all required policy rules."""
        return len(self.failed_rules) == 0

    def add_failed_rule(self, rule_name: str) -> None:
        """Record a failed policy rule."""
        self.failed_rules.append(rule_name)

    def add_passed_rule(self, rule_name: str) -> None:
        """Record a passed policy rule."""
        self.passed_rules.append(rule_name)