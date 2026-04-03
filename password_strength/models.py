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


@dataclass(slots=True)
class PasswordPatternResult:
    """Stores pattern-detection findings for one password candidate."""

    candidate: PasswordCandidate
    repeated_characters_detected: bool = False
    repeated_chunks_detected: bool = False
    sequential_characters_detected: bool = False
    reverse_sequence_detected: bool = False
    keyboard_pattern_detected: bool = False
    year_pattern_detected: bool = False
    date_pattern_detected: bool = False
    email_like_detected: bool = False
    phone_like_detected: bool = False
    weak_tokens_detected: list[str] = field(default_factory=list)
    pattern_hits: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_pattern_findings(self) -> bool:
        """Return True if any pattern or weak-token finding exists."""
        return any(
            (
                self.repeated_characters_detected,
                self.repeated_chunks_detected,
                self.sequential_characters_detected,
                self.reverse_sequence_detected,
                self.keyboard_pattern_detected,
                self.year_pattern_detected,
                self.date_pattern_detected,
                self.email_like_detected,
                self.phone_like_detected,
                len(self.weak_tokens_detected) > 0,
                len(self.pattern_hits) > 0,
                len(self.warnings) > 0,
            )
        )

    def add_pattern_hit(self, hit_name: str) -> None:
        """Record a named pattern hit."""
        self.pattern_hits.append(hit_name)

    def add_warning(self, warning_text: str) -> None:
        """Record a warning message for the candidate."""
        self.warnings.append(warning_text)

    def add_weak_token(self, token: str) -> None:
        """Record a weak token detected within the candidate."""
        self.weak_tokens_detected.append(token)


@dataclass(slots=True)
class PasswordScoreResult:
    """Stores scoring outputs for one password candidate."""

    candidate: PasswordCandidate
    entropy_estimate: float = 0.0
    length_score: int = 0
    diversity_score: int = 0
    pattern_penalty: int = 0
    dictionary_penalty: int = 0
    repetition_penalty: int = 0
    predictability_penalty: int = 0
    randomness_bonus: int = 0
    passphrase_bonus: int = 0
    final_score: int = 0
    strength_label: str = "Unrated"
    scoring_notes: list[str] = field(default_factory=list)

    def add_note(self, note: str) -> None:
        """Record a scoring explanation note."""
        self.scoring_notes.append(note)

    @property
    def total_penalty(self) -> int:
        """Return the total penalty from all penalty components."""
        return (
            self.pattern_penalty
            + self.dictionary_penalty
            + self.repetition_penalty
            + self.predictability_penalty
        )

    @property
    def total_bonus(self) -> int:
        """Return the total bonus from all bonus components."""
        return self.randomness_bonus + self.passphrase_bonus