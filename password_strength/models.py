"""Data models for password analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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

    def to_dict(self) -> dict[str, Any]:
        """Serialize the candidate into a stable dictionary."""
        return {
            "raw_password": self.raw_password,
            "cleaned_password": self.cleaned_password,
            "source": self.source,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "source_line": self.source_line,
            "sanitizer_actions": list(self.sanitizer_actions),
            "original_length": self.original_length,
            "cleaned_length": self.cleaned_length,
            "was_modified_by_sanitizer": self.was_modified_by_sanitizer,
        }

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize metadata only; omit raw and cleaned password material."""
        return {
            "source": self.source,
            "source_file": self.source_file,
            "line_number": self.line_number,
            "original_length": self.original_length,
            "cleaned_length": self.cleaned_length,
            "sanitizer_actions": list(self.sanitizer_actions),
            "was_modified_by_sanitizer": self.was_modified_by_sanitizer,
        }


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

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy result into a stable dictionary."""
        return {
            "candidate": self.candidate.to_dict(),
            "min_length_passed": self.min_length_passed,
            "max_length_passed": self.max_length_passed,
            "lowercase_passed": self.lowercase_passed,
            "uppercase_passed": self.uppercase_passed,
            "digit_passed": self.digit_passed,
            "special_character_passed": self.special_character_passed,
            "unique_character_count": self.unique_character_count,
            "min_unique_characters_passed": self.min_unique_characters_passed,
            "character_class_count": self.character_class_count,
            "min_character_classes_passed": self.min_character_classes_passed,
            "failed_rules": list(self.failed_rules),
            "passed_rules": list(self.passed_rules),
            "policy_passed": self.policy_passed,
        }


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

    def to_dict(self) -> dict[str, Any]:
        """Serialize the pattern result into a stable dictionary."""
        return {
            "candidate": self.candidate.to_dict(),
            "repeated_characters_detected": self.repeated_characters_detected,
            "repeated_chunks_detected": self.repeated_chunks_detected,
            "sequential_characters_detected": self.sequential_characters_detected,
            "reverse_sequence_detected": self.reverse_sequence_detected,
            "keyboard_pattern_detected": self.keyboard_pattern_detected,
            "year_pattern_detected": self.year_pattern_detected,
            "date_pattern_detected": self.date_pattern_detected,
            "email_like_detected": self.email_like_detected,
            "phone_like_detected": self.phone_like_detected,
            "weak_tokens_detected": list(self.weak_tokens_detected),
            "pattern_hits": list(self.pattern_hits),
            "warnings": list(self.warnings),
            "has_pattern_findings": self.has_pattern_findings,
        }


@dataclass(slots=True)
class DictionaryMatchResult:
    """Stores dictionary and banned-token intelligence for one candidate."""

    candidate: PasswordCandidate
    normalized_password: str = ""
    matches_common_password: bool = False
    matched_common_password: str | None = None
    banned_tokens_detected: list[str] = field(default_factory=list)
    weak_family_detected: bool = False
    weak_family_label: str | None = None
    near_common_password: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def has_dictionary_findings(self) -> bool:
        """Return True when any dictionary or banned-token finding exists."""
        return any(
            (
                self.matches_common_password,
                self.near_common_password,
                self.weak_family_detected,
                len(self.banned_tokens_detected) > 0,
                len(self.warnings) > 0,
            )
        )

    def add_banned_token(self, token: str) -> None:
        """Record a banned token detected in the password."""
        self.banned_tokens_detected.append(token)

    def add_warning(self, warning_text: str) -> None:
        """Record a dictionary-related warning."""
        self.warnings.append(warning_text)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the dictionary result into a stable dictionary."""
        return {
            "candidate": self.candidate.to_dict(),
            "normalized_password": self.normalized_password,
            "matches_common_password": self.matches_common_password,
            "matched_common_password": self.matched_common_password,
            "banned_tokens_detected": list(self.banned_tokens_detected),
            "weak_family_detected": self.weak_family_detected,
            "weak_family_label": self.weak_family_label,
            "near_common_password": self.near_common_password,
            "warnings": list(self.warnings),
            "has_dictionary_findings": self.has_dictionary_findings,
        }


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

    def to_dict(self) -> dict[str, Any]:
        """Serialize the score result into a stable dictionary."""
        return {
            "candidate": self.candidate.to_dict(),
            "entropy_estimate": self.entropy_estimate,
            "length_score": self.length_score,
            "diversity_score": self.diversity_score,
            "pattern_penalty": self.pattern_penalty,
            "dictionary_penalty": self.dictionary_penalty,
            "repetition_penalty": self.repetition_penalty,
            "predictability_penalty": self.predictability_penalty,
            "randomness_bonus": self.randomness_bonus,
            "passphrase_bonus": self.passphrase_bonus,
            "final_score": self.final_score,
            "strength_label": self.strength_label,
            "scoring_notes": list(self.scoring_notes),
            "total_penalty": self.total_penalty,
            "total_bonus": self.total_bonus,
        }


@dataclass(slots=True)
class PasswordAuditRecord:
    """Final per-password audit record ready for reporting and export."""

    candidate: PasswordCandidate
    policy_result: PasswordPolicyResult
    pattern_result: PasswordPatternResult
    score_result: PasswordScoreResult
    masked_password: str
    dictionary_result: DictionaryMatchResult | None = None
    findings: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    remediation_suggestions: list[str] = field(default_factory=list)

    @property
    def raw_password_optional(self) -> str | None:
        """Return the raw password when explicitly available on the candidate."""
        return self.candidate.raw_password

    @property
    def cleaned_password(self) -> str:
        """Return the cleaned password from the candidate."""
        return self.candidate.cleaned_password

    @property
    def policy_passed(self) -> bool:
        """Return the policy status from the linked policy result."""
        return self.policy_result.policy_passed

    @property
    def score(self) -> int:
        """Return the final score from the linked score result."""
        return self.score_result.final_score

    @property
    def strength_rating(self) -> str:
        """Return the strength label from the linked score result."""
        return self.score_result.strength_label

    def add_finding(self, finding: str) -> None:
        """Record a finding on the audit record."""
        self.findings.append(finding)

    def add_warning(self, warning: str) -> None:
        """Record a warning on the audit record."""
        self.warnings.append(warning)

    def add_remediation_suggestion(self, suggestion: str) -> None:
        """Record a remediation suggestion on the audit record."""
        self.remediation_suggestions.append(suggestion)

    def to_safe_dict(self) -> dict[str, Any]:
        """Serialize for shared logs and SIEM-style exports (no password material)."""
        p, pat, s = self.policy_result, self.pattern_result, self.score_result
        dictionary_safe: dict[str, Any] | None
        if self.dictionary_result is None:
            dictionary_safe = None
        else:
            dr = self.dictionary_result
            dictionary_safe = {
                "matches_common_password": dr.matches_common_password,
                "near_common_password": dr.near_common_password,
                "banned_tokens_detected": list(dr.banned_tokens_detected),
                "weak_family_detected": dr.weak_family_detected,
                "weak_family_label": dr.weak_family_label,
                "dictionary_warnings": list(dr.warnings),
                "has_dictionary_findings": dr.has_dictionary_findings,
            }
        return {
            "candidate": self.candidate.to_safe_dict(),
            "policy_result": {
                "min_length_passed": p.min_length_passed,
                "max_length_passed": p.max_length_passed,
                "lowercase_passed": p.lowercase_passed,
                "uppercase_passed": p.uppercase_passed,
                "digit_passed": p.digit_passed,
                "special_character_passed": p.special_character_passed,
                "unique_character_count": p.unique_character_count,
                "min_unique_characters_passed": p.min_unique_characters_passed,
                "character_class_count": p.character_class_count,
                "min_character_classes_passed": p.min_character_classes_passed,
                "failed_rules": list(p.failed_rules),
                "passed_rules": list(p.passed_rules),
                "policy_passed": p.policy_passed,
            },
            "pattern_result": {
                "repeated_characters_detected": pat.repeated_characters_detected,
                "repeated_chunks_detected": pat.repeated_chunks_detected,
                "sequential_characters_detected": pat.sequential_characters_detected,
                "reverse_sequence_detected": pat.reverse_sequence_detected,
                "keyboard_pattern_detected": pat.keyboard_pattern_detected,
                "year_pattern_detected": pat.year_pattern_detected,
                "date_pattern_detected": pat.date_pattern_detected,
                "email_like_detected": pat.email_like_detected,
                "phone_like_detected": pat.phone_like_detected,
                "weak_tokens_detected": list(pat.weak_tokens_detected),
                "pattern_hits": list(pat.pattern_hits),
                "pattern_warnings": list(pat.warnings),
                "has_pattern_findings": pat.has_pattern_findings,
            },
            "score_result": {
                "entropy_estimate": s.entropy_estimate,
                "length_score": s.length_score,
                "diversity_score": s.diversity_score,
                "pattern_penalty": s.pattern_penalty,
                "dictionary_penalty": s.dictionary_penalty,
                "repetition_penalty": s.repetition_penalty,
                "predictability_penalty": s.predictability_penalty,
                "randomness_bonus": s.randomness_bonus,
                "passphrase_bonus": s.passphrase_bonus,
                "final_score": s.final_score,
                "strength_label": s.strength_label,
                "scoring_notes": list(s.scoring_notes),
                "total_penalty": s.total_penalty,
                "total_bonus": s.total_bonus,
            },
            "dictionary_result": dictionary_safe,
            "masked_password": self.masked_password,
            "policy_passed": self.policy_passed,
            "score": self.score,
            "strength_rating": self.strength_rating,
            "findings": list(self.findings),
            "warnings": list(self.warnings),
            "remediation_suggestions": list(self.remediation_suggestions),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the audit record into a stable dictionary."""
        return {
            "candidate": self.candidate.to_dict(),
            "policy_result": self.policy_result.to_dict(),
            "pattern_result": self.pattern_result.to_dict(),
            "dictionary_result": (
                None if self.dictionary_result is None else self.dictionary_result.to_dict()
            ),
            "score_result": self.score_result.to_dict(),
            "masked_password": self.masked_password,
            "raw_password_optional": self.raw_password_optional,
            "cleaned_password": self.cleaned_password,
            "policy_passed": self.policy_passed,
            "score": self.score,
            "strength_rating": self.strength_rating,
            "findings": list(self.findings),
            "warnings": list(self.warnings),
            "remediation_suggestions": list(self.remediation_suggestions),
        }


@dataclass(slots=True)
class PasswordRunReport:
    """Run-level summary for a password audit execution."""

    source: str
    total_passwords: int = 0
    compliant_passwords: int = 0
    non_compliant_passwords: int = 0
    weak_passwords: int = 0
    suspicious_passwords: int = 0
    duplicate_passwords: int = 0
    warning_count: int = 0
    policy_results_count: int = 0
    pattern_results_count: int = 0
    score_results_count: int = 0
    classified_results_count: int = 0
    completed_stages: list[str] = field(default_factory=list)
    exit_code: int = 0

    def add_completed_stage(self, stage_name: str) -> None:
        """Record a completed stage on the run report."""
        self.completed_stages.append(stage_name)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the run report into a stable dictionary."""
        return {
            "source": self.source,
            "total_passwords": self.total_passwords,
            "compliant_passwords": self.compliant_passwords,
            "non_compliant_passwords": self.non_compliant_passwords,
            "weak_passwords": self.weak_passwords,
            "suspicious_passwords": self.suspicious_passwords,
            "duplicate_passwords": self.duplicate_passwords,
            "warning_count": self.warning_count,
            "policy_results_count": self.policy_results_count,
            "pattern_results_count": self.pattern_results_count,
            "score_results_count": self.score_results_count,
            "classified_results_count": self.classified_results_count,
            "completed_stages": list(self.completed_stages),
            "exit_code": self.exit_code,
        }
