"""Data models for password analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
@dataclass
class PasswordCandidate:
    """Step 11 — one raw input password and its source metadata."""
    raw_password: str
    source_file: str = ""
    line_number: int = 0
 
@dataclass
class SanitizationResult:
    """Step 12 — raw vs cleaned text plus actions taken."""
    raw_text: str = ""
    cleaned_text: str = ""
    actions: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
 
@dataclass
class PolicyCheckResult:
    """Step 13 — per-rule pass/fail outcomes."""
    passed: bool = True
    passed_rules: list[str] = field(default_factory=list)
    failed_rules: list[str] = field(default_factory=list)
 
@dataclass
class PatternMatchResult:
    """Step 14 — regex hits for weak patterns."""
    hits: list[str] = field(default_factory=list)
 
@dataclass
class DictionaryMatchResult:
    """Step 15 — banned-password / dictionary matches."""
    hits: list[str] = field(default_factory=list)
 
@dataclass
class PasswordScore:
    """Step 16 — entropy, penalties, bonuses, final score, label."""
    entropy_estimate: float = 0.0
    penalties: float = 0.0
    bonuses: float = 0.0
    final_score: float = 0.0
    strength_label: str = "Unknown"
# ---------------------------------------------------------------------------
 
 
@dataclass
class PasswordAuditResult:
    """Final per-password audit record ready for export.
 
    This is the single object that exporters (JSON, CSV, console)
    and the batch summary (Step 18) will consume.  It owns every
    sub-result so downstream code never has to reach back into the
    pipeline internals.
    """
 
    # --- Sub-results from prior steps ----------------------------------
    candidate: PasswordCandidate
    sanitization: SanitizationResult
    policy: PolicyCheckResult
    patterns: PatternMatchResult
    dictionary: DictionaryMatchResult
    score: PasswordScore
 
    # --- Derived / convenience fields ----------------------------------
    # These are set by the pipeline *after* scoring so the exporter
    # doesn't have to re-derive them.
    classification: str = "unknown"          # e.g. compliant, weak, suspicious, non_compliant
    masked_password: str = ""                # safe-for-display version
    include_raw_password: bool = False       # toggled by --show-raw flag
 
    # Collected warnings and suggestions across all stages
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
 
    # --- Helpers -------------------------------------------------------
 
    def __post_init__(self) -> None:
        """Derive the masked password if the caller didn't supply one."""
        if not self.masked_password and self.candidate.raw_password:
            pw = self.candidate.raw_password
            if len(pw) <= 3:
                self.masked_password = "*" * len(pw)
            else:
                # show first and last char, mask the middle
                self.masked_password = pw[0] + "*" * (len(pw) - 2) + pw[-1]
 
    # --- Aggregate properties ------------------------------------------
 
    @property
    def passed(self) -> bool:
        """True when the password satisfies policy AND scores above weak."""
        return self.policy.passed and self.score.strength_label not in (
            "Very Weak",
            "Weak",
        )
 
    @property
    def finding_count(self) -> int:
        """Total number of findings across patterns and dictionary."""
        return len(self.patterns.hits) + len(self.dictionary.hits)
 
    # --- Serialization -------------------------------------------------
 
    def to_dict(self, *, include_raw: bool | None = None) -> dict[str, Any]:
        """Flatten the audit result into a single-level dict for export.
 
        Parameters
        ----------
        include_raw:
            Override the instance-level ``include_raw_password`` flag
            for this single call.  Useful when the exporter needs to
            suppress plaintext regardless of CLI flags.
        """
        show_raw = include_raw if include_raw is not None else self.include_raw_password
 
        result: dict[str, Any] = {
            # Identity
            "source_file": self.candidate.source_file,
            "line_number": self.candidate.line_number,
            "masked_password": self.masked_password,
 
            # Sanitization
            "original_length": len(self.sanitization.raw_text),
            "cleaned_length": len(self.sanitization.cleaned_text),
            "sanitizer_actions": self.sanitization.actions,
            "sanitizer_warnings": self.sanitization.warnings,
 
            # Policy
            "policy_passed": self.policy.passed,
            "passed_rules": self.policy.passed_rules,
            "failed_rules": self.policy.failed_rules,
 
            # Patterns
            "pattern_hits": self.patterns.hits,
 
            # Dictionary
            "dictionary_hits": self.dictionary.hits,
 
            # Scoring
            "entropy_estimate": self.score.entropy_estimate,
            "penalties": self.score.penalties,
            "bonuses": self.score.bonuses,
            "score": self.score.final_score,
            "strength_rating": self.score.strength_label,
 
            # Overall
            "classification": self.classification,
            "finding_count": self.finding_count,
            "warnings": self.warnings,
            "suggestions": self.suggestions,
        }
 
        # Only include plaintext when explicitly enabled
        if show_raw:
            result["raw_password"] = self.candidate.raw_password
            result["cleaned_password"] = self.sanitization.cleaned_text
 
        return result
 
 
# ---------------------------------------------------------------------------
# Quick sanity check — run this file directly to verify it works.
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    candidate = PasswordCandidate(
        raw_password="P@ssw0rd123!",
        source_file="test_batch.txt",
        line_number=1,
    )
    sanitization = SanitizationResult(
        raw_text="P@ssw0rd123!",
        cleaned_text="P@ssw0rd123!",
        actions=[],
        warnings=[],
    )
    policy = PolicyCheckResult(
        passed=False,
        passed_rules=["min_length", "has_uppercase", "has_digit", "has_special"],
        failed_rules=["min_unique_chars"],
    )
    patterns = PatternMatchResult(
        hits=["common_substitution: P@ssw0rd", "sequential: 123"],
    )
    dictionary = DictionaryMatchResult(
        hits=["banned: password"],
    )
    score = PasswordScore(
        entropy_estimate=28.5,
        penalties=-35.0,
        bonuses=0.0,
        final_score=22.0,
        strength_label="Weak",
    )
 
    audit = PasswordAuditResult(
        candidate=candidate,
        sanitization=sanitization,
        policy=policy,
        patterns=patterns,
        dictionary=dictionary,
        score=score,
        classification="weak",
        warnings=["Contains common substitution pattern"],
        suggestions=[
            "Avoid dictionary words with character substitutions",
            "Increase password length to at least 16 characters",
        ],
    )
 
    import json
    print("=== Masked output (default) ===")
    print(json.dumps(audit.to_dict(), indent=2))
 
    print("\n=== With raw password ===")
    print(json.dumps(audit.to_dict(include_raw=True), indent=2))
 
    print(f"\n  passed:        {audit.passed}")
    print(f"  finding_count: {audit.finding_count}")
    print(f"  masked:        {audit.masked_password}")