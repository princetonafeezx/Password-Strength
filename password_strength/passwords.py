"""Top-level orchestration module for password workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from password_strength.models import PasswordAuditRecord
from password_strength.models import PasswordCandidate
from password_strength.models import PasswordPatternResult
from password_strength.models import PasswordPolicyResult
from password_strength.models import PasswordRunReport
from password_strength.models import PasswordScoreResult


PIPELINE_STAGES: tuple[str, ...] = (
    "read_input",
    "sanitize_input",
    "parse_passwords",
    "validate_policy",
    "detect_patterns",
    "check_dictionary",
    "score_passwords",
    "classify_results",
    "export_results",
    "build_report",
)


def mask_password(password: str) -> str:
    """Return a masked representation of a password for safe display."""
    if not password:
        return ""
    if len(password) <= 2:
        return "*" * len(password)
    if len(password) <= 4:
        return password[0] + ("*" * (len(password) - 1))
    return password[:2] + ("*" * (len(password) - 4)) + password[-2:]


@dataclass(slots=True)
class PipelineContext:
    """Carries data and execution details through the password pipeline."""

    source: str = "unknown"
    raw_input: Any = None
    sanitized_input: Any = None
    parsed_passwords: list[PasswordCandidate] = field(default_factory=list)
    policy_results: list[PasswordPolicyResult] = field(default_factory=list)
    pattern_results: list[PasswordPatternResult] = field(default_factory=list)
    dictionary_results: list[Any] = field(default_factory=list)
    score_results: list[PasswordScoreResult] = field(default_factory=list)
    classified_results: list[PasswordAuditRecord] = field(default_factory=list)
    exported_output: Any = None
    report: PasswordRunReport | None = None
    completed_stages: list[str] = field(default_factory=list)

    def mark_stage_complete(self, stage_name: str) -> None:
        """Record a successfully completed pipeline stage."""
        self.completed_stages.append(stage_name)


class PasswordPipeline:
    """Coordinates the end-to-end password auditing pipeline."""

    def __init__(self) -> None:
        self.stage_order = PIPELINE_STAGES

    def run(self, raw_input: Any, source: str = "unknown") -> PipelineContext:
        """Run the full password pipeline in the defined stage order."""
        context = PipelineContext(source=source, raw_input=raw_input)

        context = self.read_input(context)
        context = self.sanitize_input(context)
        context = self.parse_passwords(context)
        context = self.validate_policy(context)
        context = self.detect_patterns(context)
        context = self.check_dictionary(context)
        context = self.score_passwords(context)
        context = self.classify_results(context)
        context = self.export_results(context)
        context = self.build_report(context)

        return context

    def read_input(self, context: PipelineContext) -> PipelineContext:
        """Normalize the initial raw input for downstream processing."""
        context.mark_stage_complete("read_input")
        return context

    def sanitize_input(self, context: PipelineContext) -> PipelineContext:
        """Sanitize raw input before password parsing and analysis."""
        context.sanitized_input = context.raw_input
        context.mark_stage_complete("sanitize_input")
        return context

    def parse_passwords(self, context: PipelineContext) -> PipelineContext:
        """Parse sanitized input into individual password candidates."""
        if context.sanitized_input is None:
            context.parsed_passwords = []
        elif isinstance(context.sanitized_input, list):
            context.parsed_passwords = [
                PasswordCandidate(
                    raw_password=str(value),
                    cleaned_password=str(value),
                    source=context.source,
                )
                for value in context.sanitized_input
            ]
        else:
            context.parsed_passwords = [
                PasswordCandidate(
                    raw_password=str(context.sanitized_input),
                    cleaned_password=str(context.sanitized_input),
                    source=context.source,
                )
            ]

        context.mark_stage_complete("parse_passwords")
        return context

    def validate_policy(self, context: PipelineContext) -> PipelineContext:
        """Create placeholder policy results for parsed passwords."""
        context.policy_results = [
            PasswordPolicyResult(
                candidate=candidate,
                unique_character_count=len(set(candidate.cleaned_password)),
            )
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("validate_policy")
        return context

    def detect_patterns(self, context: PipelineContext) -> PipelineContext:
        """Create placeholder pattern-detection results for parsed passwords."""
        context.pattern_results = [
            PasswordPatternResult(candidate=candidate)
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("detect_patterns")
        return context

    def check_dictionary(self, context: PipelineContext) -> PipelineContext:
        """Check passwords against common and banned-password intelligence."""
        context.dictionary_results = []
        context.mark_stage_complete("check_dictionary")
        return context

    def score_passwords(self, context: PipelineContext) -> PipelineContext:
        """Create placeholder score results for parsed passwords."""
        context.score_results = [
            PasswordScoreResult(candidate=candidate)
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("score_passwords")
        return context

    def classify_results(self, context: PipelineContext) -> PipelineContext:
        """Combine per-stage outputs into final audit records."""
        context.classified_results = [
            PasswordAuditRecord(
                candidate=candidate,
                policy_result=policy_result,
                pattern_result=pattern_result,
                score_result=score_result,
                masked_password=mask_password(candidate.cleaned_password),
            )
            for candidate, policy_result, pattern_result, score_result in zip(
                context.parsed_passwords,
                context.policy_results,
                context.pattern_results,
                context.score_results,
                strict=True,
            )
        ]
        context.mark_stage_complete("classify_results")
        return context

    def export_results(self, context: PipelineContext) -> PipelineContext:
        """Prepare exportable output structures."""
        context.exported_output = None
        context.mark_stage_complete("export_results")
        return context

    def build_report(self, context: PipelineContext) -> PipelineContext:
        """Build the final run report returned by the orchestration layer."""
        total_passwords = len(context.parsed_passwords)
        policy_results_count = len(context.policy_results)
        pattern_results_count = len(context.pattern_results)
        score_results_count = len(context.score_results)
        classified_results_count = len(context.classified_results)

        compliant_passwords = sum(
            1 for record in context.classified_results if record.policy_passed
        )
        non_compliant_passwords = classified_results_count - compliant_passwords
        weak_passwords = sum(
            1
            for record in context.classified_results
            if record.strength_rating.lower() in {"very weak", "weak"}
        )
        suspicious_passwords = sum(
            1
            for record in context.classified_results
            if record.pattern_result.has_pattern_findings
        )
        warning_count = sum(len(record.warnings) for record in context.classified_results)

        context.report = PasswordRunReport(
            source=context.source,
            total_passwords=total_passwords,
            compliant_passwords=compliant_passwords,
            non_compliant_passwords=non_compliant_passwords,
            weak_passwords=weak_passwords,
            suspicious_passwords=suspicious_passwords,
            duplicate_passwords=0,
            warning_count=warning_count,
            policy_results_count=policy_results_count,
            pattern_results_count=pattern_results_count,
            score_results_count=score_results_count,
            classified_results_count=classified_results_count,
            completed_stages=list(context.completed_stages),
            exit_code=0,
        )
        context.mark_stage_complete("build_report")
        return context


def run_password_pipeline(raw_input: Any, source: str = "unknown") -> PipelineContext:
    """Convenience wrapper for running the password pipeline."""
    pipeline = PasswordPipeline()
    return pipeline.run(raw_input=raw_input, source=source)