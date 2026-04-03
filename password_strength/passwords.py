"""Top-level orchestration module for password workflows."""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from password_strength.dictionary import analyze_dictionary
from password_strength.exporters import export_records
from password_strength.feedback import generate_feedback
from password_strength.models import (
    DictionaryMatchResult,
    PasswordAuditRecord,
    PasswordCandidate,
    PasswordPatternResult,
    PasswordPolicyResult,
    PasswordRunReport,
    PasswordScoreResult,
)
from password_strength.patterns import detect_patterns
from password_strength.policy import PasswordPolicyConfig, evaluate_policy, load_policy_config
from password_strength.scoring import score_password

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


ANSI_ESCAPE_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
CONTROL_CHARACTER_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
INVISIBLE_TRANSLATION_TABLE = str.maketrans("", "", "\ufeff\u200b\u200c\u200d\u2060")


def sanitize_password_value(value: str) -> tuple[str, list[str]]:
    """Normalize a password-like string and return the applied actions."""
    cleaned = value
    actions: list[str] = []

    without_invisible = cleaned.translate(INVISIBLE_TRANSLATION_TABLE)
    if without_invisible != cleaned:
        cleaned = without_invisible
        actions.append("removed_invisible_unicode")

    without_ansi = ANSI_ESCAPE_RE.sub("", cleaned)
    if without_ansi != cleaned:
        cleaned = without_ansi
        actions.append("stripped_ansi_escape_sequences")

    normalized_newlines = cleaned.replace("\r\n", "\n").replace("\r", "\n")
    if normalized_newlines != cleaned:
        cleaned = normalized_newlines
        actions.append("normalized_newlines")

    without_control_characters = CONTROL_CHARACTER_RE.sub("", cleaned)
    if without_control_characters != cleaned:
        cleaned = without_control_characters
        actions.append("removed_control_characters")

    trimmed = cleaned.strip()
    if trimmed != cleaned:
        cleaned = trimmed
        actions.append("trimmed_outer_whitespace")

    return cleaned, actions


@dataclass(slots=True)
class PipelineContext:
    """Carries data and execution details through the password pipeline."""

    source: str = "unknown"
    raw_input: Any = None
    sanitized_input: Any = None
    policy_name: str = "default"
    export_format: str = "console"
    policy_config: PasswordPolicyConfig | None = None
    parsed_passwords: list[PasswordCandidate] = field(default_factory=list)
    policy_results: list[PasswordPolicyResult] = field(default_factory=list)
    pattern_results: list[PasswordPatternResult] = field(default_factory=list)
    dictionary_results: list[DictionaryMatchResult] = field(default_factory=list)
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

    def __init__(
        self,
        policy_name: str = "default",
        export_format: str = "console",
    ) -> None:
        self.stage_order = PIPELINE_STAGES
        self.policy_name = policy_name
        self.export_format = export_format

    def run(self, raw_input: Any, source: str = "unknown") -> PipelineContext:
        """Run the full password pipeline in the defined stage order."""
        context = PipelineContext(
            source=source,
            raw_input=raw_input,
            policy_name=self.policy_name,
            export_format=self.export_format,
        )

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
        if isinstance(context.raw_input, tuple):
            context.raw_input = list(context.raw_input)
        context.mark_stage_complete("read_input")
        return context

    def sanitize_input(self, context: PipelineContext) -> PipelineContext:
        """Sanitize raw input before password parsing and analysis."""
        raw_input = context.raw_input
        if raw_input is None:
            context.sanitized_input = None
        elif isinstance(raw_input, list):
            context.sanitized_input = [
                sanitize_password_value(str(value))[0]
                for value in raw_input
            ]
        else:
            context.sanitized_input = sanitize_password_value(str(raw_input))[0]
        context.mark_stage_complete("sanitize_input")
        return context

    def parse_passwords(self, context: PipelineContext) -> PipelineContext:
        """Parse sanitized input into individual password candidates."""
        if context.sanitized_input in (None, ""):
            context.parsed_passwords = []
        elif isinstance(context.sanitized_input, list):
            raw_values = (
                context.raw_input
                if isinstance(context.raw_input, list)
                else [context.raw_input] * len(context.sanitized_input)
            )
            parsed_passwords: list[PasswordCandidate] = []
            for index, (raw_value, cleaned_value) in enumerate(
                zip(raw_values, context.sanitized_input, strict=True),
                start=1,
            ):
                cleaned_password, actions = sanitize_password_value(str(raw_value))
                if not cleaned_value and not cleaned_password:
                    continue
                parsed_passwords.append(
                    PasswordCandidate(
                        raw_password=str(raw_value),
                        cleaned_password=cleaned_password,
                        source=context.source,
                        source_file=(
                            context.source if context.source not in {"cli", "stdin"} else None
                        ),
                        line_number=index,
                        source_line=str(raw_value),
                        sanitizer_actions=actions,
                    )
                )
            context.parsed_passwords = parsed_passwords
        else:
            cleaned_password, actions = sanitize_password_value(str(context.raw_input))
            context.parsed_passwords = (
                [
                    PasswordCandidate(
                        raw_password=str(context.raw_input),
                        cleaned_password=cleaned_password,
                        source=context.source,
                        sanitizer_actions=actions,
                    )
                ]
                if cleaned_password
                else []
            )

        context.mark_stage_complete("parse_passwords")
        return context

    def validate_policy(self, context: PipelineContext) -> PipelineContext:
        """Evaluate deterministic password policy rules."""
        context.policy_config = load_policy_config(context.policy_name)
        context.policy_results = [
            evaluate_policy(candidate=candidate, policy=context.policy_config)
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("validate_policy")
        return context

    def detect_patterns(self, context: PipelineContext) -> PipelineContext:
        """Detect predictable structural patterns in parsed passwords."""
        context.pattern_results = [
            detect_patterns(candidate)
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("detect_patterns")
        return context

    def check_dictionary(self, context: PipelineContext) -> PipelineContext:
        """Check passwords against common and banned-password intelligence."""
        context.dictionary_results = [
            analyze_dictionary(candidate)
            for candidate in context.parsed_passwords
        ]
        context.mark_stage_complete("check_dictionary")
        return context

    def score_passwords(self, context: PipelineContext) -> PipelineContext:
        """Produce strength scores for parsed passwords."""
        context.score_results = [
            score_password(candidate, policy_result, pattern_result, dictionary_result)
            for candidate, policy_result, pattern_result, dictionary_result in zip(
                context.parsed_passwords,
                context.policy_results,
                context.pattern_results,
                context.dictionary_results,
                strict=True,
            )
        ]
        context.mark_stage_complete("score_passwords")
        return context

    def classify_results(self, context: PipelineContext) -> PipelineContext:
        """Combine per-stage outputs into final audit records."""
        classified_results: list[PasswordAuditRecord] = []
        for candidate, policy_result, pattern_result, dictionary_result, score_result in zip(
            context.parsed_passwords,
            context.policy_results,
            context.pattern_results,
            context.dictionary_results,
            context.score_results,
            strict=True,
        ):
            record = PasswordAuditRecord(
                candidate=candidate,
                policy_result=policy_result,
                pattern_result=pattern_result,
                score_result=score_result,
                masked_password=mask_password(candidate.cleaned_password),
                dictionary_result=dictionary_result,
            )
            findings, warnings, suggestions = generate_feedback(
                policy_result=policy_result,
                pattern_result=pattern_result,
                dictionary_result=dictionary_result,
                score_result=score_result,
            )
            for finding in findings:
                record.add_finding(finding)
            for warning in warnings:
                record.add_warning(warning)
            if candidate.was_modified_by_sanitizer:
                record.add_warning("Input was sanitized before analysis.")
            for suggestion in suggestions:
                record.add_remediation_suggestion(suggestion)
            classified_results.append(record)

        duplicate_counts = Counter(
            record.cleaned_password
            for record in classified_results
            if record.cleaned_password
        )
        for record in classified_results:
            if duplicate_counts[record.cleaned_password] > 1:
                record.add_finding("Password is duplicated within the current batch.")
                record.add_warning("Duplicate password detected in batch input.")

        context.classified_results = classified_results
        context.mark_stage_complete("classify_results")
        return context

    def export_results(self, context: PipelineContext) -> PipelineContext:
        """Prepare exportable output structures."""
        context.mark_stage_complete("export_results")
        preview_report = _build_run_report(context)
        context.exported_output = export_records(
            context.classified_results,
            preview_report,
            context.export_format,
        )
        return context

    def build_report(self, context: PipelineContext) -> PipelineContext:
        """Build the final run report returned by the orchestration layer."""
        context.mark_stage_complete("build_report")
        context.report = _build_run_report(context)
        context.exported_output = export_records(
            context.classified_results,
            context.report,
            context.export_format,
        )
        return context


def _build_run_report(context: PipelineContext) -> PasswordRunReport:
    """Build a run report from the current pipeline context."""
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
        or (
            record.dictionary_result is not None
            and record.dictionary_result.has_dictionary_findings
        )
    )
    warning_count = sum(len(record.warnings) for record in context.classified_results)
    duplicate_passwords = sum(
        count - 1
        for count in Counter(
            record.cleaned_password
            for record in context.classified_results
            if record.cleaned_password
        ).values()
        if count > 1
    )

    return PasswordRunReport(
        source=context.source,
        total_passwords=total_passwords,
        compliant_passwords=compliant_passwords,
        non_compliant_passwords=non_compliant_passwords,
        weak_passwords=weak_passwords,
        suspicious_passwords=suspicious_passwords,
        duplicate_passwords=duplicate_passwords,
        warning_count=warning_count,
        policy_results_count=policy_results_count,
        pattern_results_count=pattern_results_count,
        score_results_count=score_results_count,
        classified_results_count=classified_results_count,
        completed_stages=list(context.completed_stages),
        exit_code=0,
    )


def run_password_pipeline(
    raw_input: Any,
    source: str = "unknown",
    policy_name: str = "default",
    export_format: str = "console",
) -> PipelineContext:
    """Convenience wrapper for running the password pipeline."""
    pipeline = PasswordPipeline(
        policy_name=policy_name,
        export_format=export_format,
    )
    return pipeline.run(raw_input=raw_input, source=source)
