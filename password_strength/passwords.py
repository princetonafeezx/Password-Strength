"""Top-level orchestration module for password workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


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


@dataclass(slots=True)
class PipelineContext:
    """Carries data and execution details through the password pipeline.

    Data flow overview:
        raw_input
        -> sanitized_input
        -> parsed_passwords
        -> policy_results
        -> pattern_results
        -> dictionary_results
        -> score_results
        -> classified_results
        -> exported_output
        -> report
    """

    source: str = "unknown"
    raw_input: Any = None
    sanitized_input: Any = None
    parsed_passwords: list[Any] = field(default_factory=list)
    policy_results: list[Any] = field(default_factory=list)
    pattern_results: list[Any] = field(default_factory=list)
    dictionary_results: list[Any] = field(default_factory=list)
    score_results: list[Any] = field(default_factory=list)
    classified_results: list[Any] = field(default_factory=list)
    exported_output: Any = None
    report: Any = None
    completed_stages: list[str] = field(default_factory=list)

    def mark_stage_complete(self, stage_name: str) -> None:
        """Record a successfully completed pipeline stage."""
        self.completed_stages.append(stage_name)


class PasswordPipeline:
    """Coordinates the end-to-end password auditing pipeline.

    Execution order:
        1. read_input
        2. sanitize_input
        3. parse_passwords
        4. validate_policy
        5. detect_patterns
        6. check_dictionary
        7. score_passwords
        8. classify_results
        9. export_results
        10. build_report

    Design intent:
        - Keep orchestration in one place.
        - Keep stage ordering stable.
        - Let each stage own one major responsibility.
        - Allow future implementations to replace placeholders without
          changing the public pipeline contract.
    """

    def __init__(self) -> None:
        self.stage_order = PIPELINE_STAGES

    def run(self, raw_input: Any, source: str = "unknown") -> PipelineContext:
        """Run the full password pipeline in the defined stage order."""
        context = PipelineContext(source=source, raw_input=raw_input)

        # Stage 1: normalize inbound data from CLI, files, stdin, or future modes.
        context = self.read_input(context)

        # Stage 2: clean unsafe or malformed input while preserving audit intent.
        context = self.sanitize_input(context)

        # Stage 3: turn the sanitized input into one or more password candidates.
        context = self.parse_passwords(context)

        # Stage 4: apply deterministic policy rules.
        context = self.validate_policy(context)

        # Stage 5: detect structural and regex-driven weak patterns.
        context = self.detect_patterns(context)

        # Stage 6: compare passwords against dictionary and banned-token intelligence.
        context = self.check_dictionary(context)

        # Stage 7: generate strength and entropy-related scoring outputs.
        context = self.score_passwords(context)

        # Stage 8: map raw results into user-facing classifications.
        context = self.classify_results(context)

        # Stage 9: prepare exportable output structures.
        context = self.export_results(context)

        # Stage 10: build the final run summary and metadata.
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
            context.parsed_passwords = list(context.sanitized_input)
        else:
            context.parsed_passwords = [context.sanitized_input]

        context.mark_stage_complete("parse_passwords")
        return context

    def validate_policy(self, context: PipelineContext) -> PipelineContext:
        """Run policy validation for parsed passwords."""
        context.policy_results = []
        context.mark_stage_complete("validate_policy")
        return context

    def detect_patterns(self, context: PipelineContext) -> PipelineContext:
        """Run structural and regex-based pattern detection."""
        context.pattern_results = []
        context.mark_stage_complete("detect_patterns")
        return context

    def check_dictionary(self, context: PipelineContext) -> PipelineContext:
        """Check passwords against common and banned-password intelligence."""
        context.dictionary_results = []
        context.mark_stage_complete("check_dictionary")
        return context

    def score_passwords(self, context: PipelineContext) -> PipelineContext:
        """Score passwords based on structure, patterns, and risk signals."""
        context.score_results = []
        context.mark_stage_complete("score_passwords")
        return context

    def classify_results(self, context: PipelineContext) -> PipelineContext:
        """Classify audit results into user-facing categories."""
        context.classified_results = []
        context.mark_stage_complete("classify_results")
        return context

    def export_results(self, context: PipelineContext) -> PipelineContext:
        """Prepare exported output for the requested output mode."""
        context.exported_output = None
        context.mark_stage_complete("export_results")
        return context

    def build_report(self, context: PipelineContext) -> PipelineContext:
        """Build the final run report returned by the orchestration layer."""
        context.report = {
            "source": context.source,
            "total_passwords": len(context.parsed_passwords),
            "completed_stages": list(context.completed_stages),
        }
        context.mark_stage_complete("build_report")
        return context


def run_password_pipeline(raw_input: Any, source: str = "unknown") -> PipelineContext:
    """Convenience wrapper for running the password pipeline."""
    pipeline = PasswordPipeline()
    return pipeline.run(raw_input=raw_input, source=source)