"""Export utilities for password audit results."""

from __future__ import annotations

import csv
import io
import json

from password_strength.exceptions import ExportFormatError
from password_strength.models import PasswordAuditRecord, PasswordRunReport


def _flatten_record(record: PasswordAuditRecord) -> dict[str, object]:
    """Flatten a record into a CSV-friendly dictionary."""
    dictionary_result = record.dictionary_result
    return {
        "masked_password": record.masked_password,
        "cleaned_length": record.candidate.cleaned_length,
        "policy_passed": record.policy_passed,
        "score": record.score,
        "strength_rating": record.strength_rating,
        "failed_rules": ";".join(record.policy_result.failed_rules),
        "pattern_hits": ";".join(record.pattern_result.pattern_hits),
        "banned_tokens": (
            "" if dictionary_result is None else ";".join(dictionary_result.banned_tokens_detected)
        ),
        "findings": ";".join(record.findings),
        "warnings": ";".join(record.warnings),
        "remediation_suggestions": ";".join(record.remediation_suggestions),
    }


def render_console(records: list[PasswordAuditRecord], report: PasswordRunReport) -> str:
    """Render a console-safe summary of the audit results."""
    lines = [
        f"Source: {report.source}",
        (
            "Processed: "
            f"{report.total_passwords} | Compliant: {report.compliant_passwords} | "
            f"Weak: {report.weak_passwords} | Suspicious: {report.suspicious_passwords}"
        ),
    ]

    if not records:
        lines.append("No passwords supplied.")
        return "\n".join(lines)

    for record in records:
        compliance_label = "compliant" if record.policy_passed else "non-compliant"
        lines.append(
            
                f"- {record.masked_password} | {record.strength_rating} | "
                f"score={record.score} | {compliance_label}"
            
        )
        if record.findings:
            lines.append(f"  Findings: {'; '.join(record.findings)}")
        if record.remediation_suggestions:
            lines.append(
                f"  Suggestions: {'; '.join(record.remediation_suggestions[:2])}"
            )

    return "\n".join(lines)


def render_json(records: list[PasswordAuditRecord], report: PasswordRunReport) -> str:
    """Render the full audit results as pretty JSON."""
    payload = {
        "report": report.to_dict(),
        "records": [record.to_dict() for record in records],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_jsonl(records: list[PasswordAuditRecord], report: PasswordRunReport) -> str:
    """Render the audit results as JSONL."""
    lines = [
        json.dumps({"type": "record", **record.to_dict()}, sort_keys=True)
        for record in records
    ]
    lines.append(json.dumps({"type": "summary", **report.to_dict()}, sort_keys=True))
    return "\n".join(lines)


def render_csv(records: list[PasswordAuditRecord], report: PasswordRunReport) -> str:
    """Render the audit results as CSV."""
    buffer = io.StringIO()
    fieldnames = (
        "masked_password",
        "cleaned_length",
        "policy_passed",
        "score",
        "strength_rating",
        "failed_rules",
        "pattern_hits",
        "banned_tokens",
        "findings",
        "warnings",
        "remediation_suggestions",
    )
    writer = csv.DictWriter(buffer, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow(_flatten_record(record))

    if not records:
        writer.writerow({field: "" for field in fieldnames})

    writer.writerow(
        {
            "masked_password": "__summary__",
            "cleaned_length": report.total_passwords,
            "policy_passed": report.compliant_passwords,
            "score": report.weak_passwords,
            "strength_rating": report.source,
            "failed_rules": "",
            "pattern_hits": "",
            "banned_tokens": "",
            "findings": "",
            "warnings": report.warning_count,
            "remediation_suggestions": "",
        }
    )
    return buffer.getvalue()


def export_records(
    records: list[PasswordAuditRecord],
    report: PasswordRunReport,
    output_format: str = "console",
) -> str:
    """Export records in the requested format."""
    normalized_format = output_format.strip().lower()
    if normalized_format == "console":
        return render_console(records, report)
    if normalized_format == "json":
        return render_json(records, report)
    if normalized_format == "jsonl":
        return render_jsonl(records, report)
    if normalized_format == "csv":
        return render_csv(records, report)

    raise ExportFormatError(f"Unsupported export format: {output_format}")
