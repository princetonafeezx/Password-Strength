"""Export utilities for password audit results."""

from __future__ import annotations

import csv
import io
import json

from password_strength.exceptions import ExportFormatError
from password_strength.models import PasswordAuditRecord, PasswordRunReport

# CSV: ``row_kind`` is ``detail`` per password or ``summary`` for the aggregate row.
# Summary metrics use ``sum_*`` columns; detail rows leave those empty.

_DETAIL_FIELDNAMES = (
    "row_kind",
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
    "sum_total_passwords",
    "sum_compliant",
    "sum_non_compliant",
    "sum_weak",
    "sum_suspicious",
    "sum_duplicates",
    "sum_warnings",
    "sum_source",
)


def _flatten_record(record: PasswordAuditRecord) -> dict[str, object]:
    """Flatten a record into a CSV-friendly dictionary."""
    dictionary_result = record.dictionary_result
    empty_sums = {key: "" for key in _DETAIL_FIELDNAMES if key.startswith("sum_")}
    return {
        "row_kind": "detail",
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
        **empty_sums,
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


def render_json(
    records: list[PasswordAuditRecord],
    report: PasswordRunReport,
    *,
    redacted: bool = False,
) -> str:
    """Render the full audit results as pretty JSON."""
    to_row = (lambda r: r.to_safe_dict()) if redacted else (lambda r: r.to_dict())
    payload = {
        "report": report.to_dict(),
        "records": [to_row(record) for record in records],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


def render_jsonl(
    records: list[PasswordAuditRecord],
    report: PasswordRunReport,
    *,
    redacted: bool = False,
) -> str:
    """Render the audit results as JSONL."""
    to_row = (lambda r: r.to_safe_dict()) if redacted else (lambda r: r.to_dict())
    lines = [
        json.dumps({"type": "record", **to_row(record)}, sort_keys=True)
        for record in records
    ]
    lines.append(json.dumps({"type": "summary", **report.to_dict()}, sort_keys=True))
    return "\n".join(lines)


def render_csv(records: list[PasswordAuditRecord], report: PasswordRunReport) -> str:
    """Render the audit results as CSV.

    Each password is a ``detail`` row. The last row has ``row_kind=summary`` and
    populated ``sum_*`` columns for run-level metrics; password columns are empty.
    """
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=_DETAIL_FIELDNAMES, lineterminator="\n")
    writer.writeheader()
    for record in records:
        writer.writerow(_flatten_record(record))

    if not records:
        writer.writerow({field: "" for field in _DETAIL_FIELDNAMES})

    writer.writerow(
        {
            "row_kind": "summary",
            "masked_password": "",
            "cleaned_length": "",
            "policy_passed": "",
            "score": "",
            "strength_rating": "",
            "failed_rules": "",
            "pattern_hits": "",
            "banned_tokens": "",
            "findings": "",
            "warnings": "",
            "remediation_suggestions": "",
            "sum_total_passwords": report.total_passwords,
            "sum_compliant": report.compliant_passwords,
            "sum_non_compliant": report.non_compliant_passwords,
            "sum_weak": report.weak_passwords,
            "sum_suspicious": report.suspicious_passwords,
            "sum_duplicates": report.duplicate_passwords,
            "sum_warnings": report.warning_count,
            "sum_source": report.source,
        }
    )
    return buffer.getvalue()


def export_records(
    records: list[PasswordAuditRecord],
    report: PasswordRunReport,
    output_format: str = "console",
    *,
    redacted: bool = False,
) -> str:
    """Export records in the requested format.

    For ``json`` and ``jsonl``, set ``redacted=True`` (or use ``json-safe`` /
    ``jsonl-safe``) to omit raw/cleaned passwords and other sensitive fields.
    """
    normalized_format = output_format.strip().lower()
    if normalized_format in {"json-safe", "jsonl-safe"}:
        normalized_format = normalized_format.replace("-safe", "")
        effective_redacted = True
    else:
        effective_redacted = redacted

    if normalized_format == "console":
        return render_console(records, report)
    if normalized_format == "json":
        return render_json(records, report, redacted=effective_redacted)
    if normalized_format == "jsonl":
        return render_jsonl(records, report, redacted=effective_redacted)
    if normalized_format == "csv":
        return render_csv(records, report)

    raise ExportFormatError(f"Unsupported export format: {output_format}")
