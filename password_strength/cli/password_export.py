"""Export command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.cli._shared import register_common_input_arguments, run_pipeline_from_args


def register_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the export subcommand."""
    parser = subparsers.add_parser(
        "export",
        help="Export audit results.",
    )
    register_common_input_arguments(parser)
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "json-safe", "jsonl-safe", "csv", "console"],
        default="json",
        help="Export format. Use json-safe or jsonl-safe to omit raw/cleaned passwords.",
    )
    parser.add_argument(
        "--redact",
        action="store_true",
        help="With json or jsonl, omit sensitive fields (same as *-safe formats).",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the export command."""
    result = run_pipeline_from_args(args, export_format=args.format)
    print(result.exported_output)
    return int(result.report.exit_code) if result.report is not None else 0
