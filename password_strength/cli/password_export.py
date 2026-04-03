"""Export command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.passwords import run_password_pipeline


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the export subcommand."""
    parser = subparsers.add_parser(
        "export",
        help="Export audit results.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to audit before export.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Export format.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the export command."""
    result = run_password_pipeline(
        raw_input=args.password,
        source="cli",
    )

    print({
        "format": args.format,
        "exported": result.exported_output,
        "summary": result.report,
    })

    return 0