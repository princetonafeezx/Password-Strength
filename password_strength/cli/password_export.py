"""Export command for Password Strength Architect."""

from __future__ import annotations

import argparse


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the export subcommand."""
    parser = subparsers.add_parser(
        "export",
        help="Export audit results.",
        description="Export audit results.",
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
    print(f"export command received (format={args.format})")
    return 0