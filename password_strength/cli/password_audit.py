"""Audit command for Password Strength Architect."""

from __future__ import annotations

import argparse
import sys

from password_strength.input_loader import load_password_input
from password_strength.passwords import run_password_pipeline

from password_strength.cli._shared import register_common_input_arguments, run_pipeline_from_args

def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the audit subcommand."""
    parser = subparsers.add_parser(
        "audit",
        help="Audit one password or a batch of passwords.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Single password to audit.",
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Path to a file containing one password per line.",
    )
    parser.add_argument(
        "--files",
        nargs="+",
        help="One or more files containing passwords.",
    )
    parser.add_argument(
        "--stdin",
        action="store_true",
        help="Read passwords from standard input.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the audit command."""
    loaded = load_password_input(
        password=args.password,
        file=args.file,
        files=args.files,
        use_stdin=bool(args.stdin),
        stdin=sys.stdin,
    )

    raw_input: str | list[str]
    if len(loaded.values) == 1:
        raw_input = loaded.values[0]
    else:
        raw_input = loaded.values

    result = run_password_pipeline(
        raw_input=raw_input,
        source=loaded.source,
    )

    if result.report is not None:
        print(result.report.to_dict())
    else:
        print({"source": loaded.source, "total_passwords": len(loaded.values)})

    return 0