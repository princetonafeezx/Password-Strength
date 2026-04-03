"""Audit command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.passwords import run_password_pipeline


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the audit subcommand."""
    parser = subparsers.add_parser(
        "audit",
        help="Audit one password or a batch of passwords.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to audit.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the audit command."""
    result = run_password_pipeline(
        raw_input=args.password,
        source="cli",
    )

    print(result.report)
    return 0