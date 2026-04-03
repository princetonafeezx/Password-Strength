"""Validate command for Password Strength Architect."""

from __future__ import annotations

import argparse


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the validate subcommand."""
    parser = subparsers.add_parser(
        "validate",
        help="Validate password policy compliance.",
        description="Validate password policy compliance.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to validate.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the validate command."""
    password_state = "provided" if args.password else "missing"
    print(f"validate command received (password={password_state})")
    return 0