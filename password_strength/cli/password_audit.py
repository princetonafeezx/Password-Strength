"""Audit command for Password Strength Architect."""

from __future__ import annotations

import argparse


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the audit subcommand."""
    parser = subparsers.add_parser(
        "audit",
        help="Audit one password or a batch of passwords.",
        description="Audit one password or a batch of passwords.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to audit.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the audit command."""
    password_state = "provided" if args.password else "missing"
    print(f"audit command received (password={password_state})")
    return 0