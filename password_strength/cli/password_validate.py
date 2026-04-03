"""Validate command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.passwords import run_password_pipeline


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the validate subcommand."""
    parser = subparsers.add_parser(
        "validate",
        help="Validate password policy compliance.",
    )
    parser.add_argument(
        "--password",
        type=str,
        help="Password to validate.",
    )
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the validate command."""
    result = run_password_pipeline(
        raw_input=args.password,
        source="cli",
    )

    # For now, just print policy stage placeholder
    print({
        "policy_results": result.policy_results,
        "total_passwords": len(result.parsed_passwords),
    })

    return 0