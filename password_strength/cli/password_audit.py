"""Audit command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.cli._shared import register_common_input_arguments, run_pipeline_from_args


def register_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the audit subcommand."""
    parser = subparsers.add_parser(
        "audit",
        help="Audit one password or a batch of passwords.",
    )
    register_common_input_arguments(parser)
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the audit command."""
    result = run_pipeline_from_args(args, export_format="console")
    print(result.exported_output)
    return int(result.report.exit_code) if result.report is not None else 0
