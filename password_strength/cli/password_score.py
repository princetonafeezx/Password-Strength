"""Score command for Password Strength Architect."""

from __future__ import annotations

import argparse

from password_strength.cli._shared import (
    print_json,
    register_common_input_arguments,
    run_pipeline_from_args,
)


def register_parser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the score subcommand."""
    parser = subparsers.add_parser(
        "score",
        help="Score password strength without exporting a full report.",
    )
    register_common_input_arguments(parser)
    parser.set_defaults(command_handler=handle_command)


def handle_command(args: argparse.Namespace) -> int:
    """Handle the score command."""
    result = run_pipeline_from_args(args, export_format="json")
    payload = {
        "summary": {} if result.report is None else result.report.to_dict(),
        "records": [
            {
                "masked_password": record.masked_password,
                "score": record.score,
                "strength_rating": record.strength_rating,
                "entropy_estimate": record.score_result.entropy_estimate,
                "scoring_notes": list(record.score_result.scoring_notes),
            }
            for record in result.classified_results
        ],
    }
    print_json(payload)
    return int(result.report.exit_code) if result.report is not None else 0
