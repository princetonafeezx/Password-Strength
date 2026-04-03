"""Shared helpers for Password Strength Architect CLI commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from password_strength.exceptions import PasswordInputError
from password_strength.passwords import PipelineContext, run_password_pipeline


def register_common_input_arguments(parser: argparse.ArgumentParser) -> None:
    """Register the shared input-related arguments for a subcommand."""
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument(
        "--password",
        type=str,
        help="Password to analyze.",
    )
    input_group.add_argument(
        "--file",
        type=str,
        help="Read one password per line from a file.",
    )
    input_group.add_argument(
        "--stdin",
        action="store_true",
        help="Read one password per line from standard input.",
    )
    parser.add_argument(
        "--policy",
        choices=["default", "strict"],
        default="default",
        help="Policy preset to evaluate against.",
    )


def _read_password_file(path: Path) -> list[str]:
    """Read password candidates from a file with a few safe encoding fallbacks."""
    encodings = ("utf-8-sig", "utf-8", "cp1252", "latin-1")
    for encoding in encodings:
        try:
            return path.read_text(encoding=encoding).splitlines()
        except UnicodeDecodeError:
            continue
        except OSError as exc:
            raise PasswordInputError(f"Unable to read password file: {path}") from exc

    raise PasswordInputError(f"Unable to decode password file: {path}")


def collect_raw_input(args: argparse.Namespace) -> tuple[str | list[str] | None, str]:
    """Collect raw password input and its source label from parsed arguments."""
    if getattr(args, "password", None) is not None:
        return args.password, "cli"

    file_path = getattr(args, "file", None)
    if file_path:
        path = Path(file_path)
        return _read_password_file(path), str(path)

    if getattr(args, "stdin", False):
        return sys.stdin.read().splitlines(), "stdin"

    return None, "cli"


def run_pipeline_from_args(
    args: argparse.Namespace,
    export_format: str,
) -> PipelineContext:
    """Run the password pipeline for a parsed subcommand namespace."""
    raw_input, source = collect_raw_input(args)
    return run_password_pipeline(
        raw_input=raw_input,
        source=source,
        policy_name=args.policy,
        export_format=export_format,
    )


def print_json(payload: object) -> None:
    """Print a JSON payload with stable formatting."""
    print(json.dumps(payload, indent=2, sort_keys=True))
