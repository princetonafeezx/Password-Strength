"""CLI entrypoint for Password Strength Architect."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from password_strength import __version__
from password_strength.cli.password_audit import register_parser as register_audit_parser
from password_strength.cli.password_export import register_parser as register_export_parser
from password_strength.cli.password_score import register_parser as register_score_parser
from password_strength.cli.password_validate import register_parser as register_validate_parser
from password_strength.exceptions import PasswordStrengthError


def build_parser() -> argparse.ArgumentParser:
    """Build and return the root CLI parser."""
    parser = argparse.ArgumentParser(
        prog="password-architect",
        description="Enterprise-grade CLI password auditing tool.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command")
    register_audit_parser(subparsers)
    register_validate_parser(subparsers)
    register_score_parser(subparsers)
    register_export_parser(subparsers)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    handler = getattr(args, "command_handler", None)
    if handler is None:
        parser.print_help()
        return 1

    try:
        return int(handler(args))
    except PasswordStrengthError as exc:
        print(f"error: {exc}")
        return 2


__all__ = ["build_parser", "main"]
