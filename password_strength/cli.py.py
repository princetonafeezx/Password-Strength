"""CLI entrypoint for Password Strength Architect."""

from __future__ import annotations

import argparse
from typing import Sequence

from password_strength import __version__


def build_parser() -> argparse.ArgumentParser:
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

    audit_parser = subparsers.add_parser(
        "audit",
        help="Audit one password or a batch of passwords.",
    )
    audit_parser.add_argument(
        "--password",
        type=str,
        help="Password to audit.",
    )

    validate_parser = subparsers.add_parser(
        "validate",
        help="Validate password policy compliance.",
    )
    validate_parser.add_argument(
        "--password",
        type=str,
        help="Password to validate.",
    )

    score_parser = subparsers.add_parser(
        "score",
        help="Score password strength.",
    )
    score_parser.add_argument(
        "--password",
        type=str,
        help="Password to score.",
    )

    export_parser = subparsers.add_parser(
        "export",
        help="Export audit results.",
    )
    export_parser.add_argument(
        "--format",
        choices=["json", "jsonl", "csv"],
        default="json",
        help="Export format.",
    )

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    print(f"Command received: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())