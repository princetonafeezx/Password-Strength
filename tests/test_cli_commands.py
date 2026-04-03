from password_strength.cli import build_parser
from password_strength.cli import main


def test_audit_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--password", "Example123!"])

    assert args.command == "audit"
    assert args.password == "Example123!"
    assert callable(args.command_handler)


def test_validate_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["validate", "--password", "Example123!"])

    assert args.command == "validate"
    assert args.password == "Example123!"
    assert callable(args.command_handler)


def test_export_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["export", "--format", "jsonl"])

    assert args.command == "export"
    assert args.format == "jsonl"
    assert callable(args.command_handler)


def test_main_runs_audit_command() -> None:
    exit_code = main(["audit", "--password", "Example123!"])
    assert exit_code == 0


def test_main_runs_validate_command() -> None:
    exit_code = main(["validate", "--password", "Example123!"])
    assert exit_code == 0


def test_main_runs_export_command() -> None:
    exit_code = main(["export", "--format", "csv"])
    assert exit_code == 0