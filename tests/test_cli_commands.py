from password_strength.cli import build_parser, main


def test_audit_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["audit", "--password", "Example1234!"])

    assert args.command == "audit"
    assert args.password == "Example1234!"
    assert callable(args.command_handler)


def test_validate_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["validate", "--password", "Example1234!"])

    assert args.command == "validate"
    assert args.password == "Example1234!"
    assert callable(args.command_handler)


def test_export_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["export", "--format", "jsonl"])

    assert args.command == "export"
    assert args.format == "jsonl"
    assert callable(args.command_handler)


def test_export_command_accepts_json_safe_format() -> None:
    parser = build_parser()
    args = parser.parse_args(["export", "--format", "json-safe", "--redact"])

    assert args.format == "json-safe"
    assert args.redact is True


def test_score_command_registers() -> None:
    parser = build_parser()
    args = parser.parse_args(["score", "--password", "Example1234!"])

    assert args.command == "score"
    assert args.password == "Example1234!"
    assert callable(args.command_handler)


def test_main_runs_audit_command() -> None:
    exit_code = main(["audit", "--password", "Example1234!"])
    assert exit_code == 0


def test_main_runs_validate_command() -> None:
    exit_code = main(["validate", "--password", "Example1234!"])
    assert exit_code == 0


def test_main_runs_score_command() -> None:
    exit_code = main(["score", "--password", "Example1234!"])
    assert exit_code == 0


def test_main_runs_export_command() -> None:
    exit_code = main(["export", "--format", "csv"])
    assert exit_code == 0
