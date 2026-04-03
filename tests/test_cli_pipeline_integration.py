from password_strength.cli import main


def test_audit_command_runs_pipeline() -> None:
    exit_code = main(["audit", "--password", "Example1234!"])
    assert exit_code == 0


def test_validate_command_runs_pipeline() -> None:
    exit_code = main(["validate", "--password", "Example1234!"])
    assert exit_code == 0


def test_export_command_runs_pipeline() -> None:
    exit_code = main(["export", "--password", "Example1234!"])
    assert exit_code == 0


def test_pipeline_handles_missing_password() -> None:
    exit_code = main(["audit"])
    assert exit_code == 0


def test_export_command_exits_nonzero_for_common_password() -> None:
    exit_code = main(["export", "--password", "password"])
    assert exit_code == 1
