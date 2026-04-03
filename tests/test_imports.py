from password_strength.cli import build_parser
from password_strength.exceptions import PasswordStrengthError


def test_parser_builds() -> None:
    parser = build_parser()
    assert parser.prog == "password-architect"


def test_base_exception_exists() -> None:
    error = PasswordStrengthError("boom")
    assert str(error) == "boom"