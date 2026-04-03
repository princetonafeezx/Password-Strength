from password_strength.conventions import DEFAULT_CONVENTIONS


def test_conventions_have_rules() -> None:
    assert len(DEFAULT_CONVENTIONS.all_rules()) > 0


def test_contains_known_rule() -> None:
    assert DEFAULT_CONVENTIONS.contains_rule("never print raw passwords by default") is True


def test_unknown_rule_returns_false() -> None:
    assert DEFAULT_CONVENTIONS.contains_rule("auto-upload passwords to cloud storage") is False


def test_rule_matching_is_case_insensitive() -> None:
    assert (
        DEFAULT_CONVENTIONS.contains_rule("Use PascalCase for dataclasses and exceptions") is True
    )
