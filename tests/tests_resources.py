from password_strength.resources import (
    load_banned_tokens,
    load_common_passwords,
    load_keyboard_patterns,
    load_policy_preset,
)


def test_common_passwords_load() -> None:
    values = load_common_passwords()
    assert "password" in values
    assert "123456" in values
    assert len(values) >= 10


def test_keyboard_patterns_load() -> None:
    values = load_keyboard_patterns()
    assert "qwerty" in values
    assert "asdf" in values


def test_banned_tokens_load() -> None:
    values = load_banned_tokens()
    assert "admin" in values
    assert "secret" in values


def test_default_policy_loads() -> None:
    policy = load_policy_preset("default")
    assert policy["policy_name"] == "default"
    assert policy["min_length"] == 12


def test_strict_policy_loads() -> None:
    policy = load_policy_preset("strict")
    assert policy["policy_name"] == "strict"
    assert policy["min_length"] == 16
