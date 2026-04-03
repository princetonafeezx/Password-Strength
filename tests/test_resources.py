from pathlib import Path

from password_strength.exceptions import PasswordDictionaryError
from password_strength.models import PasswordConfig

from password_strength.resources import (
    load_banned_tokens,
    load_common_passwords,
    load_keyboard_patterns,
    load_password_config,
    load_policy_preset,
    read_text_lines
    
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

def test_password_config_loads_from_default_policy() -> None:
    config = load_password_config("default")

    assert isinstance(config, PasswordConfig)
    assert config.policy_name == "default"
    assert config.min_length == 12
    assert config.require_uppercase is True


def test_password_config_loads_from_strict_policy() -> None:
    config = load_password_config("strict")

    assert isinstance(config, PasswordConfig)
    assert config.policy_name == "strict"
    assert config.min_length == 16
    assert config.min_character_classes == 4

def test_read_text_lines_raises_dictionary_error_for_missing_file() -> None:
    missing_path = Path("resources") / "does_not_exist.txt"

    try:
        read_text_lines(missing_path)
        assert False, "Expected PasswordDictionaryError for missing text resource"
    except PasswordDictionaryError as exc:
        assert "Failed to load text resource" in str(exc)