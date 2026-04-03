from password_strength.exceptions import PasswordConfigError
from password_strength.exceptions import PasswordDictionaryError
from password_strength.exceptions import PasswordInputError
from password_strength.exceptions import PasswordPolicyError
from password_strength.exceptions import PasswordStrengthError
from password_strength.exceptions import UnsafePasswordOutputError


def test_exception_hierarchy() -> None:
    assert issubclass(PasswordConfigError, PasswordStrengthError)
    assert issubclass(PasswordPolicyError, PasswordStrengthError)
    assert issubclass(PasswordDictionaryError, PasswordStrengthError)
    assert issubclass(UnsafePasswordOutputError, PasswordStrengthError)
    assert issubclass(PasswordInputError, PasswordStrengthError)


def test_exception_messages_are_preserved() -> None:
    error = PasswordConfigError("bad config")
    assert str(error) == "bad config"