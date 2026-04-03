"""Custom exception types for password auditing."""

from __future__ import annotations


class PasswordStrengthError(Exception):
    """Base exception for the password strength package."""


class PasswordConfigError(PasswordStrengthError):
    """Raised when password configuration is invalid."""


class PasswordPolicyError(PasswordStrengthError):
    """Raised when password policy execution fails unexpectedly."""


class PasswordDictionaryError(PasswordStrengthError):
    """Raised when dictionary or banned-token resources cannot be loaded."""


class UnsafePasswordOutputError(PasswordStrengthError):
    """Raised when a caller requests unsafe raw-password output."""


class PasswordInputError(PasswordStrengthError):
    """Raised when password input is missing, malformed, or unsupported."""


class PolicyConfigurationError(PasswordStrengthError):
    """Raised when a policy preset is invalid or incomplete."""


class ResourceLoadError(PasswordStrengthError):
    """Raised when a bundled resource cannot be loaded."""


class ExportFormatError(PasswordStrengthError):
    """Raised when an unsupported export format is requested."""
