"""Custom exception types for password auditing."""

from __future__ import annotations


class PasswordStrengthError(Exception):
    """Base exception for the password strength package."""


class PasswordInputError(PasswordStrengthError):
    """Raised when CLI or file-based input cannot be processed safely."""


class PolicyConfigurationError(PasswordStrengthError):
    """Raised when a policy preset is invalid or incomplete."""


class ResourceLoadError(PasswordStrengthError):
    """Raised when a bundled resource cannot be loaded."""


class ExportFormatError(PasswordStrengthError):
    """Raised when an unsupported export format is requested."""
