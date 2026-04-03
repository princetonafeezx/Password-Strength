"""Compatibility wrapper for the misspelled patterns module."""

from __future__ import annotations

import warnings

warnings.warn(
    "password_strength.pattterns is deprecated; use password_strength.patterns instead.",
    DeprecationWarning,
    stacklevel=2,
)

from password_strength.patterns import *  # noqa: F403, E402
