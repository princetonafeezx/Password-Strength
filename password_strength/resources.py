"""Resource loading helpers for Password Strength Architect."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources
from typing import cast

from password_strength.exceptions import ResourceLoadError

_DATA_ROOT = resources.files("password_strength.data")


def _read_text_lines(relative_parts: tuple[str, ...]) -> list[str]:
    """Read non-empty stripped lines from a file under bundled ``data``."""
    path = _DATA_ROOT.joinpath(*relative_parts)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError) as exc:
        rel = "/".join(relative_parts)
        raise ResourceLoadError(f"Unable to read bundled resource: {rel}") from exc
    return [line.strip() for line in text.splitlines() if line.strip()]


@lru_cache(maxsize=1)
def load_common_passwords() -> list[str]:
    """Load the built-in common password list."""
    return _read_text_lines(("common_passwords.txt",))


@lru_cache(maxsize=1)
def load_keyboard_patterns() -> list[str]:
    """Load the built-in keyboard pattern list."""
    return _read_text_lines(("keyboard_patterns.txt",))


@lru_cache(maxsize=1)
def load_banned_tokens() -> list[str]:
    """Load the built-in banned token list."""
    return _read_text_lines(("banned_tokens.txt",))


def load_policy_preset(policy_name: str) -> dict[str, object]:
    """Load a JSON policy preset by name."""
    normalized = policy_name.strip().lower()
    path = _DATA_ROOT.joinpath("policies", f"{normalized}.json")
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, FileNotFoundError) as exc:
        raise ResourceLoadError(f"Unable to load policy preset '{normalized}'.") from exc
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ResourceLoadError(f"Policy preset '{normalized}' is not valid JSON.") from exc
    return cast(dict[str, object], payload)
