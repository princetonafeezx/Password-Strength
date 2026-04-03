"""Resource loading helpers for Password Strength Architect."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import cast

from password_strength.exceptions import ResourceLoadError

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parent
RESOURCES_DIR = PROJECT_ROOT / "resources"
POLICIES_DIR = RESOURCES_DIR / "policies"


def read_text_lines(path: Path) -> list[str]:
    """Read non-empty, stripped lines from a text resource file."""
    try:
        with path.open("r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    except OSError as exc:
        raise ResourceLoadError(f"Unable to read resource file: {path}") from exc


@lru_cache(maxsize=1)
def load_common_passwords() -> list[str]:
    """Load the built-in common password list."""
    return read_text_lines(RESOURCES_DIR / "common_passwords.txt")


@lru_cache(maxsize=1)
def load_keyboard_patterns() -> list[str]:
    """Load the built-in keyboard pattern list."""
    return read_text_lines(RESOURCES_DIR / "keyboard_patterns.txt")


@lru_cache(maxsize=1)
def load_banned_tokens() -> list[str]:
    """Load the built-in banned token list."""
    return read_text_lines(RESOURCES_DIR / "banned_tokens.txt")


def load_policy_preset(policy_name: str) -> dict[str, object]:
    """Load a JSON policy preset by name."""
    normalized = policy_name.strip().lower()
    policy_path = POLICIES_DIR / f"{normalized}.json"

    try:
        with policy_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
            return cast(dict[str, object], payload)
    except OSError as exc:
        raise ResourceLoadError(f"Unable to load policy preset '{normalized}'.") from exc
    except json.JSONDecodeError as exc:
        raise ResourceLoadError(f"Policy preset '{normalized}' is not valid JSON.") from exc
